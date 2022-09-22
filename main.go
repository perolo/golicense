package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/go-github/v18/github"
	"github.com/rsc/goversion/version"
	"golang.org/x/oauth2"

	"github.com/mitchellh/golicense/config"
	"github.com/mitchellh/golicense/license"
	githubFinder "github.com/mitchellh/golicense/license/github"
	"github.com/mitchellh/golicense/license/golang"
	"github.com/mitchellh/golicense/license/gopkg"
	"github.com/mitchellh/golicense/license/mapper"
	"github.com/mitchellh/golicense/license/resolver"
	"github.com/mitchellh/golicense/module"
)

type moduleVersionLicense struct {
	Version  string    `json:"version,omitempty"`
	License  string    `json:"license,omitempty"`
	SPDX     string    `json:"spdx,omitempty"`
	Hash     string    `json:"hash,omitempty"`
	Created  time.Time `json:"created,omitempty"`
	LastUsed time.Time `json:"used,omitempty"`
}
type cachedModule struct {
	Path   string                 `json:"path,omitempty"`
	VerLic []moduleVersionLicense `json:"verlic,omitempty"`
}

type cacheFile struct {
	Modules []cachedModule
}

var cacheData cacheFile = cacheFile{}
var cacheDataLookup map[string]cachedModule

const (
	EnvGitHubToken = "GITHUB_TOKEN"
)

func main() {
	os.Exit(realMain())
}

func readFile(fn string) {

	jsonFile, err := os.Open(fn)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Successfully Opened: %s\n", fn)
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'users' which we defined above
	err = json.Unmarshal(byteValue, &cacheData)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		fmt.Printf("No file found, will attempt to create new \n")
	}

	cacheDataLookup = map[string]cachedModule{}

	for _, cc := range cacheData.Modules {
		cacheDataLookup[cc.Path] = cc
	}
}

func realMain() int {
	termOut := &TermOutput{Out: os.Stdout}

	var flagLicense bool
	var flagOutXLSX string
	var flagCache string
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.BoolVar(&flagLicense, "license", true,
		"look up and verify license. If false, dependencies are\n"+
			"printed without licenses.")
	flags.BoolVar(&termOut.Plain, "plain", false, "plain terminal output, no colors or live updates")
	flags.BoolVar(&termOut.Verbose, "verbose", false, "additional logging to terminal, requires -plain")
	flags.StringVar(&flagOutXLSX, "out-xlsx", "",
		"save report in Excel XLSX format to the given path")
	flags.StringVar(&flagCache, "cache", "",
		"read cached file from the given path")
	err := flags.Parse(os.Args[1:])
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		printHelp(flags)
		return 1
	}

	args := flags.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, color.RedString(
			"❗️ Path to file to analyze expected.\n\n"))
		printHelp(flags)
		return 1
	}

	if flagCache != "" {
		readFile(flagCache)
	}

	// Determine the exe path and parse the configuration if given.
	var cfg config.Config
	exePaths := args[:1]
	if len(args) > 1 {
		exePaths = args[1:]

		c, err := config.ParseFile(args[0])
		if err != nil {
			fmt.Fprint(os.Stderr, color.RedString(fmt.Sprintf(
				"❗️ Error parsing configuration:\n\n%s\n", err)))
			return 1
		}

		// Store the config and set it on the output
		cfg = *c
	}

	allMods := map[module.Module]struct{}{}
	for _, exePath := range exePaths {
		// Read the dependencies from the binary itself
		vsn, err := version.ReadExe(exePath)
		if err != nil {
			fmt.Fprint(os.Stderr, color.RedString(fmt.Sprintf(
				"❗️ Error reading %q: %s\n", args[0], err)))
			return 1
		}

		if vsn.ModuleInfo == "" {
			// ModuleInfo empty means that the binary didn't use Go modules
			// or it could mean that a binary has no dependencies. Either way
			// we error since we can't be sure.
			fmt.Fprint(os.Stderr, color.YellowString(fmt.Sprintf(
				"⚠️  %q ⚠️\n\n"+
					"This executable was compiled without using Go modules or has \n"+
					"zero dependencies. golicense considers this an error (exit code 1).\n", exePath)))
			return 1
		}

		// From the raw module string from the binary, we need to parse this
		// into structured data with the module information.
		mods, err := module.ParseExeData(vsn.ModuleInfo)
		if err != nil {
			fmt.Fprint(os.Stderr, color.RedString(fmt.Sprintf(
				"❗️ Error parsing dependencies: %s\n", err)))
			return 1
		}
		for _, mod := range mods {
			allMods[mod] = struct{}{}
		}
	}

	mods := make([]module.Module, 0, len(allMods))
	for mod := range allMods {
		mods = append(mods, mod)
	}

	// Complete terminal output setup
	termOut.Config = &cfg
	termOut.Modules = mods

	// Setup the outputs
	out := &MultiOutput{Outputs: []Output{termOut}}
	if flagOutXLSX != "" {
		out.Outputs = append(out.Outputs, &XLSXOutput{
			Path:   flagOutXLSX,
			Config: &cfg,
		})
	}

	// Setup a context. We don't connect this to an interrupt signal or
	// anything since we just exit immediately on interrupt. No cleanup
	// necessary.
	ctx := context.Background()

	// Auth with GitHub if available
	var githubClient *http.Client
	if v := os.Getenv(EnvGitHubToken); v != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: v})
		githubClient = oauth2.NewClient(ctx, ts)
	}

	// Build our translators and license finders
	ts := []license.Translator{
		&mapper.Translator{Map: cfg.Translate},
		&resolver.Translator{},
		&golang.Translator{},
		&gopkg.Translator{},
	}
	var fs []license.Finder
	if flagLicense {
		fs = []license.Finder{
			&mapper.Finder{Map: cfg.Override},
			&githubFinder.RepoAPI{
				Client: github.NewClient(githubClient),
			},
		}
	}

	// Kick off all the license lookups.
	var wg sync.WaitGroup
	sem := NewSemaphore(5)
	count := 0
	for _, m := range mods {
		count++
		wg.Add(1)
		go func(m module.Module) {
			defer wg.Done()

			// Acquire a semaphore so that we can limit concurrency
			sem.Acquire()
			defer sem.Release()

			// Build the context
			ctx = license.StatusWithContext(ctx, StatusListener(out, &m))

			// Lookup
			out.Start(&m)
			var lic *license.License
			var err error
			if flagCache != "" {

				found := false
				index := 0
				cca, ok := cacheDataLookup[m.Path]
				if ok {
					for vvk, vv := range cca.VerLic {
						if vv.Version == m.Version {
							if vv.Hash != m.Hash {
								os.Exit(1)
							}
							found = true
							index = vvk
						}
					}
				}
				if ok && found {
					ccc := cacheDataLookup[m.Path]
					ccc.VerLic[index].LastUsed = time.Now()
					lic = &license.License{Name: cca.VerLic[index].License, SPDX: cca.VerLic[index].SPDX}
					cacheDataLookup[m.Path] = ccc
				} else {
					count++
					// We first try the untranslated version. If we can detect
					// a license then take that. Otherwise, we translate.
					lic, err = license.Find(ctx, m, fs)
					if lic == nil || err != nil {
						lic, err = license.Find(ctx, license.Translate(ctx, m, ts), fs)
					}

					if lic != nil && err == nil {
						c2, ok2 := cacheDataLookup[m.Path]

						var newVerLic moduleVersionLicense
						newVerLic.Version = m.Version
						newVerLic.License = lic.Name
						newVerLic.SPDX = lic.SPDX
						newVerLic.Hash = m.Hash
						newVerLic.Created = time.Now()
						newVerLic.LastUsed = time.Now()

						if ok2 {
							c2.VerLic = append(c2.VerLic, newVerLic)
						} else {
							var newMod cachedModule
							newMod.Path = m.Path
							newMod.VerLic = append(newMod.VerLic, newVerLic)

							cacheData.Modules = append(cacheData.Modules, newMod)
						}
					}
				}
			} else {
				count++
				// We first try the untranslated version. If we can detect
				// a license then take that. Otherwise, we translate.
				lic, err = license.Find(ctx, m, fs)
				if lic == nil || err != nil {
					lic, err = license.Find(ctx, license.Translate(ctx, m, ts), fs)
				}
			}
			out.Finish(&m, lic, err)
		}(m)

		if count > 5 {
			break
		}
	}

	// Wait for all lookups to complete
	wg.Wait()

	if flagCache != "" {

		content, err := json.Marshal(cacheData)
		if err != nil {
			fmt.Println(err)
		}
		err = ioutil.WriteFile(flagCache, content, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Close the output
	if err := out.Close(); err != nil {
		fmt.Fprint(os.Stderr, color.RedString(fmt.Sprintf(
			"❗️ Error: %s\n", err)))
		return 1
	}

	return termOut.ExitCode()
}

func printHelp(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, strings.TrimSpace(help)+"\n\n", os.Args[0])
	fs.PrintDefaults()
}

const help = `
golicense analyzes the dependencies of a binary compiled from Go.

Usage: %[1]s [flags] [BINARY]
Usage: %[1]s [flags] [CONFIG] [BINARY]

One or two arguments can be given: a binary by itself which will output
all the licenses of dependencies, or a configuration file and a binary
which also notes which licenses are allowed among other settings.

For full help text, see the README in the GitHub repository:
http://github.com/mitchellh/golicense

Flags:

`
