package main

import (
	"flag"
	"log"
	"os"
	"regexp"

	"github.com/wdahlenburg/CVESearch/utils/search"
)

func main() {
	var (
		cve     string
		verbose bool
	)
	flag.StringVar(&cve, "cve", "", "CVE to query")
	flag.BoolVar(&verbose, "v", false, "Enable verbose mode")
	flag.Parse()

	validateCVE(cve)

	apiKey := os.Getenv("GITHUB_KEY")

	search.New().Start(cve, apiKey, verbose)
}

func validateCVE(cve string) {
	re := regexp.MustCompile(`^CVE-\d{4}-\d+$`)
	if !re.Match([]byte(cve)) {
		log.Fatal("Error. CVE must be in the format of CVE-20XX-XXXX")
	}
}
