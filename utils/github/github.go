package github

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

type GitHub struct{}

func New() *GitHub {
	return new(GitHub)
}

func (g *GitHub) Start(cve string, gitKey string, verbose bool) {
	if gitKey == "" {
		if verbose {
			log.Printf("GITHUB_KEY environment variable isn't set")
		}
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: gitKey},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	g.startGithub(ctx, client, cve, verbose)
	g.startNuclei(ctx, client, cve, verbose)
}

func (g *GitHub) startGithub(ctx context.Context, client *github.Client, cve string, verbose bool) {
	var (
		results []string
	)
	repos, _, err := client.Search.Repositories(ctx, cve, nil)
	if err != nil {
		if verbose {
			log.Printf(err.Error())
		}
		return
	}

	for i := 0; i < len(repos.Repositories); i++ {
		results = append(results, *repos.Repositories[i].HTMLURL)
	}

	if verbose {
		if len(results) == 0 {
			log.Println("No results found in GitHub")
		} else {
			log.Printf("Found %d repositories in GitHub\n", len(repos.Repositories))
		}
	}

	g.prettyPrint(results)
}

func (g *GitHub) startNuclei(ctx context.Context, client *github.Client, cve string, verbose bool) {
	var (
		results []string
	)
	// Query is: "CVE-20XX-YYYY in:file language:yaml repo:projectdiscovery/nuclei-templates"
	query := fmt.Sprintf("%s in:file language:yaml repo:projectdiscovery/nuclei-templates", cve)
	files, _, err := client.Search.Code(ctx, query, nil)
	if err != nil {
		if verbose {
			log.Printf(err.Error())
		}
		return
	}

	for i := 0; i < *files.Total; i++ {
		// Do a check to make sure it's in the 'cves' folder
		if strings.Contains(*files.CodeResults[i].HTMLURL, "cves/") {
			results = append(results, *files.CodeResults[i].HTMLURL)
		}
	}

	if verbose {
		if len(results) == 0 {
			log.Println("No results found in Nuclei-Templates")
		} else {
			log.Printf("Found %d file(s) in Nuclei-Templates\n", len(results))
		}
	}

	g.prettyPrint(results)
}

func (g *GitHub) prettyPrint(results []string) {
	for _, result := range results {
		fmt.Printf("%s\n", result)
	}
}
