package github

import (
	"context"
	"fmt"
	"log"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

type GitHub struct{}

func New() *GitHub {
	return new(GitHub)
}

func (g *GitHub) Start(cve string, gitKey string, verbose bool) {
	var (
		results []string
	)
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

	repos, _, err := client.Search.Repositories(ctx, cve, nil)
	if err != nil {
		if verbose {
			log.Printf(err.Error())
		}
		return
	}

	if verbose {
		log.Printf("Found %d repositories in GitHub\n", len(repos.Repositories))
	}
	for i := 0; i < len(repos.Repositories); i++ {
		results = append(results, *repos.Repositories[i].HTMLURL)
	}

	g.prettyPrint(results)
}

func (g *GitHub) prettyPrint(results []string) {
	if len(results) == 0 {
		log.Println("No results found in GitHub")
		return
	}
	for _, result := range results {
		fmt.Printf("%s\n", result)
	}
}
