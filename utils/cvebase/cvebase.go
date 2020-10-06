package cvebase

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type CVEBase struct{}

func New() *CVEBase {
	return new(CVEBase)
}

func (c *CVEBase) Start(cve string, verbose bool) {
	var (
		client  *http.Client
		resp    *http.Response
		err     error
		results []string
	)
	client = new(http.Client)
	query := strings.Split(strings.ToLower(cve), "cve-")[1]
	cveAttrs := strings.Split(query, "-")
	url := fmt.Sprintf("https://www.cvebase.com/cve/%s/%s", cveAttrs[0], cveAttrs[1])
	if verbose {
		log.Printf("Requesting %s\n", url)
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "CVESearch")
	if resp, err = client.Do(req); err != nil {
		log.Printf(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		c.prettyPrint(results)
		return
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	doc.Find("h3:contains('Proof-of-Concept Exploits') + ul").Each(func(i int, s *goquery.Selection) {
		link, ok := s.Find("a").Attr("href")
		if ok {
			results = append(results, link)
		}
	})

	if verbose {
		log.Printf("Found %d results in CVEBase\n", len(results))
	}

	c.prettyPrint(results)
}

func (c *CVEBase) prettyPrint(results []string) {
	if len(results) == 0 {
		log.Println("No results found on CVEBase")
		return
	}
	for _, result := range results {
		fmt.Printf("%s\n", result)
	}
}
