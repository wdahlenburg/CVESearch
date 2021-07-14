package seebug

import (
	"fmt"
	"log"
	"net/http"

	"github.com/PuerkitoBio/goquery"
)

type Seebug struct{}

func New() *Seebug {
	return new(Seebug)
}

func (s *Seebug) Start(cve string, verbose bool) {
	var (
		client  *http.Client
		resp    *http.Response
		err     error
		results []string
	)
	client = new(http.Client)
	url := fmt.Sprintf("https://www.seebug.org/search/?keywords=%s", cve)
	if verbose {
		log.Printf("Requesting %s\n", url)
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "CVESearch")
	if resp, err = client.Do(req); err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("Error: %d %s", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	doc.Find(".vul-title").Each(func(i int, sel *goquery.Selection) {
		// <a class="vul-title" title="Apache Solr SSRF漏洞 (CVE-2021-27905)" href="/vuldb/ssvid-99264">Apache Solr SSRF漏洞 (CVE-2021-27905)</a>
		href, ok := sel.Attr("href")
		if !ok {
			log.Printf("Error: href missing from result\n")
		}
		title, ok := sel.Attr("title")
		if !ok {
			log.Printf("Error: Title missing from result\n")
		}

		result := fmt.Sprintf("%s - https://www.seebug.org%s", title, href)
		results = append(results, result)
	})

	if verbose {
		log.Printf("Found %d result(s) in Seebug\n", len(results))
	}
	s.prettyPrint(results)
}

func (s *Seebug) prettyPrint(results []string) {
	if len(results) == 0 {
		log.Println("No results found on Seebug")
		return
	}
	for _, result := range results {
		fmt.Printf("%s\n", result)
	}
}
