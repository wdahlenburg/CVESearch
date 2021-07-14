package utils

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func PrintDescription(cve string) {
	var (
		details string
		err     error
	)
	details, err = checkNist(cve)
	if err != nil {
		details, err = checkMitre(cve)
		if err != nil {
			details = "N/A"
		}
	}

	fmt.Printf("Description of %s:\n\n%s\n\n", cve, details)
}

func checkNist(cve string) (string, error) {
	var (
		client *http.Client
		resp   *http.Response
		result string
		err    error
	)
	client = new(http.Client)
	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "CVESearch")
	if resp, err = client.Do(req); err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Filter for description details
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", err
	}

	doc.Find("#vulnDetailTableView").Each(func(i int, s *goquery.Selection) {
		s.Find("p").Each(func(j int, s2 *goquery.Selection) {
			class, _ := s2.Attr("data-testid")
			if class == "vuln-description" {
				result = s2.Text()
			}
		})
	})

	if result == "" {
		return "", errors.New("CVE not found")
	}

	return strings.TrimRight(result, "\n"), nil
}

func checkMitre(cve string) (string, error) {
	var (
		client *http.Client
		resp   *http.Response
		result string
		err    error
	)
	client = new(http.Client)
	url := fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cve)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "CVESearch")
	if resp, err = client.Do(req); err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Filter for description details
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", err
	}

	doc.Find("#GeneratedTable > table > tbody > tr:nth-child(4) > td").Each(func(i int, s *goquery.Selection) {
		result = s.Text()
	})

	if result == "" {
		return "", errors.New("CVE not found")
	}

	return strings.TrimRight(result, "\n"), nil
}
