package gitlab

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type GitLab struct{}

type CVEResponse struct {
	ID          uint64 `json:"id"`
	Description string `json:"description"`
	Name        string `json:"name"`
	Url         string `json:"web_url"`
}

func New() *GitLab {
	return new(GitLab)
}

func (e *GitLab) Start(cve string, gitlabToken string, verbose bool) {
	var (
		client   *http.Client
		resp     *http.Response
		err      error
		body     []byte
		response []CVEResponse
		results  []string
	)

	if gitlabToken == "" {
		if verbose {
			log.Printf("GITLAB_KEY environment variable isn't set")
		}
		return
	}

	client = new(http.Client)
	url := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=projects&search=%s", cve)
	if verbose {
		log.Printf("Requesting %s\n", url)
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "CVESearch")
	req.Header.Set("PRIVATE-TOKEN", gitlabToken)
	if resp, err = client.Do(req); err != nil {
		log.Fatal(err)
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		if verbose {
			log.Printf("Error - %s\n", string(body))
		}
		return
	}

	if err := json.Unmarshal([]byte(body), &response); err != nil {
		log.Fatal(err)
	}

	for i := 0; i < len(response); i++ {
		result := fmt.Sprintf("%s - %s", response[i].Name, response[i].Url)
		results = append(results, result)
	}

	if verbose {
		if len(results) == 0 {
			log.Println("No results found on GitLab")
		} else {
			log.Printf("Found %d results from GitLab\n", len(response))
		}
	}

	e.prettyPrint(results)
}

func (e *GitLab) prettyPrint(results []string) {
	for _, result := range results {
		fmt.Printf("%s\n", result)
	}
}
