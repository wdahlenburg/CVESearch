package search

import (
	"github.com/wdahlenburg/CVESearch/utils/cvebase"
	"github.com/wdahlenburg/CVESearch/utils/exploitdb"
	"github.com/wdahlenburg/CVESearch/utils/github"
)

type Search struct{}

func New() *Search {
	return new(Search)
}

func (s *Search) Start(cve string, gitKey string, verbose bool) {
	exploitdb.New().Start(cve, verbose)
	cvebase.New().Start(cve, verbose)
	github.New().Start(cve, gitKey, verbose)
}
