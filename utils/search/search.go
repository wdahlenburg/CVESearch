package search

import (
	"github.com/wdahlenburg/CVESearch/utils"
	"github.com/wdahlenburg/CVESearch/utils/exploitdb"
	"github.com/wdahlenburg/CVESearch/utils/github"
	"github.com/wdahlenburg/CVESearch/utils/gitlab"
	"github.com/wdahlenburg/CVESearch/utils/seebug"
)

type Search struct{}

func New() *Search {
	return new(Search)
}

func (s *Search) Start(cve string, apiKeys utils.ApiKeys, verbose bool) {
	exploitdb.New().Start(cve, verbose)
	github.New().Start(cve, apiKeys.GitHub, verbose)
	gitlab.New().Start(cve, apiKeys.GitLab, verbose)
	seebug.New().Start(cve, verbose)
}
