# CVESearch
Query various sources for CVE proof-of-concepts

Many vendors and references provide no proof-of-concept or working exploit for CVEs. This utility was created to automate searching for proof-of-concepts.

There is currently support for:
* Exploit Database
* GitHub
  * [Nuclei-Templates](https://github.com/projectdiscovery/nuclei-templates/)
  * [Metasploit Framework](https://github.com/rapid7/metasploit-framework/) 
* GitLab
* Seebug

The GitHub search requires a personal access token is created and set to the GITHUB_KEY environment variable.

GitLab allows searching of projects, but does not offer a global code search, so results will be limited. Set the GITLAB_KEY environment variable to add this API.
