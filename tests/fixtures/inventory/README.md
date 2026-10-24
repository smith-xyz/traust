# Forge inventory answers

Copied from traust-core `tests/fixtures/inventory/` (recorded 2026-10-24 from a public org and repository; org, repo and handle names replaced):

- `github-org-repos.jsonl`: `gh api --paginate "orgs/<org>/repos?type=sources&per_page=100" --jq '.[] | {url: .html_url, archived, visibility, fork}'`.
- `OWNERS`, `github-contributors.txt`: a repository's OWNERS file and `contributors?per_page=10` logins (the two bot accounts keep their `-bot` / `-robot` suffixes).
