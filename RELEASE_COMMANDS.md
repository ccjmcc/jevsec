# Release commands

GitHub CLI was unavailable in the development environment, so no remote repository, push, or GitHub Release has been created. After reviewing and configuring a GitHub repository URL:

```sh
git remote add origin <YOUR_GITHUB_REPOSITORY_URL>
git branch -M main
git add -A
git commit -m "Release v0.1.0"
git tag -a v0.1.0 -m "v0.1.0"
git push -u origin main --tags
```

Upload the prepared artifact using the GitHub web release page, or install/configure `gh` and run:

```sh
gh release create v0.1.0 dist/security-decision-engine-v0.1.0.tar.gz --title "v0.1.0" --notes-file CHANGELOG.md
```

The current workspace git repository has no commits and no remote configured. Review docs, dependency/model licensing, and test/benchmark output before publishing.
