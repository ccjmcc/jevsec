# Release status and commands

The v0.2.0 source release is prepared locally as tag `v0.2.0` and archive `dist/security-decision-engine-v0.2.0.tar.gz`. The corrected Qwen3-4B benchmark, OWASP CRS comparison, test suite and authenticated Docker health check are recorded in this checkout. No GitHub remote is configured, and this does not publish the release.

After creating the repository and confirming authentication, publish the branch and release tag:

```sh
git remote add origin <YOUR_GITHUB_REPOSITORY_URL>
git push -u origin main
git push origin v0.2.0
```

Create the GitHub release and attach the checked archive:

```sh
gh release create v0.2.0 dist/security-decision-engine-v0.2.0.tar.gz \
  --title "v0.2.0" --notes-file CHANGELOG.md
```

The archive excludes `.env`, local databases, datasets, virtual environments, and model weights. Check `dist/security-decision-engine-v0.2.0.tar.gz.sha256` before sharing it.
