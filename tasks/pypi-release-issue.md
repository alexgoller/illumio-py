## Summary

Publish this fork to PyPI under a new distribution name (Illumio orphaned the original
`illumio` package). Keep the import package as `illumio` so existing user code
(`import illumio`) is unchanged.

Packaging + a tag-triggered release workflow are already wired up (see "Done" below);
this issue tracks the remaining decisions and the one-time PyPI setup before the first
real publish.

## Distribution name

Proposed: **`illumio-py-open`** (import name stays `illumio`).

- ⚠️ Confirm exact spelling — original request read `illuio-py-open` (likely a typo).
- ⚠️ **Trademark:** Apache-2.0 does not grant trademark rights, and "Illumio" is Illumio's
  mark. Using it in the distribution name is a separate consideration from the code license.
  As an Illumio employee this may be authorized — worth a quick internal/legal check before
  publishing. If it's a concern, a non-mark name (e.g. `pce-client`, `segpy`) avoids it.

## License / fork basis

- Upstream is Apache-2.0 → forking, modifying, renaming the distribution, and redistributing
  are permitted. Requirements honored: `LICENSE` retained, `NOTICE` updated (keeps the
  original Illumio copyright + states this is a fork), copyright headers kept, changes stated.

## Release process (already implemented)

1. Bump = create a git tag `vX.Y.Z` (version is derived from the tag by `setuptools_scm`).
2. Pushing the tag triggers `.github/workflows/release.yml`: run tests → build sdist+wheel →
   `twine check` → publish to PyPI via **Trusted Publishing (OIDC)** (no token secret).

## Remaining one-time setup (before first publish)

- [ ] Confirm the final distribution name (spelling + trademark).
- [ ] Create the PyPI project / reserve the name (a TestPyPI dry run first is recommended).
- [ ] Configure the PyPI **Trusted Publisher**: owner `alexgoller`, repo `illumio-py`,
      workflow `release.yml`, environment `pypi`. (Token alternative: set a `PYPI_API_TOKEN`
      secret and switch the publish step to use it.)
- [ ] Create a GitHub `pypi` environment (optionally with required reviewers).
- [ ] Decide the first version tag (e.g. `v2.0.0` to signal the fork/major change).

## Done in this repo

- `setup.cfg`: `name = illumio-py-open`, fork maintainer/url/project_urls, description.
- `NOTICE`: fork attribution added (original Illumio copyright retained).
- `MANIFEST.in`: excludes dev/reference material (webservices bundle, schemas, tasks, docs,
  tests, tools, CLAUDE.md) — verified sdist/wheel are clean and pass `twine check`.
- `.github/workflows/release.yml`: tag-triggered test → build → publish.
