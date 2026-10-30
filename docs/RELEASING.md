# Releasing Sentinel

Sentinel is released on its own line of versions. A canon edit never forces a Sentinel release.

A release is a tag named `sentinel-vX.Y.Z` where `X.Y.Z` equals `version` in `sentinel/pyproject.toml`
(the workflow refuses a mismatch). Pushing the tag runs `.github/workflows/release-sentinel.yml`:

1. `version`: tag and `pyproject.toml` agree.
2. `build`: the same steps CI runs on every pull request (`sentinel-build.yml`): build the wheel and sdist, check them,
   confirm no licence or billing code is inside, install the wheel and run the CLI; build the image and smoke-test it;
   write the CycloneDX SBOM.
3. `pypi`: publishes to PyPI by **trusted publishing** (no token stored anywhere).
4. `image`: pushes `ghcr.io/<owner>/kbg-sentinel:<version>`, signs it keylessly with Sigstore, attests the SBOM, and
   creates the GitHub release with the SBOM and the image digest.

Every release entry in `sentinel/CHANGELOG.md` carries a change class (Compatible, Behavioural, Breaking) from
Sentinel ADR-004.

## One-time setup (the repository owner does these; no agent can)

### 1. PyPI trusted publisher
On pypi.org, create the project name by adding a *pending publisher* (Account, then Publishing):

| Field | Value |
|---|---|
| PyPI project name | `kbg-sentinel` |
| Owner | `MohanKbgrid` |
| Repository name | `kbg-platform` |
| Workflow name | `release-sentinel.yml` |
| Environment name | `pypi` |

### 2. GitHub environment
In the repository: Settings, Environments, New environment, name `pypi`. Add yourself as a required reviewer if you
want a human click before every publish.

### 3. Repository secret for the scrub check
Settings, Secrets and variables, Actions, New repository secret: `KBG_SCRUB_PATTERNS`. The value is the private list of
customer and internal-product names (one regular expression per line). The workflow `ci-platform` fails without it on
anything but a fork pull request.

### 4. Branch protection and community settings
Settings, Branches: protect `main` (require pull request, require the `ci-platform` and `ci-sentinel` checks, no force
pushes). Settings, General: turn on Discussions. Settings, Pages: only if the docs site is published from here.

## Pushing a release
```
git tag sentinel-v0.24.0 <commit>
git push origin sentinel-v0.24.0
```
Watch the run under the Actions tab. A failed run publishes nothing that has not already succeeded; PyPI files are
immutable, so a bad release is fixed by a new version, never by re-tagging.
