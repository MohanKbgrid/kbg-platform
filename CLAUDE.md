# kbg-platform: working rules for agents

This is a PUBLIC repository. Every file, commit message and pull request is public.

- **Never name a customer or an internal product.** `tools/scrub_check.py` fails CI if one appears. Its pattern list is
  a repository secret (`KBG_SCRUB_PATTERNS`), never a file here.
- **Every build is tested, then independently function-tested.** Evidence goes in the commit message: what was run and
  the result. "Looks right" is not evidence.
- **Source repositories are read-only.** Code harvested from a private product is copied, scrubbed and re-tested here;
  it is never pushed back.
- **DCO sign-off** (`git commit -s`) on every commit. No CLA.
- **No secrets, ever.** Scan before any visibility change.
- **Move files, do not delete them,** unless the owner has said so.

## Tags

The rule "never create or push git tags" applies to every KBGrid repository. In THIS repository it is lifted for
exactly one pattern: `sentinel-vX.Y.Z`, which triggers `.github/workflows/release-sentinel.yml`. The workflow was fixed
(the old private release failed on an upper-case image name) and is exercised on every pull request by
`sentinel-build.yml`. Any other tag, and any tag in any other repository, stays forbidden. A release is pushed only
after the owner says so; see `docs/RELEASING.md`.
