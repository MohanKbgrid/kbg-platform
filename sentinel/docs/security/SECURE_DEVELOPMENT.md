# Secure development and change policy

1. **Code review.** Every change to `main` goes through a pull request with passing CI: lint including the
   bandit security rules, the full test suite on SQLite and PostgreSQL, the reference schema check, and the
   open-source licence check. Security-relevant changes (authentication, authorisation, audit, egress,
   secrets, personal data) need a reviewer other than the author.
2. **Dependencies.** Runtime dependencies are open source and few; new ones need a reason in the pull
   request. Dependabot proposes updates weekly; advisories are checked on every push and weekly.
3. **Secrets.** Never committed (gitleaks runs on every push). Configuration reads secrets only from
   `SENTINEL_SECRET_*` environment variables.
4. **Releases.** Tagged from `main`, with a changelog entry. The release workflow builds the image, signs it,
   attaches the SBOM and provenance, and publishes the digest. Customer sites pin to a digest and upgrade
   deliberately after the overlay's own tests pass on the new version.
5. **Customer configuration changes** use the product's own change control: versioned, checked, optionally
   approved by a second person, replayable, and moved between environments as signed bundles.
