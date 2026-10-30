# Security policy

This covers the whole repository: the canon, the gates, the bases and Sentinel.

## Reporting a vulnerability

Email **mohanp@kbgrid.com** with what you found, how to reproduce it and the version (`sentinel --version`
or the image digest). Please do not open a public issue. We acknowledge within two working days, give a first
assessment within five, and agree a disclosure date with you; fixes for critical issues aim for seven days.
We do not take legal action against good-faith research that avoids privacy violations, data destruction and
service disruption.

## Supported versions

The latest minor release gets security fixes; the one before it gets critical fixes for six months after a
new minor release.

## Verifying what you run

Release images are signed keylessly with Sigstore and carry a CycloneDX SBOM attestation:

```
cosign verify ghcr.io/mohankbgrid/kbg-sentinel:<version> \
  --certificate-identity-regexp 'https://github.com/MohanKbgrid/kbg-platform/.github/workflows/release-sentinel.yml@refs/tags/sentinel-v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type cyclonedx ...same flags... ghcr.io/mohankbgrid/kbg-sentinel:<version>
```

Each GitHub release also has `sbom.cdx.json` and `image-digest.txt`. Pin deployments to the digest.

More: [sentinel/docs/security/](sentinel/docs/security/README.md).
