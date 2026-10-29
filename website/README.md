# KB Grid website

Static Next.js 15 (App Router) site. All copy lives in `src/content/`; pages are thin.

```bash
npm install
npm run dev        # http://localhost:3000
npm run build      # static export to ./out
```

## Where things are

| Change | Edit |
|---|---|
| Palette / theme | `src/styles/tokens.css` (only file with colour values) |
| Platform copy: canon, core, Sentinel | `src/content/platform.ts` |
| Domains | `src/content/domains.ts` |
| Projects (anonymised) | `src/content/projects.ts` |
| Nav, tagline, contact email | `src/content/site.ts` |

## Decisions baked in

- **No client names.** Projects describe capabilities only. Check screenshots, sample data and URLs before adding any.
- **Theme.** Ink canvas with gold primary and jade secondary, held in one tokens file. Do not reuse any customer's logo, name or copy.
- **Intelligence layer.** Ask AI and Sentinel are presented as built to plug into every product. Project badges show only what is verified shipped in the repos.

## Open items (search for `TODO(founder)`)

- Confirm status labels in `projects.ts` (NextGen and Foundation Management as "Live" are inferred).
- Real contact address, company story and location; confirm the team bios in `src/content/team.ts`.
- Contact form handler, analytics, favicon, social image, logo.

## Deploy to Cloudflare Pages

The site is a static export (`out/`). Two ways to publish:

**A. Git integration (recommended).** Push this repo to GitHub, then in Cloudflare:
Workers & Pages → Create → Pages → Connect to Git. Build command `npm run build`,
output directory `out`, environment variable `NODE_VERSION=22`.

**B. Direct upload from a machine that can reach Cloudflare.**
```bash
export CLOUDFLARE_API_TOKEN=...   # token with "Cloudflare Pages: Edit"
export CLOUDFLARE_ACCOUNT_ID=...
npm run deploy                    # builds, then wrangler pages deploy out
```

**Custom domain.** A DNS CNAME alone is not enough on Pages: open the Pages project →
Custom domains → add the hostname, and point the CNAME at `<project>.pages.dev`
(the dashboard offers to create the record when the zone is on Cloudflare).
Headers and caching are in `public/_headers`.
