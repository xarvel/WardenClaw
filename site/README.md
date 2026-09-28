# WardenClaw site

*Take back control.* The landing page and documentation of WardenClaw, built with
[Astro](https://astro.build) as a static site, in English.

```sh
npm install
npm run dev      # local preview
npm run build    # static output in dist/
```

- `src/pages/`: routes (`/`, `/docs/…`); `src/components/`: landing and docs layout;
  `src/i18n/`: interface strings; `src/config.ts`: domain, install URL, repository links.
- `src/docs/*.en.md`: documentation pages (CLI, installation, tamper resistance).
- One locale for now. Another one is a dictionary in `src/i18n/` with its own path, its entries
  in `src/claims.ts`, `src/docs/*.<lang>.md` and pages under that path.
- `public/`: fonts (self-hosted, with their licenses), brand files, `CNAME` (the
  custom domain; the build checks it against `DOMAIN` in `src/config.ts`).
- `src/brand/`: the diagrams, served at `/brand/` by `src/pages/brand/[diagram].ts` (see
  "Features left out of a release" below).
- `scripts/fetch-install-sh.sh`: takes `install.sh` of the latest signed daemon release for the
  site root.

Deployed to GitHub Pages by `.github/workflows/site-pages.yml` on every push to `main` under
`site/` and on every published daemon release. The site root also serves `install.sh`, a checked
copy of the one in the latest signed release, so the install command is
`curl -fsSL https://wardenclaw.dev/install.sh | sudo sh`; see `daemon/docs/release.md`.

No trackers, no cookies, no third-party requests.

## Features left out of a release

Some features exist in the code but are not part of a release yet. `FEATURES` in `src/config.ts`
has one flag for each (`hardwareKey`: the YubiKey second factor, `appleWatch`: the Apple Watch app,
`phoneJudge`: the risk judge on a model running on the phone; the judge at a URL is always in).
While a flag is `false` the site says nothing about the feature; set it to `true` and every text
comes back. Mark new text about such a feature the same way:

- **Docs** (`src/docs/*.md`), removed by the `doc-features` plugin in `astro.config.mjs`:
  - `<!-- feature:NAME -->` … `<!-- /feature -->`: kept only while the flag is on. Around blocks
    (each marker on its own line, with blank lines around) or inline inside one paragraph,
    heading, link text or table cell. `<!-- feature:!NAME -->` … `<!-- /feature -->` is the text
    for while the flag is off (the release wording).
  - `<!-- feature-item:NAME -->` anywhere in a list item or a table row: the whole item or row.
  - The `title` and `description` of the frontmatter take the inline form too (quote the value).
  - Code blocks can't hold markers: put two blocks, one in `feature:NAME`, one in `feature:!NAME`.
  - A heading's anchor follows its text: a link to it needs both variants.
- **TS strings** (`src/i18n/`, `src/claims.ts`, components): `feat("NAME", on, off)` for a phrase,
  `...only("NAME", item)` for items of a list.
- **README.md** (repository root): the build checks it against `README_FEATURES` in
  `src/claims.ts`, which keeps the full text word for word. While a flag is off README.md must
  carry the release text and not the full one; once it is on, the full one.

To bring a feature back: set its flag to `true`, put the `full` texts of its `README_FEATURES`
entries into README.md in place of the `release` ones (the build names what is missing), build.
No page is dropped as a whole: `src/docs/apple-watch.*.md` also holds the APNs setup the iPhone
needs, so it is served at `/docs/apns/` with its Apple Watch parts marked.

## License

Copyright (C) 2026 The WardenClaw Authors (see [AUTHORS](../AUTHORS)).

| part | license |
|---|---|
| site code (everything not listed below) | **Apache License 2.0**, [LICENSE](LICENSE), SPDX `Apache-2.0` |
| documentation texts in `src/docs/` | **Creative Commons Attribution 4.0 International**, [src/docs/LICENSE](src/docs/LICENSE), SPDX `CC-BY-4.0` |
| diagrams `src/brand/architecture.*.svg`, `src/brand/lifecycle.*.svg` (served at `/brand/`) | CC BY 4.0 |
| fonts in `public/fonts/` | SIL Open Font License 1.1 (texts next to the fonts) |
| logo and icons (`public/brand/logo.svg`, `favicon.svg`, `apple-touch-icon.png`, `public/favicon.ico`), hero image and app screenshot | not licensed: trademarks of The WardenClaw Authors, see [TRADEMARKS.md](../TRADEMARKS.md) |

When you reuse documentation under CC BY 4.0, credit "The WardenClaw Authors" and link to the
source page. A fork of the site has to replace the logo and the icons.

See [NOTICE](NOTICE). Contributions: [CONTRIBUTING.md](../CONTRIBUTING.md) (DCO sign-off);
vulnerabilities: [SECURITY.md](../SECURITY.md).
