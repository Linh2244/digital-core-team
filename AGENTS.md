# AGENTS.md

Static multi-page marketing/knowledge site for the DigitalCore Team. Plain HTML + CSS + vanilla JS (ES5 style, IIFEs, `var`), no build system, no package manager, no tests, no lint, no CI. Edits are committed directly.

## Preview

Serve statically (PDF embeds behave inconsistently from `file://`):

```
python -m http.server 8000
```

## Pages and CSS mapping

| Page | Purpose | CSS |
|---|---|---|
| `index.html` | Home: hero, features, roadmap, articles, stats | `styles.css`, `index.css` |
| `docs.html` | Docs intro / platform modules | `styles.css`, `docs.css` |
| `knowledge-base.html` | PDF guide library + quick-reference table | `styles.css`, `docs.css` |
| `viewer.html` | Online PDF reader (`viewer.html?doc=<key>`) | `styles.css`, `viewer.css` |
| `tools.html` | Tool Database: DigitalCore Security Toolkit catalog | `styles.css`, `docs.css`, `tools.css` |
| `about.html` | About / principles | `styles.css`, `docs.css`, `about.css` |

`styles.css` is the shared design system: CSS custom properties in `:root` (colors like `--cyan`, `--blue`, fonts, radii). Reuse these tokens; do not hardcode hex values.

`tools.html` is a static catalog of the Python security toolkit (`pyscan`, `httpsec`, `dnslookup`, `subfind`, `dirbf`, `loginbf`, `secretscan`, `jwtcheck`, `pwgen`, `pwcheck`, `hashid`, `logsec`, `tlscheck`, `depcheck`). The downloadable tool Python scripts live in the `tools/` folder and are linked via `download` buttons on each card; the legal-warning callout must stay.

## Adding a document (PDF guide)

All five pages/drivers below must stay in sync:

1. Drop the PDF in `pdfs/`.
2. Add an entry to the `DOCS` map in `viewer.html` (key → `file`, `titleEn`, `titleVn`, `sizeEn`, `sizeVn`). Keys in use: `nen-tang`, `lap-trinh`, `linux`, `security`, `bao-cao-ctf`. Unknown `?doc=` falls back to `nen-tang`.
3. Add a "Read Full Article" link (`viewer.html?doc=<key>`) in the articles section of `index.html` and a `.doc-item` card in `knowledge-base.html`.
4. Displayed sizes (in `knowledge-base.html`, `index.html`, and `DOCS`) are hardcoded text — update to match the actual PDF size.

Gotcha: `pdfs/Vận dụng thành thạo.pdf` (the CTF guide) has spaces and Vietnamese diacritics in its filename — preserve the exact name; `viewer.html` references it verbatim. `pdfs/Kali_Linux_Tools_Detailed_Guide.pdf` is committed but linked from nowhere; don't assume it is part of the published set.

## Bilingual EN/VN i18n

Every user-visible string needs both `data-en` and `data-vn` attributes; the literal text content is the English default. The toggle in each page reads those attributes, swaps `innerHTML`, and persists the choice in `localStorage["dc-lang"]`. The button label shows the *target* language (`VN` when currently English). Any visible text added without both attributes will not translate.

## Inline JS is duplicated per page

Each page inlines its own copy of the same boilerplate IIFE (particles canvas, mobile menu, language toggle) — there is no shared JS file. Keep behavior edits consistent across pages. `viewer.html` has the language toggle but no particles/hamburger; `index.html` also has reveal-on-scroll and count-up logic. All scripts are plain ES5 (`var`, `"use strict"`); match that style.

## Git

Single `main` branch, remote at `github.com/Linh2244/digital-core-team`, no workflows or pre-commit hooks.
