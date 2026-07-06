# CoRIM presentation

The deck lives in [`presentation.md`](presentation.md) as a Markdown
file that converts to PowerPoint via either **pandoc** (no browser
needed) or **Marp** (richer styling, needs Chromium).

## Render to PowerPoint (`.pptx`)

### Option A — pandoc (recommended, no extra deps)

```sh
pandoc docs/presentation.md -o docs/presentation.pptx --slide-level=2
```

Each `## Heading` becomes one slide. The Marp front-matter at the top
is read as YAML metadata (harmless to pandoc). Output: `docs/presentation.pptx`.

To use a custom PowerPoint template (your team's brand, etc.):

```sh
pandoc docs/presentation.md -o docs/presentation.pptx \
       --slide-level=2 --reference-doc=path/to/template.pptx
```

### Option B — Marp (better styling, requires Chromium)

```sh
# One-off, needs Chromium/Chrome/Edge already installed on PATH:
npx @marp-team/marp-cli docs/presentation.md --pptx --allow-local-files
```

On a fresh Linux box without a browser, install one first (needs sudo):

```sh
sudo apt install chromium-browser   # Debian/Ubuntu
# then re-run the npx command above
```

## Other formats

```sh
pandoc docs/presentation.md -o docs/presentation.pdf  --slide-level=2
pandoc docs/presentation.md -o docs/presentation.html --slide-level=2 -t revealjs -s
```

With Marp (needs browser):

```sh
npx @marp-team/marp-cli docs/presentation.md --pdf
npx @marp-team/marp-cli docs/presentation.md --html
npx @marp-team/marp-cli -w docs/presentation.md      # live preview
```

## VS Code preview

Install the **Marp for VS Code** extension (`marp-team.marp-vscode`)
and the deck previews live in the editor — no browser required for
preview, only for export.

## Editing tips

- Slides are separated by `---` on its own line (Marp convention).
  Pandoc ignores these and uses `## Heading` as the slide break with
  `--slide-level=2`, which matches the deck's structure 1:1.
- Front-matter (`marp: true`, `theme:`, `style:`) controls the whole
  deck when rendered with Marp; pandoc reads the same block as YAML
  metadata.
- Per-slide directives use HTML comments like `<!-- _class: lead -->`
  — these are Marp-only and ignored by pandoc.
- Keep one idea per slide; the existing slides are sized to be readable
  at 16:9 / 1280×720.
