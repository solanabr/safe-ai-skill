# solana-new / superstack — ASCII Art & Branding Inventory

Verbatim collection of all ASCII art, text-art banners, logos, and decorative
terminal output found in the `sendaifun/solana-new` project (npm package
`superstack`, site `solana.new`).

Source: `https://github.com/sendaifun/solana-new` (shallow clone, READ-ONLY) plus
the locally installed skills under `~/.claude/skills/`.

Notes on what was found:
- The project DOES contain real ASCII art (not just emoji): a FIGlet-style
  `superstack` wordmark and a fully hand-drawn "Founder Pass" terminal card with
  a Solana/SendAI block-character logo.
- Art lives in the CLI (`cli/banner.ts` + `cli/branding.ts`), the shell
  installers (`install.sh`, `setup`, `public/setup.sh`), and the standalone
  welcome screen (`solana-pass.sh`).
- The installed skill payload (`~/.claude/skills/`, `~/.superstack/`) contains
  NO banner art — only Markdown skills and table/diagram box-drawing. All the
  decorative art ships in the CLI/installer layer of the repo, not the skills.

---

## 1. `superstack` wordmark (FIGlet banner) — primary launch banner

This is the main banner. It is defined once as a string array and rendered with a
purple→pink truecolor gradient on every CLI launch (no args, `--help`).

**Source:** `cli/branding.ts` lines 36–41 (`ASCII_ART` constant).
**Used by:** `cli/banner.ts` → `renderBanner()`, called from `cli/index.ts`
(the no-args "friendly starter screen" at line 555 and `--help` at line 571).
Each line is prefixed with two spaces and passed through `gradientLine()`.

Verbatim (raw, exactly as in `branding.ts` — note the leading spaces inside each string):

```
  ___ _   _ ___ ___ ___ ___ _____ _   ___ _  __
 / __| | | | _ \ __| _ \ __|_   _/_\ / __| |/ /
 \__ \ |_| |  _/ _||   /__ \ | |/ _ \ (__| ' < 
 |___/\___/|_| |___|_|_\___/ |_/_/ \_\___|_|\_\
```

Tagline printed underneath (dim) — `PRODUCT_DESCRIPTION` in `branding.ts`:

```
Ship on Solana — skills, repos, MCPs
```

### Colors / ANSI
- Rendered char-by-char with a 6-stop RGB gradient defined in `cli/colors.ts`
  (`GRADIENT_STOPS`): purple `rgb(130,80,255)` → pink `rgb(255,25,120)`, via
  `155,65,245` · `180,50,230` · `205,40,205` · `230,35,170`.
- Each character emits a truecolor escape: `\x1b[38;2;{r};{g};{b}m`.
- Honors `NO_COLOR` / `--no-color` (then prints plain, no escapes) and
  `SUPERSTACK_NO_BANNER=1` (skips banner entirely).
- Tagline wrapped in `DIM` (`\x1b[2m`) … `RESET` (`\x1b[0m`).

---

## 2. Same wordmark in the shell installers (cyan/bold variant)

The shell installers print the identical FIGlet wordmark, but statically colored
**cyan + bold** instead of the gradient. Tagline differs slightly
("Idea to Launch").

**Sources (all three carry the same banner):**
- `install.sh` lines 29–34
- `setup` (executable bootstrap) lines 87–92
- `public/setup.sh` lines 144–152 (this is the file served at
  `https://www.solana.new/setup.sh`, the documented installer:
  `curl -fsSL https://www.solana.new/setup.sh | bash`)

**Used as:** the install/setup header echoed at the top of the installer run.

Raw, with the surrounding `printf` so the escapes are visible
(`${CYAN}=\033[0;36m`, `${BOLD}=\033[1m`, `${DIM}=\033[2m`, `${RESET}=\033[0m`):

```sh
printf "\n"
printf "  ${CYAN}${BOLD} ___ _   _ ___ ___ ___ ___ _____ _   ___ _  __${RESET}\n"
printf "  ${CYAN}${BOLD}/ __| | | | _ \\ __| _ \\ __|_   _/_\\ / __| |/ /${RESET}\n"
printf "  ${CYAN}${BOLD}\\__ \\ |_| |  _/ _||   /__ \\ | |/ _ \\ (__| ' < ${RESET}\n"
printf "  ${CYAN}${BOLD}|___/\\___/|_| |___|_|_\\___/ |_/_/ \\_\\___|_|\\_\\\\${RESET}\n"
printf "  ${DIM}Ship on Solana — Idea to Launch${RESET}\n\n"
```

Clean (rendered, no escapes):

```
  ___ _   _ ___ ___ ___ ___ _____ _   ___ _  __
 / __| | | | _ \ __| _ \ __|_   _/_\ / __| |/ /
 \__ \ |_| |  _/ _||   /__ \ | |/ _ \ (__| ' < 
 |___/\___/|_| |___|_|_\___/ |_/_/ \_\___|_|\_\
  Ship on Solana — Idea to Launch
```

---

## 3. "What gets installed" info box (installer)

A simple single-line box-drawing frame printed near the end of install.

**Sources:** `install.sh` lines 141–144; `setup` lines 196–199 (and the
equivalent in `public/setup.sh`). Color: cyan border (`${CYAN}`), bold label.

Clean (rendered):

```
  ┌─────────────────────────────────────────────────────────────────┐
  │ What gets installed: Agent Skills in ~/.claude/skills/,              │
  │ ~/.codex/skills/, and ~/.agents/skills/.                       │
  └─────────────────────────────────────────────────────────────────┘
```

(The inner padding is intentionally hand-tuned in the source and the bold escape
makes the visible width line up in a real terminal.)

---

## 4. "Copilot Insight" bordered box (CLI runtime, generated)

Not static art, but a decorative box generator used in the interactive CLI.

**Source:** `cli/colors.ts` → `insightBox(text, width=60)` (lines 63–86).
Builds a titled box with light box-drawing characters:

```
  ┌ Copilot Insight ───────────────────────────────────────────┐
  │ <wrapped text>                                              │
  └──────────────────────────────────────────────────────────┘
```

Top border uses `┌` + ` Copilot Insight ` + `─`-fill + `┐`; body rows are
`│ … │`; bottom is `└` + `─`-fill + `┘`.

---

## 5. SendAI "S" logo — Solana block-character art (Founder Pass watermark)

A hand-drawn block-character rendering of the SendAI / Solana "S-circle" mark,
built from `▄ █ ▀` half-block glyphs. Used as the watermark / side art on the
Founder Pass welcome screen.

**Source:** `solana-pass.sh` lines 305–328 (the `LOGO=( … )` array).
**Used as:** ghost watermark beside the Founder Pass card. Color in source is a
near-black "ghost" shade `\033[38;5;234m` (1 step above background); shown here in
plain form.

Verbatim (clean — the block glyphs, leading spaces preserved):

```
           ▄▄▄▄████▄▄▄▄
        ▄▄███████████████▄
      ▄███▀▄███▀████████▀███
     ▄██▀ ▄██▀  █████████ ▀██▄
    ██▀   ███   ██████████▄ ██▄
   ██▀  ▄███▄██████████████▄ ██▄
   ██▄██████▀▀▀▀██████████▀  ▀██
  ████▀▀ ███    ▀▀▀▀█████▄    ██
  ████▄  ███        ██████  ▄███
  ▀█████████▄▄      ████████████
   ██▄ ▀▀▀████████  █████▀▀▀ ██▀
   ▀██▄            ▄█████   ███
    ▀██▄  ███      █████▀  ██▀
      ███▄ ███▄   █████▀▄▄██▀
        ▀█████████████████▀
          ▀▀▀█████████▀▀
```

---

## 6. SOLANA·NEW "Founder Pass" terminal card (full welcome screen)

The flagship piece: a full ticket/membership-card drawn with double-line and
light box-drawing characters, perforated stub edges (`╌`, `┄`), a date "seal"
(`╭───────╮ … ╰───────╯`), stamp dots, and the SendAI logo (piece #5) floating to
the right.

**Source:** `solana-pass.sh` (entire render; rows assembled lines ~283–405).
Title comment at top of file: `SOLANA·NEW — Founder Pass · Terminal Welcome
Screen`.
**Used as:** a standalone terminal welcome screen.
`Usage: bash solana-pass.sh [theme]`. Themes: `gold` (default), `blue`, `cyber`,
`royal`, `obsidian`, `platinum` (color palette only — same geometry).

This card is a **dynamic template**: NAME comes from `git config user.name`,
ISSUED is today's date, the seal is the current month/day/'YY, GITHUB shows the
linked account or `NOT CONNECTED`, and `N° 0142` is the founding-builder number.
The capture below was rendered locally with `gold` theme and ANSI stripped, so
NAME/ISSUED/date reflect the rendering environment — treat those fields as
placeholders.

Clean (rendered with ANSI stripped; the SendAI logo is the right-hand column):

```
        ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ 
  ╔═════╕ ╔════════════════════════════════════════════════════════════╗ ╕═════╗           ▄▄▄▄████▄▄▄▄
  ║     │ ║ ◆ SOLANA·NEW  |  FOUNDER PASS               N° 0 1 4 2 ║ │     ║        ▄▄███████████████▄
  ║     │ ║ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄ ║ │     ║      ▄███▀▄███▀████████▀███
  ║     ╯ ║                                                            ║ ╰     ║     ▄██▀ ▄██▀  █████████ ▀██▄
  ║  S    ║ NAME  ····· CANOKAUE                                  ║       ║    ██▀   ███   ██████████▄ ██▄
  ║  O    ║ ISSUED ···  11  JUN  2026                      ╭───────╮ ║       ║   ██▀  ▄███▄██████████████▄ ██▄
  ║  L    ║ CLASS  ···· FOUNDING  BUILDER                  │  JUN  │ ║       ║   ██▄██████▀▀▀▀██████████▀  ▀██
  ║  A    ║ GITHUB ···· ◆  NOT  CONNECTED                │  11   │ ║       ║  ████▀▀ ███    ▀▀▀▀█████▄    ██
  ║  N    ║                                              │  '26  │ ║       ║  ████▄  ███        ██████  ▄███
  ║  A    ║                                ╰───────╯ ║       ║  ▀█████████▄▄      ████████████
  ║     ╮ ║                                                            ║ ╭     ║   ██▄ ▀▀▀████████  █████▀▀▀ ██▀
  ║     │ ║ STAMPS ···  ○ IDEA    ○ BUILD   ○ SHIP            ║ │     ║   ▀██▄            ▄█████   ███
  ║     │ ║     ──────────────────────────────────────────────────     ║ │     ║    ▀██▄  ███      █████▀  ██▀
  ║     │ ║     you're now a certified agentic engineer on solana      ║ │     ║      ███▄ ███▄   █████▀▄▄██▀
  ║     │ ║     ──────────────────────────────────────────────────     ║ │     ║        ▀█████████████████▀
  ║     │ ╠════════════════════════════════════════════════════════════╣ │     ║          ▀▀▀█████████▀▀
  ║     │ ║ SUPERTEAM              solana.new                   SendAI ║ │     ║
  ╚═════╛ ╚════════════════════════════════════════════════════════════╝ ╛═════╝
        ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ ╌ 
```

### Card elements / colors
- Outer frame: double-line `║ ═ ╔ ╗ ╚ ╝ ╠ ╣`; ticket stubs on both sides with
  perforation column `│`/`╕`/`╛`/`╮`/`╯`.
- Top/bottom dashed perforation: `╌ ╌ ╌ …`.
- Inner divider under the header: `┄┄┄…`.
- "Seal": small rounded box `╭───────╮ / │  MON  │ / │  DD   │ / │  'YY  │ /
  ╰───────╯`.
- Left stub spells `S O L A N A` vertically (one letter per row).
- Stamp row: `○ IDEA  ○ BUILD  ○ SHIP` (open circles = not yet stamped).
- Theme = palette only. `gold` uses gold/amber tones; `cyber` uses
  cyan/magenta; etc. Geometry is identical across themes.
- Tagline: `you're now a certified agentic engineer on solana`.
- Footer: `SUPERTEAM   solana.new   SendAI`.

---

## 7. Decorative status glyphs (installer log helpers)

Minor, but part of the brand's terminal voice. From `install.sh` lines 21–24
(and mirrored in `setup`/`public/setup.sh`):

```
  ▸ <log message>      (green)
  ! <warning>          (yellow)
  ✗ <failure>          (red)
  ✓ <ok>               (green)
```

---

## 8. README / npm branding (non-ASCII-art, for completeness)

`README.md` has no FIGlet art — it uses shields.io badges and an image cover.
Captured here as the textual branding:

- Title: `# superstack`
- Tagline line: *"The open-source platform behind solana.new — 25 journey skills
  that take you from 'what should I build?' to a shipped, funded product on
  Solana."*
- One-line install (the canonical entry point):
  `curl -fsSL https://www.solana.new/setup.sh | bash`
- `PRODUCT_TAGLINE` (branding.ts): `Ship on Solana — Idea to Launch`
- Starter-screen voice (`cli/index.ts` line 556):
  `i'm your solana buddy by SendAI & Superteam.`

---

## Wiring into solana-claude

Where this art could be reused in this repo (`safe-ai-skill` / solana-claude):

1. **`SessionStart` hook banner in `.claude/settings.json`** — currently prints a
   plain `🤖 Solana Claude Config is ON` line. Replace it with a real wordmark.
   Two good options:
   - Reuse the cyan/bold `superstack`-style FIGlet approach but with our own text
     (e.g. a "SOLANA CLAUDE" or "SAFE-AI-SKILL" FIGlet), so the look matches the
     solana-new family.
   - Or drop in piece #5 (the SendAI/Solana block-logo) as a compact splash.

2. **A `safe-ai-skill` / CLI startup banner** — if/when a launcher script exists, mirror
   `renderBanner()`: print the wordmark with the purple→pink gradient
   (`GRADIENT_STOPS` from `cli/colors.ts`) and a dim one-line tagline, honoring
   `NO_COLOR`.

3. **Installer / setup script header** — if this repo ships a `setup.sh`, echo a
   wordmark + status glyphs (`▸ ! ✗ ✓`) exactly like `install.sh` for a
   consistent install experience.

### Ready-to-use SessionStart banner snippet

Drop-in shell `echo`/`printf` snippet for a `SessionStart` hook `command`
(cyan + bold wordmark + dim tagline, the same style as the solana-new installer).
Single-quote-safe and self-contained:

```bash
printf '\n  \033[1;36m ___      _                  ___ _              _\033[0m\n'
printf '  \033[1;36m/ __| ___| |__ _ _ _  __ _   / __| |__ _ _  _ __| |___\033[0m\n'
printf '  \033[1;36m\\__ \\/ _ \\ / _` | ` \\/ _` | | (__| / _` | || / _` / -_)\033[0m\n'
printf '  \033[1;36m|___/\\___/_\\__,_|_||_\\__,_|  \\___|_\\__,_|\\_,_\\__,_\\___|\033[0m\n'
printf '  \033[2mSafe AI Skill — config is ON\033[0m\n\n'
```

If you prefer to keep it minimal and just reuse the exact solana-new `superstack`
wordmark verbatim (cyan + bold), this is the smallest drop-in:

```bash
printf '\n'
printf '  \033[1;36m ___ _   _ ___ ___ ___ ___ _____ _   ___ _  __\033[0m\n'
printf '  \033[1;36m/ __| | | | _ \\ __| _ \\ __|_   _/_\\ / __| |/ /\033[0m\n'
printf "  \\033[1;36m\\__ \\ |_| |  _/ _||   /__ \\ | |/ _ \\ (__| ' < \\033[0m\\n"
printf '  \033[1;36m|___/\\___/|_| |___|_|_\\___/ |_/_/ \\_\\___|_|\\_\\\033[0m\n'
printf '  \033[2mShip on Solana — Idea to Launch\033[0m\n\n'
```

> Note: do NOT edit `.claude/settings.json` from this doc — this is just the
> snippet to paste into the existing `SessionStart` hook's `command`.

---

## Source file index

| # | Art | Source file (in `sendaifun/solana-new`) | Where used |
|---|-----|------------------------------------------|------------|
| 1 | `superstack` FIGlet (gradient) | `cli/branding.ts` L36–41 + `cli/banner.ts` | CLI launch banner / `--help` |
| 2 | `superstack` FIGlet (cyan/bold) | `install.sh` L29–34, `setup` L87–92, `public/setup.sh` L144–152 | Installer header (`solana.new/setup.sh`) |
| 3 | "What gets installed" box | `install.sh` L141–144, `setup` L196–199 | Installer footer |
| 4 | "Copilot Insight" box generator | `cli/colors.ts` L63–86 (`insightBox`) | Interactive CLI |
| 5 | SendAI/Solana "S" block logo | `solana-pass.sh` L305–328 (`LOGO`) | Founder Pass watermark |
| 6 | "Founder Pass" terminal card | `solana-pass.sh` (full render) | Standalone welcome screen |
| 7 | Status glyphs `▸ ! ✗ ✓` | `install.sh` L21–24 | Installer log lines |
| 8 | README/npm text branding | `README.md`, `cli/branding.ts` | Repo / npm page |
