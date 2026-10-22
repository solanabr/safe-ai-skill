# Scanner coverage

safe-ai-skill scans skill packs with a native rule engine (`crates/engine/src/verify/rules/`).
It has no network access, runs no processes and has no LLM. This page maps the engine against the
pack-review checklist in solanabr/ai-kit's `docs/skill-packs.md`, and lists what stays a manual
review step. Decision record: design spec D2.4–D2.5, D2.10 and D7.1.

## How a pack is graded

Every finding has a rule id, a severity (`info`, `warn` or `high`), a pack-relative `path:line` and a
context:

| Context | What it covers |
|---|---|
| `code` | Executable source, decided by extension, shebang or exec bit, plus `` !`cmd` `` lines. A lexer marks strings, regex literals, comments and interpolations; lines end at `\n`, `\r`, U+2028 or U+2029. Its whole state carries across lines: block comments, Python triple-quoted strings (f-string flag included), JS template text, backslash-continued strings, and every open interpolation with its bracket depth (nesting past 64 is lexed as code). Lines are joined into statements (open brackets, `\` continuations), and a tool and its marker must appear in the same command. |
| `doc` | Markdown prose, fenced blocks and inline code, and any other text file (JSON, YAML, HTML …). |
| `meta` | Pack structure: manifests, harness config, `SKILL.md` frontmatter, symlinks and binaries. |

The pack grade (`rules::grade`) is decided as follows:

* **clean**: nothing above INFO.
* **warn**: the worst finding is WARN. **Findings in docs are capped at WARN**, because the runtime
  gates catch execution.
* **high**: at least one code or meta finding at HIGH. A pack seen for the first time is recorded as
  *unreviewed* and the user is warned. It is never blocked.
* **block**: only a combination rule fires. Drift against a pin or a committed `packs.lock` is
  decided by the verify state machine, not by the scanner.

A sink written inside a string literal or a comment (code-as-data: a help text, a rule table, a
command built for a remote host) is graded WARN and never feeds a combination rule. Interpolations
are code, not data: JS template `${…}`, Python f-string `{…}` and shell `"$(…)"`. One exception:
a real base64 payload (see `exec_b64_literal`) in the same command as a sink feeds the combo even
when the sink is quoted. Google's `exec(base64.b64decode('{encoded_script}'))`, built as a
string around a placeholder, stays WARN.

### What is read

* **Text decoding.**
  * UTF-8 is decoded with a leading BOM dropped.
  * UTF-16 and UTF-32 are decoded by their byte-order mark, but only when the content is
    plausible for that encoding: no invalid unit, and at least half the characters ASCII. Behind
    an implausible mark (a forged one in front of ASCII), the bytes are also read as UTF-8, both
    readings are scanned, and the worse result counts.
  * A text or code file (known extension or shebang) with NUL bytes is read with the NULs
    stripped and gets `nul_bytes` WARN. So is UTF-16/32 text with no mark and no extension:
    NULs make up a quarter of its bytes and the rest is printable ASCII.
  * Only archive or executable magic, `.pyc`, or other NUL-bearing data make a file binary.
* **What is skipped.** The pack's own top-level `.git` (a nested one is scanned), and lockfiles by
  exact name (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
  `bun.lock(b)`, `deno.lock`, `Cargo.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`,
  `Gemfile.lock`, `composer.lock`, `Podfile.lock`, `pubspec.lock`, `mix.lock`, `flake.lock`,
  `packages.lock.json`) without an exec bit or shebang. Any other `*.lock` is scanned.

## Combination rules (the only BLOCKs)

| Combo | Fires when |
|---|---|
| `padding_sink` | A run of 100+ whitespace characters (space, tab, Unicode Zs, blank-rendering fillers) has an exec, env-dump or network sink on the same line; or 50+ blank lines are followed by such a sink. Code only. |
| `exec_b64_literal` | An execution sink and a quoted base64 literal of 64+ characters appear in the same command, the sink itself possibly inside a string. The literal must not be hex, and either a decoder is present or the literal decodes to text, so signatures, hashes and keys don't count. |
| `eval_decoder` | `eval` / `Function(` anywhere in the pack's code plus a decoder anywhere in it (a split payload). Only real bundles are left out of this cross-file rule: `*.min.js`, `node_modules/`, or a file carrying a bundler runtime (esbuild `__commonJS`/`__toESM`, webpack `__webpack_require__`, Rollup `commonjsGlobal`, Parcel `parcelRequire`) or a minified shape (1 KiB or more, averaging 1000+ bytes per line). A `dist/`, `build/` or `out/` directory alone proves nothing. |
| `symlink_escape` | A symlink target leaves the pack, resolved from the link's directory with in-pack symlinks met on the way expanded (`a -> sub/l/..` with `sub/l -> ..` escapes). An absolute target always counts. Nothing outside the pack is read. |
| `pyc_beside_py` | `x.pyc` (or `__pycache__/x.cpython-NNN.pyc`) ships next to `x.py`. |
| `native_binary` | A native ELF, Mach-O or PE file. BPF and SBF `.so` files (e_machine 247 and 263) are exempt. |
| `masquerade_referenced` | Archive or executable bytes sit behind a text extension, and a `SKILL.md` names the file, its stem or its disguised inner extension (`.docx` in `x.docx.txt`). |
| `bang_exfil` | A `` !`cmd` `` outside a closed fence touches the network, a secret path, the environment or a credential variable, directly or by running a pack script that does (`bash scripts/x.sh`, `./x.sh`, `${CLAUDE_SKILL_DIR}/x.sh`). A fence that never closes hides nothing. |
| `description_injection` | A `SKILL.md` description carries shell syntax (`$(`, `\| sh`, `&&` …), a URL with an action verb or next to a credential (see [Description URLs](#description-urls-a-deliberate-deviation-from-d24)), an instruction aimed at every turn ("before responding …", "first, always run …"), or injection phrasing. The description is read as YAML (escapes, quoted keys, block scalars) and line by line, and tag characters are decoded first. |
| `lifecycle_network` | An install-time npm script (`preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare`, `dependencies`, `prepack`, `postpack`, pnpm's `pnpm:devPreinstall`) reaches the network (curl, wget, npx, a URL …) or evaluates inline code (`node -e`, `python -c`, `eval`). Names are compared after JSON decoding. |
| `harness_bypass` | A shipped `.claude/settings*.json` contains `bypassPermissions`, a `defaultMode` key or `dangerously*`, compared after JSON decoding (`\u0064efaultMode` counts). |
| `registry_hijack` | Code writes package-manager registry config (`.npmrc`, `.yarnrc`, `pip.conf`, `npm config set registry`, git `insteadOf` …) and names a registry host other than npmjs, yarnpkg, PyPI, crates.io or rubygems in the same file. A git `insteadOf` that only adds credentials to the same host is not a hijack. |

## Description URLs: a deliberate deviation from D2.4

D2.4 blocks a description URL only when a fetch verb comes before it. The scanner is stricter,
because the description is injected into every session: an instruction there to fetch, send to or
obey a URL acts before any task does.

* **BLOCK** (`description_injection`) when a URL comes with an action verb in its sentence (up to
  60 bytes before it or 40 after): fetch, curl, wget, download, get, visit, open, navigate, go to,
  send, post, upload, submit, report, read, obey, consult, follow, load, retrieve, pull, run,
  execute, source, install.
* **BLOCK** when the description has any URL and also names a secret path (`~/.config/solana`,
  `id.json`, `.ssh/`, `.env` …) or a credential term: private key, secret key, seed phrase,
  recovery phrase, mnemonic, password, passphrase, ssh key, keypair file, wallet file, env vars,
  environment variables, `process.env`, `os.environ`, `printenv`. A generic "API key" does not
  count, because vendor descriptions name it (ai-kit's `alchemy-mcp` does).
* **WARN** (`description_url`) for a bare URL, and for scheme-only mentions such as `s3://`.

The trade-off: a vendor description that says "install …" or "send …" next to its own URL blocks.
The pack can still be reviewed and pinned.

## ai-kit checklist coverage

The checklist from ai-kit's `docs/skill-packs.md` ("Non-official pack provenance"):

| Checklist item | Rules (code / doc severity) | Stays manual |
|---|---|---|
| Lines over 500 characters (payload hidden behind padding) | `padding_horizontal` HIGH / WARN; `padding_vertical` HIGH / WARN; `long_line` INFO; `encoded_blob` WARN (a long base64 run that decodes to text, i.e. printable ratio ≥ 0.75; data such as account state sits near 0.34); combo `padding_sink` | Reading what a long data line encodes |
| `eval` / `atob` / `new Function` / `createRequire` | `eval` HIGH; `obfuscated_sink` HIGH (computed eval; the `Function` constructor reached through `constructor.constructor`, `Function.prototype.constructor` or a function expression's `.constructor(`; `data:` imports; timers given a string or a decoded string; `vm`; Python `exec`/`pickle`/`marshal`/`__import__`); `exec_decode` HIGH; `decoder` INFO; `create_require` INFO; combos `exec_b64_literal`, `eval_decoder` | Deobfuscating anything beyond these shapes |
| `child_process` | `child_process` INFO, also a sink for `padding_sink`. Bracket members (`cp['exec'](…)`) count, and so does a module named in `require` / `import(…)` / `from` (`node:` prefix included), at the keyword rather than inside the quotes. `shell_eval` INFO | What each spawned command does |
| Env-var and keypair reads | `secret_read` HIGH / WARN (keypair, `.config/solana`, `.ssh`, `.aws/credentials`, `.netrc`, `.env*` except templates; a read call or a read command next to the path); `env_dump` INFO; `embedded_secret_key` INFO | Reading individual env-var names |
| Hardcoded URLs and IPs in source | `telemetry_post` HIGH / WARN (a POST carrying usage words or local data to an external host); `network_post` WARN / INFO; `ip_literal` WARN / INFO (public IPv4 destinations) | Judging whether each endpoint is the vendor's own |
| Pipe-to-shell installers | `download_and_run` HIGH / WARN (`curl … \| sh`, `sh -c "$(curl …)"`, `bash <(curl …)`, `iex (iwr …)`, eval of fetched content) | — |
| Install lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare` and the other install-time hooks) | `lifecycle_script` HIGH, at the key's line; every `package.json` script is scanned as shell code; combo `lifecycle_network`. A BOM is stripped first; a manifest that still does not parse gets `manifest_unparsed` WARN and each of its `"key": "value"` pairs is scanned as a script | What the script's own files do |
| Invisible and bidirectional Unicode | `unicode_bidi`, `unicode_invisible` WARN / INFO; `unicode_tag` WARN. Emoji joiners, script joiners and a leading BOM are ignored. | Trojan Source review of flagged lines |
| Symlinks (target, and whether it leaves the pack) | `symlink` INFO; combo `symlink_escape`. Links are never followed. | — |
| Executables (`find -perm -u+x`, naming each) | `executable` INFO for each file with an exec bit; shebang and exec-bit files are scanned as code | **What each executable does** |
| Every blob in full history | Not at SessionStart | **Manual**, or the hardened git reader planned for `verify add` (spec D7.3) |
| `hooks.json` | `harness_hooks` WARN (`hooks/`, `.claude-plugin/`, `.codex-plugin/`) | — |
| `.claude/settings.json` | `harness_settings` WARN; combo `harness_bypass` | — |
| `.mcp.json` | `mcp_config` INFO; `unpinned_npx` INFO for `@latest` / unpinned runners | Each connector's scope |
| A nested `.claude/skills/` | `nested_skills_dir` INFO | — |
| A root `CLAUDE.md`, `AGENTS.md` or `GEMINI.md` | `instruction_file` INFO; `prompt_injection` and `hidden_instruction` WARN anywhere | Reading the instructions |
| The pack's own `.gitmodules` | `gitmodules` INFO | Vetting the nested repositories |
| Author, provenance, license | — | **Manual** (the table in ai-kit's `skill-packs.md`) |

Beyond the checklist, the engine also covers:

* **Archives and executables in disguise:** `archive_masquerade` HIGH and `archive` INFO.
* **Shipped bytecode:** `bytecode` HIGH.
* **Package-manager and git tampering:** `registry_write` and `git_hooks_write` HIGH.
* **Load-time commands:** `bang_cmd` HIGH.
* **Model-facing text:**
  * the `SKILL.md` description (`description_url` WARN, combo `description_injection`);
  * a `SKILL.md` frontmatter that never closes or runs past 200 lines (`frontmatter_anomaly`
    HIGH; the description is still read to the end);
  * prompt-injection phrasing;
  * instruction-carrying HTML comments;
  * unscoped `Bash` grants (`broad_tools` INFO).
* **Unscanned tails:** `oversize_file`, HIGH for code past the 16 MiB scan cap.

Lockfiles (by exact name, see [What is read](#what-is-read)) without an exec bit or shebang are
dependency data. They are inventoried at `verify add|check` (spec D7.2), not text-scanned.
`build.rs`, proc-macro crates, `.cargo/config.toml`, `binding.gyp` and npm `hasInstallScript` are
build-time execution, reported at `verify add|check` (D7.2), not at SessionStart.

## Scan budget

SessionStart must stay fast, so a crafted pack cannot stall it:

* **Per rule.**
  * Only live hits count: code outside strings and comments. Quoted or commented hits never
    count, so they cannot be used to pad the cap.
  * After 50 live hits in one file (`rules::MAX_HITS_PER_RULE`), a rule stops creating findings
    there. Detection and combo signals carry on, so a payload after the cap still blocks.
  * `PackReport::capped` records each such rule, file and true hit count. An entry for a WARN
    or HIGH rule grades the pack at least HIGH; a capped INFO inventory rule (`decoder`,
    `child_process`, …) stays INFO.
  * Combo inputs are never dropped at a store limit. Each file keeps, per signal kind, the first
    line and a count (enough for the cross-file and pack-level combos). The line-local
    `padding_sink` is resolved from line bitsets, bounded by the file's line count and freed
    once the file is scanned, so flooding a file with thousands of sinks or padded lines hides
    nothing.
  * Stored findings stay capped at five per rule and severity.
* **Per pack and per sweep.** `rules::scan_pack_within` takes a `ScanBudget`: 2 s per pack, and
  4 s for every pack of one SessionStart sweep (`ScanBudget::session`, used by the verify
  sweep). The clock is checked between files, every 256 lines, statements or commands.
* **When the budget runs out.** The pack stops with `scan_budget_exceeded` HIGH: never clean,
  graded with the findings and combos found so far. A payload found before the cut still
  blocks.
* **In the SessionStart sweep.**
  * A cut pack is **unreviewed**: never pinned, and never recorded as scanned.
  * It is quarantined only for what was found before the cut, or for drift.
  * The session context lists it as "not fully scanned — rerun `safe-ai-skill verify check
    <dir>`" (`verify check` scans without a budget).
  * Once the sweep's budget is spent, nothing new is started. The remaining unpinned packs are
    **deferred** (not scanned, not pinned); the remaining pinned packs are listed **"drift not
    checked this session"**. Both keep their place at the front of the next sweep's queue.
    The pack in progress at the deadline may finish its drift check, up to one per-pack
    allowance, so a sweep never runs past its deadline plus one allowance, however many
    packs are pinned.
  * **Drift checks.** A pinned pack's shape is checked first, from metadata only: file count,
    total bytes and the sorted top-level names (`lockfile::shape_until`, stored in the pin). A
    changed shape is drift, so the pack is quarantined without a full hash, and a pack cannot
    dodge its drift check by growing past the hash budget. If the shape matches, the content
    hash decides. If that hash runs out of its per-pack allowance, the pin loses its clean
    status (`drift_unchecked` in the lockfile), the pack is listed "drift not checked this
    session", and it goes first in the next sweep. A high finding from the scan still
    quarantines it. Git-pinned ext submodules are compared by commit SHA and need no shape.
    Pins made before shapes existed get one at their next verified drift check.
  * **Age-ordered queue.** The lockfile counts sweeps (`sweep_session`) and records, per pack,
    the last sweep that worked on it (`sweep_marks`). Each sweep takes packs least recently
    worked on first: a pack never worked on goes first, then the oldest, in walk order within
    the same age (roots in order, skill directories and ext submodules sorted by name). A
    pack scanned or cut this session goes behind every pack that was not.
  * **Guarantee.** Each sweep starts its first pack with the full per-pack allowance (2 s is
    within the 4 s sweep). Each sweep moves every pack it worked on behind the rest, so a pack
    gains at least one place per session and reaches the front within N sessions, N being the
    number of packs (skill directories plus ext submodules) the sweep covers. So **a pack
    whose scan and hash each fit within the per-pack allowance on its own is fully scanned
    within N sessions**, however many budget-hungry packs share the sweep. The one exception
    is a pinned pack whose drift check overran. It jumps to the front once, and a second
    overrun in a row sends it back by age. With such packs present the bound is 2N sessions
    (each pack ahead can be worked on at most twice before it goes behind). Packs added
    between sessions are not counted; a new pack starts at the front.
    In practice most sessions cover more than one pack.
  * **Limit.** A pack that does not fit the per-pack allowance on its own is cut every time
    it reaches the front. It stays unreviewed (never pinned) until `safe-ai-skill verify check
    <dir>` scans it without a budget. A pinned pack whose hash never fits stays "drift not
    checked" and untrusted, and is retried by age like any cut pack.
  * The v1 shim reports a cut scan as incomplete rather than as a finding (the marker maps to
    High wherever it appears).

`tests/rules_perf.rs` replays the 23 performance probes from the round-2 review, at 16 MiB each in
release builds and 256 KiB in debug builds. Each must return within the pack budget plus 3 s of
slack (reading and splitting a 16 MiB file is not interruptible). A pack that was cut must grade
HIGH or worse.

## External scanners (spec D7.1)

| | safe-ai-skill | SkillSpector | Sentry skill-scanner | Cisco skill-scanner |
|---|---|---|---|---|
| Runs offline, no LLM | yes | only with `--no-llm` (still calls osv.dev) | yes | partly |
| Padding | yes, plus combo | yes | no | no |
| JS exec surface (`execSync`, `createRequire`, `Function(atob…)`) | yes | partial | partial | partial |
| Lifecycle (`prepare` included) | yes | partial | partial (omits `prepare`) | no |
| Symlinks | reported, never followed | silently skipped | crashes on a loop | yes |
| Harness config | yes | yes | partial | ? |
| Docs vs code grading | yes | no | no | no |

SkillSpector `--no-llm` is suggested as an advisory SARIF job in ai-kit CI when pins are bumped. Its
rule ideas were reimplemented here; no rule lists were copied.

## Acceptance corpus

`crates/engine/tests/rules_corpus.rs`:

* **Shapes** (always run): the four Trail of Bits skills re-synthesised (csv-summarizer vertical padding plus env dump,
  context-loader docx masquerade, simple-formatter `.pyc`, dev-env-setup registry overwrite), the
  issue #10 stealer, the scanner-research demo pack, harness bypass and bang exfil all **BLOCK**.
  Google's `exec(base64.b64decode('{encoded_script}'))` (built as a string) is **WARN**. Fixtures
  are inert: payloads decode to a `console.log`, and hosts are `example.invalid`.
* **Evasions** (always run, `tests/rules_evasion.rs`): 47 tests covering every probe of the two
  WS-D2 reviews, each with the verdict it must have. They cover:
  * interpolations, including frames, f-strings and depth carried across lines;
  * regex literals and division, line terminators, shell quoting;
  * NUL bytes, BOMs, plausible and forged UTF-16/32;
  * lockfile and `.git` scope, split payloads in `build/`;
  * `package.json` BOM, hooks and parse failures, escaped settings;
  * frontmatter forms, description URLs;
  * indirect and fenced bangs, symlink chains;
  * indirect sinks (`Function` constructors, decoded timers, `child_process` spellings).
* **Performance** (always run, `tests/rules_perf.rs`): see [Scan budget](#scan-budget).
* **ai-kit** (opt-in): the 46 packs at the commit pinned in `aikit.manifest.tsv` give **0 BLOCK and
  13 HIGH** (limit 14), each HIGH a true behaviour, and every pack matches its expected grade. Run it with:

  ```bash
  SAFE_AI_SKILL_CORPUS=1 cargo test --release --test rules_corpus -- --nocapture
  # add SAFE_AI_SKILL_CORPUS_DIR=<ai-kit checkout> to reuse a clone,
  # and SAFE_AI_SKILL_CORPUS_VERBOSE=1 to list every combo, HIGH and WARN finding.
  ```

  Release builds also assert that the scan stays under 5 s, taking the faster of two passes so
  that a cold page cache (a fresh clone, or a rebuild that evicted it) does not count. The scan
  covers 106 MB of text across 13.5k files.

  Timing depends on machine load; record the load average with any number.
  * About 2.5 s warm, against 2.3 s for the pre-lexer engine, interleaved on a quiet machine
    (load average ~11, before the round-2 fixes).
  * After the round-2 fixes: 3.5–3.6 s against 3.0–3.2 s, interleaved at load average 33–39,
    about 10% more CPU per pass.

  At load average 20 and above, the same binaries vary two- to threefold from run to run. At
  50–200, the 5 s assertion fails for both engines.

## Known limits

* **Obfuscation beyond the listed shapes.** Rule-based recall is low by nature: Cisco's
  benchmark puts rules-only recall at about 8% at HIGH. The runtime gates remain the backstop.
* **Unpaired fragments.** A payload split so that no sink and decoder or padding ever meet in
  hand-written code grades HIGH at most.
* **Lexing is approximate per language family.** Shell heredocs, Ruby and Perl quoting, and Rust
  raw strings are approximated. JS regex literals are told from division by the token before
  the `/`.
* **Bundle exemption.** A file can pose as a bundle (bundler helper names, a minified shape) to
  stay out of the cross-file `eval_decoder` rule. It still grades HIGH for its own `eval`, and
  in-statement combos still apply.
* **Budget cut-offs.** A pack cut by the time budget is graded on what was scanned before the
  cut: HIGH at least, BLOCK if a payload was already found. At SessionStart it stays unreviewed
  until `verify check` scans it in full.
* **Hit-cap escalation.** A WARN or HIGH rule with more than 50 live hits in one file makes the
  pack HIGH. None of the ai-kit packs reaches the cap. Capped INFO rules do not escalate.
* **Packs that never fit the budget.** A pack too large to scan within the per-pack allowance
  stays unreviewed every session, retried whenever it is the oldest in the queue, until
  `verify check` scans it in full. A pinned pack with an unchanged shape whose hash never fits
  stays "drift not checked" (its pin is untrusted): it goes to the front after its first
  overrun, then rotates by age.
* **Shape fingerprint.** An edit that keeps the file count, the total bytes and the top-level
  names is caught only by the content hash, not by the shape.
* **Indirect load-time commands.** A `` !`cmd` `` is followed into a pack script one level deep,
  and only when the script is named directly (an interpreter and a path, or a path).
* **Descriptions.** Only `SKILL.md` frontmatter is checked, not the frontmatter of agent or
  command files.
* **Unknown endpoint variables.** An unresolved variable named like an endpoint (`$RPC_URL`) is
  treated as user-configured.
* **History.** Full-history and docs-only-commit checks (D7.3) are not implemented at
  SessionStart.
