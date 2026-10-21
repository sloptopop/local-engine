# sloptopop local — architecture

`sloptopop local` (crate and binary `sloptopop-local`, MIT OR Apache-2.0)
is the open-source half of sloptopop on the user's machine (decision
D-0183). Everything proprietary — the Detector, business-logic, the
Architect, the Implementor and the Guider — runs only in the server
`sloptopop-engine`. This crate never detects, plans, lowers or verifies:
it moves files to the server, and applies what the server verified.

```text
 user's machine (open source)                                   server (sloptopop-engine)
 sloptopop collect ── .sloptopop/reports/*.sarif|lcov, .collect.json
 sloptopop-local request ── masked snapshot + reports ── request.json ──HTTPS──►  backstop, detect,
                                                          response.json ◄──────   plan, verify
 sloptopop-local report   (check: the server's Report)
 sloptopop-local apply    (fix, transform: commits on a new branch)
 sloptopop-local evidence (the project's own checks) ── evidence-request.json ──►  the Guider's verdict
```

The CLI makes the HTTPS call (decision D-0008, open: either side could;
the request and the response are plain files in the run directory).

## The four tasks (D-0183)

1. **Analyzers.** `sloptopop collect` (today in the CLI; it moves here
   once the containerized catalogue lands) runs the open-source analyzers
   from pinned component images and writes SARIF/LCOV to
   `.sloptopop/reports/`, with its run record `.collect.json`.
2. **Snapshot** (`run::request`). The repository must be clean at its top
   level. The snapshot is the base commit's tree from git's object store
   (`snapshot`: UTF-8 text only; no links, submodules, dependency or build
   directories, `.sloptopop/`, real `.env*` files or files over 1 MiB;
   each exclusion with its reason). Masking (`scanner`, `sarif`, `mask`):
   the gitleaks report must be usable (the record says gitleaks ran and
   exited 0; it is a gitleaks SARIF log whose every result names a file
   and a line; it is no older than `HEAD`'s commit or any file of the
   snapshot), or nothing is uploaded. Every result in any file of the
   snapshot is masked on every line it spans (same-length `x`s,
   documented provider prefixes kept, every token of a PEM private-key
   block), and a reported span no line rule covered gets its longest token
   masked. The reports go along without their code snippets (`reports`).
   The request (schema 2: mode, base, name, files, reports, record,
   context) is written as canonical JSON with its manifest (`upload`).
3. **Applying** (`run::apply`, `apply`; written fresh, D-0183/O-A). The
   response must answer this request (its digest) on the same `HEAD`.
   For each delivery in order: manual steps are listed; a step whose
   attestations are not recorded locally by a person of the right role
   (`records`, `.sloptopop/context.json` owners) is pending; for each
   change, the file's current masked bytes must have the `before` digest
   (a new file must not exist), the spans (byte offsets of the uploaded
   base; a step's file is the base with every earlier step's spans and its
   own) must give the `after` digest, the file must be one the server saw,
   and the real secret values are put back (`mask::restore`; the masks are
   found again by comparing the real and the uploaded file, so no list of
   secrets is ever stored). The first step not delivered blocks the
   automated steps above it. With `--apply` each delivered step is one
   commit made with git plumbing in a private index, dated as the base, by
   `sloptopop`; the branch (`sloptopop/transform-<run>` or `--branch`) is
   created only if it does not exist. `summary` writes `report.json`,
   `SUMMARY.md` and `PR.md`.
4. **Evidence** (`run::evidence`, `evidence`). The checks come from
   `.sloptopop/checks.json` or what the project declares (`package.json`
   scripts, Cargo, Go); each runs on the base and on the branch head in a
   temporary detached worktree with the root's dependency directories
   linked in, under a time limit. Only exit codes, durations, output
   lengths and digests are sent.

## Module layers

Each module imports only from lower layers (see `src/lib.rs`).

| Layer | Module | Secret | Standards |
|---|---|---|---|
| 0 | `tool`, `error`, `output`, `command` | identity, errors, streams, the command line | SCF TDA-08, TDA-12, TDA-12.1 |
| 0 | `canonical` | deterministic JSON | SCF TDA-06.5; OWASP ASVS 5.0 V1.2 |
| 0 | `digest` | request and whole-file digests, run ids | SCF TDA-20.3; NIST SSDF PS.2.1 |
| 0 | `git` | running git safely (argument vectors, no hooks, no prompts) | SCF CHG-03, TDA-12.1; OWASP ASVS 5.0 V1.2.5; CWE-78 |
| 0 | `mask` | masking, covering reported spans, finding masks again, restoring | OWASP ASVS 5.0 V13.3.1, V14.2.4; SCF IAC-14, PRI-05; CWE-200 |
| 0 | `wire` | what is read of the server's response | SCF TDA-12 |
| 1 | `snapshot` | the files of a commit and what is left out | SCF PRI-05, AST-04; OWASP ASVS 5.0 V13.3.1 |
| 1 | `sarif` | the secret scanner's results | OASIS SARIF 2.1.0 §3.27, §3.30; SCF TDA-12 |
| 1 | `reports` | the analyzer reports uploaded, without snippets | SCF PRI-05; OWASP ASVS 5.0 V13.3.1 |
| 1 | `records` | confirmations by role, kept locally | SCF CHG-04, IAC-08; ISO/IEC 27001:2022 A.8.32; OWASP ASVS 5.0 V16.3.4 |
| 1 | `evidence` | the project's own checks on base and head | SCF CHG-07, TDA-09; NIST SSDF PW.8.2 |
| 2 | `scanner` | whether the scanner's report is usable; what to mask | OWASP ASVS 5.0 V13.3.1; SCF IAC-14, PRI-05; GDPR Art. 25 |
| 2 | `apply` | the digest-checked applier and its commits | SCF CHG-03, CHG-04, CHG-07; ISO/IEC 27001:2022 A.8.32; CWE-59 |
| 3 | `upload` | the request and the manifest | SCF PRI-05, PRI-02; GDPR Art. 25 |
| 3 | `summary` | `report.json`, `SUMMARY.md`, `PR.md` | SCF CHG-02, CPL-30 |
| 4 | `run` | the commands | SCF CHG-03, CHG-04, TDA-20.3 |
| 5 | `cli`, `main.rs` | the command line and exit codes | SCF TDA-12, TDA-12.1 |

## Boundaries

- No sloptopop proprietary crate is ever a dependency
  (`tests/open-source-only.rs` reads the whole `cargo tree`).
- Dependencies: `serde`, `serde_json`, `blake3` (permissive licences;
  `deny.toml`).
- Synchronous `std` only: no network code, no TLS stack, no async runtime.
- Deterministic: the same repository and reports give byte-identical
  requests; commits carry the base commit's date.
