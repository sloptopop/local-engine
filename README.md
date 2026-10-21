# sloptopop local

`sloptopop local` is the open-source part of [sloptopop](https://sloptopop.dev)
that runs on your machine. It holds no detection logic of its own: the
sloptopop server (`sloptopop-engine`, hosted or self-hosted) detects,
plans and verifies. `sloptopop local` only:

1. **builds the snapshot** the server analyses: the files of your `HEAD`
   commit, minus what must not leave your machine (real `.env*` files,
   dependency and build directories, binary and large files, links), with
   **every secret value your secret scanner reports masked**, and the
   reports of the open-source analyzers `sloptopop collect` ran. It shows
   you a manifest first, and refuses to build a snapshot without a usable
   gitleaks report: it never uploads unmasked;
2. **applies the changes the server verified** as one commit per step on a
   new branch, checking every byte span against the server's whole-file
   digests, putting your real secret values back, and refusing on a dirty
   tree, a moved `HEAD` or any mismatch. Your checkout, its index and
   `HEAD` are never touched;
3. **runs your project's own type check, build and tests** on the base
   and on the new branch, and sends only their exit codes, durations and
   output digests to the server as evidence.

The open-source `sloptopop` CLI starts the `sloptopop-local` binary and
makes the one call to the server; see the CLI's documentation for
`sloptopop check`, `fix` and `transform`.

```text
sloptopop-local request <root> --mode check|fix|transform
sloptopop-local report <root> --run <id>
sloptopop-local apply <root> --run <id> [--apply] [--branch <name>] [--confirm <id,...> --by <name>]
sloptopop-local evidence <root> --run <id>
sloptopop-local version
```

How it works, module by module, is in [ARCHITECTURE.md](ARCHITECTURE.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party components and their licences are listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
