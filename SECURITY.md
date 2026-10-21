# Security policy

## Reporting a vulnerability

Please report security problems privately. Do not open a public issue,
discussion or pull request for them.

Use GitHub private vulnerability reporting: open the **Security** tab of
this repository and choose **Report a vulnerability**.

Please include:

- the affected version (`sloptopop-local version`);
- the steps to reproduce, ideally with a small synthetic repository;
- the impact you expect.

Do not include real credentials, customer code or other people's personal
data in a report.

## Scope

This policy covers `sloptopop-local`: building the masked snapshot from
the secret scanner's report, applying the changes the sloptopop server
verified, and running the project's own checks as evidence. Reports about
the sloptopop server (`sloptopop-engine`, hosted or self-hosted) are
welcome here too.

A secret value that reaches an upload unmasked is in scope, whichever
file it is in.

## What happens next

- We acknowledge a report within 5 working days and keep you informed
  until it is resolved.
- We fix confirmed vulnerabilities in the latest release and publish a
  GitHub security advisory. We credit you, unless you prefer otherwise.
- Please keep the details private until a fix is released, or for at most
  90 days from your report.

## Supported versions

sloptopop-local is before version 1.0. Only the latest release receives
security fixes.
