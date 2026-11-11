# Security Policy

## Project status and supported versions

SafeEvidence is a **pre-release, governance-gated research workspace project**.
Its currently qualified G01a implementation is **synthetic-only engineering
infrastructure**, not a clinical application. No production versions are
released or supported. There is no patient-data handling, medical validation,
external source admission, or authorized clinical deployment.

The public code and its CI are not an endorsement of medical or security
fitness. Independent technical/security review is still pending.

## Report a suspected vulnerability privately

Use the repository's **GitHub private vulnerability reporting** workflow:

1. Open [SafeEvidence's Security page](https://github.com/TheHalfMoon/SafeEvidence/security).
2. Choose **Report a vulnerability** and submit the private report.
3. Include the exact Git commit, affected files, a minimal reproduction using
   **synthetic, non-sensitive input only**, impact, and any safe mitigation.

Private vulnerability reporting is enabled for this public repository. Do
**not** post exploit details or confidential information in public issues,
pull requests, discussions, or review recruitment comments.

Do not include patient information, secrets, credentials, private documents,
third-party restricted content, or data taken from systems you do not control.
Do not attempt network attacks, tests against other users, production service
probing, or invasive testing without separately documented authorization.
Public code may be assessed offline using isolated synthetic fixtures.

If you cannot access the private reporting form, open a **public issue asking
only for an alternate private contact channel**; omit technical vulnerability
details. Do not assume an unverified email address is monitored.

## Handling and disclosure

Maintainers will evaluate reports against the exact affected revision and
coordinate any response or disclosure with reporters as appropriate to the
verified risk. No response-time guarantee, bug bounty, paid audit engagement,
or blanket testing authorization is offered.

Changes require ordinary signed/DCO commits, exact-head protected CI and the
repository's mandatory approving PR review. An automated review or passing CI
does not replace independent human security acceptance.

## Independent review is a separate governance decision

Qualified independent reviewers may express interest in
[Issue #17](https://github.com/TheHalfMoon/SafeEvidence/issues/17), without
including sensitive findings. Review eligibility, independence, authority,
and acceptance must be verified and recorded; volunteering or submitting a
vulnerability report alone does not grant review authority.

Full P01 product entry, clinical intended-use/evaluation, source rights,
evidence-pack trust, and release remain **blocked** under
[Issue #3](https://github.com/TheHalfMoon/SafeEvidence/issues/3),
[Issue #4](https://github.com/TheHalfMoon/SafeEvidence/issues/4), and
[Issue #5](https://github.com/TheHalfMoon/SafeEvidence/issues/5).
