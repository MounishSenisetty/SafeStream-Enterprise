# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: on this repository, go to **Security → Report a
vulnerability**. Include the version, the configuration that matters (delivery mode, redaction
mode, field rules), and the smallest input that shows the problem. Use synthetic data: never
send real personal data or credentials in a report.

A record that reaches the clean topic with sensitive data still in it is a security issue,
not an ordinary bug, and is handled as one.

You can expect an acknowledgement within 3 working days, and a fix or a mitigation plan for a
confirmed issue within 30 days.

## Supported versions

Security fixes are made on the latest release. Deployments should pin a version and move to
each new release.

## Verifying what you run

Release images are signed and carry an SBOM and build provenance. See
[Verifying a release](README.md#verifying-a-release).
