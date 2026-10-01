# Security policy

## Supported scope

v0.1 is a local detection/triage prototype. It must remain in shadow mode. There is no automatic firewall, host isolation, scanning, or attack capability.

## Reporting

Do not put secrets or live user data into issue reports. Report suspected vulnerabilities privately to the repository maintainer with the affected version, reproduction using localhost/synthetic data, and impact. Remove credentials from logs before sharing.

## Operational guidance

- Keep the API bound to loopback or place it behind an authenticated reverse proxy. v0.1 does not implement user authentication or CSRF protection.
- Restrict SQLite file permissions and use encrypted storage where required.
- Do not expose local-jev or this dashboard to untrusted networks.
- Keep model downloads and Python dependencies patched.
- Treat model output as a triage signal requiring human review.
