# Security policy

JevSec is a local, shadow-mode security decision engine. It never blocks traffic, changes firewall state, isolates hosts, or scans destinations.

## Network exposure

`security-engine serve` defaults to `127.0.0.1`, where development mode does not require login. Any non-loopback bind, including `0.0.0.0`, requires `SDE_AUTH_USERNAME` and `SDE_AUTH_PASSWORD`; the API challenges with HTTP Basic authentication. Basic authentication is not encrypted by HTTP, so place any externally reachable service behind TLS and a trusted reverse proxy. The Compose service publishes only on host loopback and still requires credentials inside the container.

## Reporting

Do not put secrets or live user data in reports. Contact the maintainer with the affected version and a localhost/synthetic reproduction. Avoid attaching raw logs. Remove credentials from all reproduction material.

## Operations

- Restrict SQLite permissions and apply filesystem encryption/retention appropriate to your environment.
- Do not expose local-jev without network controls.
- Treat model outputs as advisory. Humans review uncertain and high-impact decisions.
- Verify provider endpoint and model before importing sensitive logs.
- Shadow mode is read-only with respect to traffic enforcement; Nginx log input can still contain personal data and must be handled accordingly.
