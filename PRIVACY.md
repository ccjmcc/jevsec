# Privacy

Local mode stores normalized events and assessment data in a local SQLite database. The provider receives aggregate numeric/boolean features only; raw user-agent, referer, path samples, passwords, cookies, Authorization values, API keys and secrets are not sent to Jev. Input schemas ignore unknown keys. Query/fragment text is removed from paths, referers are reduced to scheme and host, and supplied session/request identifiers are one-way pseudonymized at ingestion.

The local-jev model weights download from Hugging Face during setup. Inference requests are sent to the configured local endpoint. The engine has no telemetry or external API client. Backups, logs, retention and disk encryption remain operator responsibilities.
