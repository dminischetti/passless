# Passless Installation Guide

Passless is a framework-free magic-link authentication system built in pure PHP 8. This guide explains how to configure the environment, deploy to different targets, and demo the security features with confidence.

## PHP Requirements
Enable the following PHP extensions:

- `pdo_mysql`
- `pdo_sqlite` (optional, used by the bundled test suite)
- `openssl`
- `mbstring`
- `curl`
- `json`
- `session`

Ensure `allow_url_fopen` is enabled and that `session.save_handler` can be overridden.

## Database Setup
1. Create an empty MySQL database and user. Grant the user `SELECT`, `INSERT`, `UPDATE`, and `DELETE` privileges.
2. Import the schema from `htdocs/database/install.sql`:
   ```bash
   mysql -u <user> -p <database> < htdocs/database/install.sql
   ```
3. Verify that the following tables exist: `users`, `login_tokens`, `sessions`, `rate_limits`, `audit_logs`, `security_events`, and `geo_cache`.

## Environment Configuration
1. Copy `.env.example` to `.env` in the project root.
2. Update the core values:
   - `APP_URL`: Public HTTPS URL of the site (set to `https://lab.minischetti.org/passless` for the hosted demo).
   - `APP_ENV`: Use `production` when running on real infrastructure.
   - `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`: Database connection credentials.
   - `MAIL_PROVIDER`, `MAIL_FROM`, `SENDGRID_API_KEY` *or* the `MAILGUN_*` trio: Outbound email settings.
3. Leave every other variable commented out unless you need to override defaults. Useful overrides include session lifetimes, rate limits, CAPTCHA thresholds, account-lock policies, optional GeoIP lookups, and `ADMIN_EMAIL`.
4. Configure your hosting document root to point at the `htdocs/` directory so that only web entrypoints are exposed. If you cannot change the document root, upload the contents of `htdocs/` into the served directory and keep the rest of the project outside of web scope.

## Email Delivery
Passless supports SendGrid and Mailgun APIs:

- **SendGrid**: set `MAIL_PROVIDER=sendgrid`, provide `SENDGRID_API_KEY`, and configure `MAIL_FROM`.
- **Mailgun**: set `MAIL_PROVIDER=mailgun`, provide `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, and `MAIL_FROM`.

During development you can disable outbound email by setting `MAIL_ENABLED=0`. In that mode the magic link appears on the landing page for quick demos.

## Session Storage
Sessions are stored in the `sessions` table using a custom handler. Cookies are issued with `Secure`, `HttpOnly`, and `SameSite=Lax` attributes. Each session tracks the owner, sliding expiration, optional absolute expiration, and revocation timestamp. Users can review and revoke active sessions from `/app.php`.

## Rate Limiting & Abuse Defenses
Rate limiting protects the magic-link workflow using a single atomic `INSERT ... ON DUPLICATE KEY UPDATE` query (with SQLite-compatible fallbacks for tests). Limits are tracked in the `rate_limits` table for email addresses, IP addresses, combined email+IP pairs, and verification attempts. When a limit triggers, Passless reports the retry time derived from the stored expiration timestamp.

Additional safeguards:
- CAPTCHA challenges after repeated request attempts.
- Fingerprint-bound magic links requiring the same IP and user agent.
- Automatic account lockouts with audit events after successive verification failures.
- Immutable audit logs (`audit_logs`) and security events (`security_events`) for forensic review.
- Optional GeoIP lookups (`GEOIP_ENABLED=1`) that alert when a sign-in originates from a new country.

## Admin & Audit Console
The authenticated dashboard (`/app.php`) shows devices, recent security events, and audit history. Users flagged via `ADMIN_EMAIL` gain access to `/admin.php`, which summarises recent audit entries, suspicious events, aggregated counts, and export links for SIEM ingestion. A storyboard of the console lives in `docs/images/admin-dashboard.svg` for easy sharing.

## Deployment
- **Shared hosting / FTP**: Configure FTPS credentials as GitHub secrets (`FTP_SERVER`, `FTP_USER`, `FTP_PASS`, `FTP_SERVER_DIR`) and push to `main`. The workflow at `.github/workflows/deploy.yml` lints, tests, packages, and deploys the project to `https://lab.minischetti.org/passless`.
- **Docker Compose**: `docker compose up --build` starts PHP, MySQL, and Mailpit locally. Override configuration via `.env` or environment variables.
- **Fly.io**: Use the reference manifest in `docs/DEPLOYMENT.md` to deploy a stateless PHP app container with managed MySQL services.
- **Railway**: Provision the repo as a service, attach a MySQL plugin, and deploy using the Docker configuration referenced in `docs/DEPLOYMENT.md`.
- **DigitalOcean App Platform**: Point to the GitHub repository, choose “PHP” as the buildpack, set the run command to `php -S 0.0.0.0:8080 -t htdocs`, and supply the same environment variables.

## Maintenance Tasks
- Run `php htdocs/deploy/cleanup.php` on a schedule to delete expired sessions, consumed tokens, and stale rate-limit entries.
- Execute `php tools/load_test.php` to capture benchmark numbers.
- Tail JSON logs from your configured PHP error log for operational insight.

## Local Development & Tests
- Run the entire test suite (TokenService, RateLimiter, CSRF, and integration flows) with:
  ```bash
  php tests/run.php
  ```
- Run static analysis locally by downloading PHPStan and executing:
  ```bash
  curl -sSL https://github.com/phpstan/phpstan/releases/latest/download/phpstan.phar -o phpstan.phar
  php phpstan.phar analyse --configuration=phpstan.neon
  ```
- The Docker environment spins up PHP 8.2 with Apache and MySQL 8:
  ```bash
  docker compose up -d
  ```
  The app becomes available at `https://localhost:8443`, and Mailpit for email previews is at `http://localhost:8025`.

## Next Steps
Consult `docs/DEPLOYMENT.md` for cloud deployment blueprints, and `docs/THREAT_MODEL.md` for the attack matrix covered by Passless.
