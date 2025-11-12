# Modern Deployment Playbook

The shared-hosting workflow ships a hardened build to `https://lab.minischetti.org/passless`, and Passless also embraces modern cloud tooling. Use these blueprints to demonstrate container fluency alongside FTP resilience.

## GitHub Actions Setup
1. Navigate to **Settings → Secrets and variables → Actions** in your GitHub repository.
2. Add the following repository secrets:
   - `FTP_SERVER` – FTPS hostname (e.g., `ftp.example.com`)
   - `FTP_USER` – Username for the FTPS account
   - `FTP_PASS` – Password or app-specific token
3. Push to the `main` branch. The workflow at `.github/workflows/deploy.yml` will:
   - Validate PHP syntax
   - Run PHPStan analysis
   - Execute the custom test suite
   - Deploy the contents of `htdocs/` to your server over FTPS

> **Tip:** If your host supports SFTP, set `protocol: sftp` in the workflow for stronger transport security.

## Docker Compose (Local & Production Pods)
```bash
docker compose up --build
```
- Serves HTTPS at `https://localhost:8443` via Caddy with a self-signed cert.
- Mailpit captures outbound email at `http://localhost:8025`.
- MySQL credentials live in `.env`; the compose stack uses them automatically.
- Convert the compose file to a production pod on services like DigitalOcean or Render by setting `APP_ENV=production` and swapping Mailpit for SendGrid.

## Fly.io
1. Install the Fly CLI and log in: `fly auth login`.
2. Create `fly.toml` (excerpt):
   ```toml
   app = "passless-demo"

   [build]
     builder = "paketobuildpacks/builder:base"

   [env]
     APP_ENV = "production"
     APP_URL = "https://<your-app>.fly.dev"

   [[services]]
     internal_port = 8080
     protocol = "tcp"
     [services.concurrency]
       hard_limit = 25
       soft_limit = 20
     [[services.ports]]
       handlers = ["http"]
       port = 80
     [[services.ports]]
       handlers = ["tls", "http"]
       port = 443
   ```
3. Run `fly launch --copy-config` and attach a managed MySQL database.
4. Set secrets: `fly secrets set DB_HOST=... DB_NAME=... DB_USER=... DB_PASS=... MAIL_PROVIDER=...`.
5. Deploy: `fly deploy`. Health checks hit `/` and `/auth/request.php`.

## Railway
1. Create a new project and add a MySQL plugin.
2. Add a service from GitHub and enable “Deploy from Dockerfile”. Railway builds from `docker-compose.yml` (first service) automatically.
3. Map plugin variables to Passless:
   - `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`
   - `APP_URL=https://<your-subdomain>.up.railway.app`
   - `APP_ENV=production`
   - Email credentials via Railway variables
4. Set the start command to `php -S 0.0.0.0:8080 -t htdocs`.
5. Add a health check pointing at `/auth/request.php`.

## DigitalOcean App Platform
1. Create an app, link this repository, and choose “PHP” as the runtime.
2. Set build command to `composer install --no-dev` (noop but required), run command to `php -S 0.0.0.0:8080 -t htdocs`.
3. Attach a managed MySQL database or supply external credentials.
4. Add environment variables for `APP_ENV`, `APP_URL`, `DB_*`, and `MAIL_*`.
5. Configure an automatic deployment on `main` to mirror the GitHub workflow.

## Observability Hooks
- Forward structured logs to a collector (Datadog, Grafana Loki, ELK).
- Ship security events via webhook by extending `htdocs/lib/Support/SecurityEventLogger.php`.
- Add application metrics or traces if your platform supports Prometheus or OpenTelemetry sidecars.

## Scaling Tips
- Horizontal scaling requires sticky sessions or migrating session storage to Redis; Passless already stores sessions in MySQL, so most platforms just need shared database access.
- Increase `MAGIC_LINK_TTL` and rate-limit windows in multi-region deployments to account for email latency.
- Move cleanup tasks (cron or container jobs) to platform-native schedulers to keep tables lean.
