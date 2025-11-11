# Passless Threat Model

The table below maps common attack scenarios to their mitigations so reviewers can validate coverage quickly.

| Threat | Mitigation |
| --- | --- |
| Magic-link interception | Tokens hashed at rest, single use, fingerprinted to IP + user agent, short TTL, and consumed immediately. |
| Credential stuffing | Passwordless design eliminates stored passwords and rate limits limit token requests per email, IP, and combination. |
| Brute-force token guessing | Rate limiting, verification throttling, jittered responses, and CAPTCHA escalation slow automated attacks. |
| Replay of stolen links | Fingerprint hash comparison, GeoIP anomaly detection, and immutable audit logging surface suspicious reuse attempts. |
| Session fixation | Sessions stored in MySQL, rotated on login, with Secure/HttpOnly/SameSite cookies and sliding expiration. |
| CSRF on sensitive actions | All POST endpoints enforce CSRF tokens stored alongside the DB session. |
| Enumeration of valid emails | Uniform error responses, randomized delays, and combined email/IP rate limits reduce signal leakage. |
| Denial of service via rate-limit flooding | Atomic `INSERT ... ON DUPLICATE KEY UPDATE` keeps rate-limit writes efficient; cleanup script purges stale data. |
| Compromised mailbox | Automatic account lockout notifications, security alert emails, and admin console visibility expose abuse quickly. |
| Insider tampering | Audit logs and security events are append-only with timestamps for forensic reconstruction. |

Review `docs/ARCHITECTURE.md` for implementation details and `docs/API.md` for service-level documentation.
