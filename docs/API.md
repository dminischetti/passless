# Security Services API Reference

The following modules power Passless' security model. Each API is intentionally small so you can discuss implementation details confidently during interviews or stakeholder reviews.

## `Passless\Security\TokenService`
- `createForUser(int $userId, string $email, string $ip, string $userAgent): MagicLink`
  - Generates selector/token pairs using `random_bytes()` and stores hashed tokens plus fingerprint hash.
  - Emits audit log `magic_link.created` and returns a `MagicLink` DTO.
- `verify(string $selector, string $token, string $ip, string $userAgent): TokenVerificationResult`
  - Wraps lookup and updates in a transaction with `SELECT ... FOR UPDATE` on MySQL.
  - Applies fingerprint and token comparison, emits security events for every failure path, and consumes the token on success.

## `Passless\Security\RateLimiter`
- `hit(string $scope, string $identifier, int $limit, int $decaySeconds): RateLimitResult`
  - Uses atomic upsert queries compatible with MySQL and SQLite.
  - Returns the current count and retry timestamp while tracking combined scopes (email, IP, email+IP).
- `clear(string $scope, string $identifier): void`
  - Removes the rate-limit bucket, typically after successful verification.

## `Passless\Security\Csrf`
- `token(): string`
  - Lazily creates a CSRF token stored in the session payload.
- `validate(?string $token): bool`
  - Compares against the stored token using `hash_equals` and rotates on successful validation.
- `rotate(): void`
  - Regenerates the CSRF token, invoked after login/logout to avoid fixation.

## `Passless\Security\SessionAuth`
- `logIn(int $userId, string $email): void`
  - Regenerates the session ID, revokes the previous session, and stores issued-at metadata.
- `logOut(): void`
  - Revokes the current session and rotates CSRF token.
- `activeSessions(): array`
  - Lists non-revoked sessions for the signed-in user for device management.
- `revokeSession(string $sessionId): bool`
  - Marks a session as revoked and terminates it if it matches the current ID.

## `Passless\Security\DatabaseSessionHandler`
- Implements `SessionHandlerInterface` with sliding expiration, absolute lifetime, and refresh interval control.
- Records session metadata (IP, user agent) for device awareness.
- Garbage collection removes expired or revoked rows in a single query.

For usage examples explore `htdocs/auth/request.php`, `htdocs/auth/verify.php`, and the integration tests in `tests/AuthFlowTest.php`.
