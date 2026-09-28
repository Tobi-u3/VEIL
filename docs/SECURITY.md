# Analyst authentication

This prototype has one locally provisioned operator account. Run `.venv/bin/python scripts/create_user.py` interactively before starting. It writes only a salted scrypt hash (N=131072, r=8, p=1) and username; no plaintext password. Account files are created atomically with mode 0600. The script can replace the account; restart the backend immediately afterward to invalidate every previous session.

Session tokens have 256 bits of randomness, are held in HttpOnly / SameSite=Strict cookies, and are hashed in the server's in-memory session map. CSRF tokens are kept in frontend memory. Each state-changing request checks the exact browser origin and the session's CSRF token; login checks origin. Data routes and WebSocket require a session. Expiry is checked on each WebSocket emission; logout revokes that token. Auth polling does not extend idle sessions. Server restart signs everyone out. A maximum of 32 sessions is retained.

Maximum session age: 8 hours; inactivity: 30 minutes without authenticated data/control HTTP requests. Viewing only the live WebSocket does not extend this idle timeout. Login permits ten attempts in a 15-minute window per peer and globally for this single account; this limits guessing but may temporarily deny the analyst access after hostile attempts. Password hashing is serialized and run outside the ingest event loop. Run one Uvicorn worker: session and throttle state are process-local and reset on restart.

## Local demo

`scripts/start.sh` binds only 127.0.0.1. HTTP cookies are allowed only with a loopback public origin for the local demo. No public registration, reset endpoint, hardcoded account or authentication bypass exists. Missing account configuration fails closed. Credentials, databases and .env files are excluded from the distributed ZIP.

## Remote analyst access

Remote analyst access is separate from passive packet ingest. Set `VEIL_PUBLIC_ORIGIN=https://your-console.example` and terminate TLS using a properly configured reverse proxy forwarding to 127.0.0.1:8000 with the original Host header. This enables Secure cookies and HSTS, accepts only that origin and host, and supports same-origin WSS. An HTTP remote origin is rejected at startup. Never expose the raw HTTP backend. Configure TLS certificates and proxy access policies yourself; remote deployment was not tested here. The sensor still must not have a path to send into the monitored production network.

No MFA, role separation, enterprise identity provider, audit-grade access log or external security review is claimed. The account file and host OS require access protection. For production, replace process-local sessions/throttling with shared storage, add MFA and operational security controls, and perform a security review. This prototype does not turn software into a hardware data diode.

References: OWASP Password Storage, Session Management and CSRF Prevention Cheat Sheets:
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
