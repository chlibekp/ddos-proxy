# DDoS Protection Proxy

A high-performance Go reverse proxy designed to protect backend services from DDoS attacks. It features global rate limiting, connection limiting, and Cloudflare Turnstile challenges to mitigate automated attacks.

## Features

- **Global Rate Limiting**: Triggers mitigation mode when request rate exceeds a threshold.
- **Connection Limiting**: Triggers mitigation mode when new connection rate exceeds a threshold.
- **Cloudflare Turnstile**: Challenges users with a CAPTCHA when mitigation mode is active.
- **JWT Authentication**: Validated users receive a signed JWT to bypass challenges for a configurable duration.
- **Sticky Mitigation**: Mitigation mode stays active for a set duration after the attack subsides.
- **Always-On Mode**: Option to permanently enable the challenge for all requests.
- **Aggressive Blocking**: IPs that fail to solve the challenge and continue sending requests are blocked and their connections are closed.

## Configuration

The proxy is configured via environment variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PROXY_BACKEND_URL` | **Required** | The full URL of the backend service (e.g., `http://localhost:3000`). |
| `PORT` | `8080` | The port the proxy listens on. |
| `PROXY_MAX_REQ` | `300` | Max global requests per second before triggering mitigation. |
| `PROXY_MAX_CONN` | `50` | Max global new connections per second before triggering mitigation. |
| `PROXY_MITIGATION_TIME` | `5m` | Duration to keep mitigation active after thresholds are no longer exceeded (e.g., `5m`, `300s`). |
| `PROXY_VERIFY_TIME` | `5m` | Duration for which a user remains verified after solving a CAPTCHA. |
| `PROXY_ALWAYS_ON` | `false` | If `true`, the challenge is served for every request regardless of rate. |
| `PROXY_JWT_SECRET` | `...` | Secret key used to sign JWT tokens. **Change this in production!** |
| `PROXY_TURNSTILE_PUBLIC_KEY` | `""` | Cloudflare Turnstile Site Key (Required for CAPTCHA). |
| `PROXY_TURNSTILE_PRIVATE_KEY` | `""` | Cloudflare Turnstile Secret Key (Required for CAPTCHA). |

## Usage

### Prerequisites

1.  **Go 1.23+** installed.
2.  **Cloudflare Turnstile Keys**: Obtain a Site Key and Secret Key from the [Cloudflare Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile).

### Running Locally

1.  Set the environment variables:

    ```bash
    export PROXY_BACKEND_URL="http://localhost:3000"
    export PROXY_TURNSTILE_PUBLIC_KEY="your-site-key"
    export PROXY_TURNSTILE_PRIVATE_KEY="your-secret-key"
    export PROXY_JWT_SECRET="your-secure-random-secret"
    
    # Optional tuning
    export PROXY_MAX_REQ=500
    export PROXY_MAX_CONN=100
    ```

2.  Run the proxy:

    ```bash
    go run main.go
    ```

3.  Access the proxy at `http://localhost:8080`.

### Building for Production

Build the binary:

```bash
go build -o ddos-proxy main.go
```

Run the binary:

```bash
./ddos-proxy
```

## How it Works

1.  **Normal Operation**: Requests are proxied to `PROXY_BACKEND_URL`. The proxy tracks global request and connection rates.
2.  **Mitigation Trigger**: If rates exceed `PROXY_MAX_REQ` or `PROXY_MAX_CONN`, the proxy enters **Mitigation Mode**.
3.  **Challenge**: In Mitigation Mode, all new requests (without a valid JWT) are served a lightweight HTML page containing a Cloudflare Turnstile widget.
4.  **Verification**:
    -   The user solves the CAPTCHA.
    -   The browser submits the solution to `/challenge/verify`.
    -   The proxy verifies the token with Cloudflare.
    -   If valid, a JWT cookie (`proxy_auth`) is set, and the user is redirected to their original URL.
5.  **Bypass**: Subsequent requests with a valid `proxy_auth` cookie bypass the rate limiter and are proxied directly to the backend.
6.  **Blocking**: If an IP receives a challenge but continues to send requests without solving it (more than 5 times), the IP is **blocked**, and its TCP connection is forcibly closed.
7.  **Recovery**: Mitigation Mode automatically turns off after `PROXY_MITIGATION_TIME` passes without rate violations (unless `PROXY_ALWAYS_ON` is set).

## Security Notes

-   **Turnstile Keys**: Ensure your Turnstile keys are kept secret and not committed to public repositories.
-   **JWT Secret**: Use a strong, random string for `PROXY_JWT_SECRET` to prevent token forging.
-   **Reverse Proxy Headers**: The proxy sets `X-Forwarded-Host` and updates the `Host` header to match the backend target. Ensure your backend is configured to trust these headers if necessary.
