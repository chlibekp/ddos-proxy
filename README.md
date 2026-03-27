# DDoS Protection Proxy

A high-performance Go reverse proxy designed to protect backend services from DDoS attacks. It features global rate limiting, connection limiting, and Cloudflare Turnstile challenges to mitigate automated attacks.

## Features

- **Global Rate Limiting**: Triggers mitigation mode when request rate exceeds a threshold.
- **Connection Limiting**: Triggers mitigation mode when new connection rate exceeds a threshold.
- **Cloudflare Turnstile**: Challenges users with a CAPTCHA when mitigation mode is active.
- **IP Verification**: Validated IPs bypass challenges for a configurable duration.
- **Sticky Mitigation**: Mitigation mode stays active for a set duration after the attack subsides.
- **Always-On Mode**: Option to permanently enable the challenge for all requests.
- **Aggressive Blocking**: IPs that fail to solve the challenge and continue sending requests are blocked. The action is configurable (403 Forbidden or Close Connection).
- **User-Agent Whitelisting**: Allows trusted bots (e.g., Googlebot) to bypass challenges, subject to a separate global rate limit.
- **Prometheus Metrics**: Exposes a `/metrics` endpoint for monitoring, secured with a rate limit of 1 req/s per IP.

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
| `PROXY_CLOUDFLARE_SUPPORT` | `false` | If `true`, the `CF-Connecting-IP` header is used as the client IP. |
| `PROXY_TURNSTILE_PUBLIC_KEY` | `""` | Cloudflare Turnstile Site Key (Required for CAPTCHA). |
| `PROXY_TURNSTILE_PRIVATE_KEY` | `""` | Cloudflare Turnstile Secret Key (Required for CAPTCHA). |
| `PROXY_WHITELIST_UA` | `""` | Comma-separated list of User-Agent substrings to whitelist (e.g., `Googlebot,Bingbot`). |
| `PROXY_WHITELIST_RATE` | `10` | Global rate limit (requests/sec) for all whitelisted User-Agents combined. |
| `PROXY_PROMETHEUS_ENABLED` | `false` | If `true`, enables the `/metrics` endpoint. |
| `PROXY_BLOCK_ACTION` | `403` | Action to take when an IP is blocked (`403` or `close`). |
| `PROXY_AUTO_MITIGATION_ON_TIMEOUT` | `false` | If `true`, enables mitigation mode when multiple requests timeout or take too long. |
| `PROXY_MAX_TIMEOUTS` | `5` | Number of timeouts/long requests allowed before triggering mitigation mode. |
| `PROXY_TIMEOUT_THRESHOLD` | `5s` | Duration threshold to consider a request as "long" (e.g., `5s`, `10s`). |

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

1.  **User-Agent Check**: Requests matching a whitelisted User-Agent (via `PROXY_WHITELIST_UA`) bypass challenges and are subject to a separate global rate limit (`PROXY_WHITELIST_RATE`). If they exceed this limit, they receive a 429 error.
2.  **Normal Operation**: Other requests are proxied to `PROXY_BACKEND_URL`. The proxy tracks global request and connection rates.
3.  **Mitigation Trigger**: If rates exceed `PROXY_MAX_REQ` or `PROXY_MAX_CONN`, the proxy enters **Mitigation Mode**.
4.  **Challenge**: In Mitigation Mode, all new requests (without a valid verification) are served a lightweight HTML page containing a Cloudflare Turnstile widget.
5.  **Verification**:
    -   The user solves the CAPTCHA.
    -   The browser submits the solution to `/challenge/verify`.
    -   The proxy verifies the token with Cloudflare.
    -   If valid, the IP address is marked as **verified** for `PROXY_VERIFY_TIME`.
    -   The user is redirected to their original URL.
6.  **Bypass**: Subsequent requests from a verified IP bypass the rate limiter and are proxied directly to the backend.
7.  **Blocking**: If an IP receives a challenge but continues to send requests without solving it (more than 5 times), the IP is **blocked**, and its TCP connection is forcibly closed.
8.  **Recovery**: Mitigation Mode automatically turns off after `PROXY_MITIGATION_TIME` passes without rate violations (unless `PROXY_ALWAYS_ON` is set).

## Security Notes

-   **Turnstile Keys**: Ensure your Turnstile keys are kept secret and not committed to public repositories.
-   **Reverse Proxy Headers**: The proxy preserves the original `Host` header from the client. Ensure your backend is configured to handle the incoming Host header correctly.
