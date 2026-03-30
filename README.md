# Granite Guardian Proxy

A reverse proxy for the OpenAI API that screens all prompts and responses
using IBM Granite Guardian. Harmful content is blocked before it reaches
OpenAI and a structured rejection message is returned to the client in
standard OpenAI response format.

## How it works
```
client → NGINX :443 (SSL termination) → mitmproxy :8080 (Guardian check) → OpenAI
```

Every prompt is sent to IBM Granite Guardian, which assigns a toxicity score
between 0.0 and 1.0. Requests scoring above the configured threshold are
blocked and never reach OpenAI. Both prompts and responses are checked.

## Project structure
```
granite-guardian-proxy/
├── certs/                  # SSL certificate and private key
├── client/                 # Test client container
│   ├── client.py
│   ├── Dockerfile
│   └── requirements.txt
├── mitmproxy/              # Proxy and Guardian addon container
│   ├── addon.py
│   ├── Dockerfile
│   └── requirements.txt
├── nginx/                  # SSL termination config
│   └── nginx.conf
├── .env.example            # Environment variable template
├── docker-compose.yml
└── README.md
```

## Prerequisites

- Docker and Docker Compose
- OpenAI API key with billing enabled
- IBM watsonx.ai account (free tier, us-south region)

## Setup

**1. Clone the repository**
```bash
git clone <repo-url>
cd granite-guardian-proxy
```

**2. Configure environment variables**
```bash
cp .env.example .env
```

Edit `.env` with your keys:
```
OPENAI_API_KEY=sk-proj-your-key-here
IBM_API_KEY=your-ibm-api-key-here
IBM_PROJECT_ID=your-project-id-here
IBM_URL=https://us-south.ml.cloud.ibm.com
TOXICITY_THRESHOLD=0.7
```

**3. Generate SSL certificate**
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=nginx" \
  -addext "subjectAltName=DNS:nginx,DNS:localhost,IP:127.0.0.1"
```

The certificate is valid for both `nginx` (Docker service name) and
`localhost` so it works inside Docker and from the host machine.

## Run
```bash
docker compose up --build
```
Stop all services:
```bash
docker compose down
```

## Block categories

| Category | Trigger keywords | Block message |
|---|---|---|
| Violent acts | stab, kill, shoot, bomb, weapon | `...contained description of violent acts.` |
| Illegal activity | hack, steal, pick a lock, drug | `...contained inquiry on how to perform an illegal activity.` |
| Sexual content | explicit, nude, porn, erotic | `...contained sexual content.` |
| Toxic content | any other harmful content | `...contained toxic content.` |

## Response format

Blocked requests return HTTP 200 with an OpenAI-compatible response:
```json
{
  "id": "blocked-by-guardian",
  "object": "chat.completion",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "The prompt was blocked because it contained description of violent acts."
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0
  },
  "guardian_score": 1.000,
  "guardian_threshold": 0.7
}
```

`total_tokens: 0` confirms OpenAI was never called. `guardian_score` shows
the confidence score that triggered the block.

## Troubleshooting

**IBM 403 — project not associated with WML instance**
Your IBM project must be in the same region as `IBM_URL`. Use `us-south` —
Toronto (`ca-tor`) does not support Granite Guardian.

**SSL certificate verify failed — hostname mismatch**
Regenerate the certificate using the command in step 3. The
`subjectAltName` must include `DNS:nginx` for Docker internal routing.

**ValueError on TOXICITY_THRESHOLD at startup**
Check `.env` — `TOXICITY_THRESHOLD` must have a numeric value such as
`0.7`, not an empty string.

**Client gets 301 Moved Permanently**
Ensure `client.py` connects to `https://nginx/v1` not `http://nginx` and
that port 80 is not exposed in `docker-compose.yml`.