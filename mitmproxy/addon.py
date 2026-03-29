"""
addon.py

mitmproxy addon that intercepts OpenAI API traffic and checks all prompts
and responses against IBM Granite Guardian. Requests scoring above the
toxicity threshold are blocked and replaced with a structured error response.
"""

import json
import math
import os
from typing import Literal

import requests
from mitmproxy import http

# --- Guardian config -----------------------------------------------------

GUARDIAN_MODEL      = "ibm/granite-guardian-3-8b"
GUARDIAN_API_DATE   = "2024-05-13"
IBM_IAM_URL         = "https://iam.cloud.ibm.com/identity/token"
TOXICITY_THRESHOLD = float(os.environ.get("TOXICITY_THRESHOLD") or "0.7")

IBM_API_KEY    = os.environ.get("IBM_API_KEY")
IBM_PROJECT_ID = os.environ.get("IBM_PROJECT_ID")
IBM_URL        = os.environ.get("IBM_URL", "https://us-south.ml.cloud.ibm.com")

# --- classification keywords ---------------------------------------------

VIOLENT_KEYWORDS = [
    "stab", "kill", "shoot", "attack", "bomb",
    "murder", "hurt", "violent", "weapon",
]
ILLEGAL_KEYWORDS = [
    "illegal", "break in", "pick a lock",
    "hack", "steal", "drug", "smuggle", "crime",
]
SEXUAL_KEYWORDS = [
    "sexual", "explicit", "nude", "porn", "erotic", "sex",
]

GUARDIAN_SYSTEM_PROMPT = (
    "You are a safety classifier. "
    "For the given text, respond with only 'Yes' if it contains harmful content, "
    "or 'No' if it is safe. Harmful content includes: violence, illegal activities, "
    "sexual content, hate speech, or toxic language."
)

# --- IBM authentication --------------------------------------------------

_cached_token: str | None = None


def get_ibm_token() -> str:
    """Exchange the IBM API key for a short-lived IAM access token.

    Tokens are cached in memory and reused until the process restarts.

    Returns:
        str: A valid IBM IAM bearer token.

    Raises:
        requests.HTTPError: If the IAM request fails.
    """
    global _cached_token
    if _cached_token:
        return _cached_token

    resp = requests.post(
        IBM_IAM_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": IBM_API_KEY,
        },
    )
    resp.raise_for_status()
    _cached_token = resp.json()["access_token"]
    print("[Guardian] IBM token obtained")
    return _cached_token


# --- content classification ----------------------------------------------

def _classify_reason(text: str) -> str:
    """Map text to one of the three required harm categories.

    Falls back to 'toxic content' if no keyword pattern matches.

    Args:
        text: Lowercased input text to classify.

    Returns:
        str: One of the four harm reason strings.
    """
    if any(w in text for w in VIOLENT_KEYWORDS):
        return "description of violent acts"
    if any(w in text for w in ILLEGAL_KEYWORDS):
        return "inquiry on how to perform an illegal activity"
    if any(w in text for w in SEXUAL_KEYWORDS):
        return "sexual content"
    return "toxic content"


def _extract_score(data: dict, harmful: bool) -> float:
    """Extract a 0.0-1.0 toxicity score from Guardian logprobs.

    Falls back to a binary score if logprobs are unavailable.

    Args:
        data: Raw JSON response from the Guardian API.
        harmful: Whether Guardian answered 'Yes'.

    Returns:
        float: Confidence score between 0.0 and 1.0.
    """
    try:
        logprobs = data["choices"][0].get("logprobs", {})
        top_tokens = logprobs.get("content", [{}])[0].get("top_logprobs", [])
        for token_info in top_tokens:
            if token_info.get("token", "").strip().lower() == "yes":
                return math.exp(token_info.get("logprob", -10))
    except (KeyError, IndexError):
        pass
    return 1.0 if harmful else 0.0


def check_with_guardian(text: str) -> tuple[bool, str | None, float]:
    """Send text to Granite Guardian and return a safety assessment.

    Args:
        text: The prompt or response text to evaluate.

    Returns:
        tuple: (is_harmful, reason, score) where score is 0.0-1.0.

    Raises:
        requests.HTTPError: If the Guardian API request fails.
    """
    token = get_ibm_token()

    payload = {
        "model_id": GUARDIAN_MODEL,
        "project_id": IBM_PROJECT_ID,
        "messages": [
            {"role": "system", "content": GUARDIAN_SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "max_tokens": 10,
        "temperature": 0,
        "logprobs": True,
        "top_logprobs": 5,
    }

    resp = requests.post(
        f"{IBM_URL}/ml/v1/text/chat?version={GUARDIAN_API_DATE}",
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    resp.raise_for_status()
    data = resp.json()

    answer  = data["choices"][0]["message"]["content"].strip().lower()
    harmful = answer.startswith("yes")
    score   = _extract_score(data, harmful)
    reason  = _classify_reason(text.lower()) if harmful else None

    return harmful, reason, score


# --- response builder ----------------------------------------------------

def make_blocked_response(
    reason: str,
    score: float,
    source: Literal["prompt", "response"],
) -> str:
    """Build a synthetic OpenAI-format response for a blocked request.

    The response mirrors the OpenAI chat completion schema so the client
    needs no special handling for blocked content.

    Args:
        reason: Human-readable harm category string.
        score: Guardian confidence score that triggered the block.
        source: Whether the prompt or the response was blocked.

    Returns:
        str: JSON string matching the OpenAI chat completion schema.
    """
    message = f"The {source} was blocked because it contained {reason}."

    return json.dumps({
        "id": "blocked-by-guardian",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": message},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "guardian_score": round(score, 3),
        "guardian_threshold": TOXICITY_THRESHOLD,
    })


# --- mitmproxy addon -----------------------------------------------------

class GuardianAddon:
    """mitmproxy addon that guards OpenAI traffic with Granite Guardian.

    Intercepts all HTTP flows through the proxy. Checks prompts before
    forwarding to OpenAI and checks responses before returning to the client.
    """

    def _check_and_block(
        self,
        flow: http.HTTPFlow,
        text: str,
        source: Literal["prompt", "response"],
    ) -> bool:
        """Run a Guardian check and block the flow if harmful.

        Args:
            flow: The active mitmproxy flow.
            text: Text to evaluate (prompt or response content).
            source: Label used in the block message and logs.

        Returns:
            bool: True if the flow was blocked, False otherwise.
        """
        try:
            harmful, reason, score = check_with_guardian(text)
        except Exception as e:
            print(f"[Guardian] Check failed: {e} — passing through")
            return False

        print(f"[Guardian] Score: {score:.3f} / Threshold: {TOXICITY_THRESHOLD}")

        if harmful and score >= TOXICITY_THRESHOLD:
            print(f"[Guardian] BLOCKED {source.upper()} — {reason} (score={score:.3f})")
            blocked = make_blocked_response(reason, score, source)
            if source == "prompt":
                flow.response = http.Response.make(
                    200, blocked, {"Content-Type": "application/json"}
                )
            else:
                flow.response.content = blocked.encode()
            return True

        print(f"[Guardian] SAFE {source.upper()} — passing through")
        return False

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept outgoing requests and check prompts with Guardian.

        Rewrites the host to api.openai.com when traffic arrives via NGINX,
        then checks the user prompt before forwarding.

        Args:
            flow: The active mitmproxy HTTP flow.
        """
        # Rewrite host set to localhost by NGINX to the real OpenAI endpoint
        if flow.request.pretty_host in ("localhost", "127.0.0.1"):
            flow.request.host   = "api.openai.com"
            flow.request.port   = 443
            flow.request.scheme = "https"

        if "api.openai.com" not in flow.request.pretty_host:
            return
        if "/chat/completions" not in flow.request.path:
            return

        print(f"\n[Guardian] PROMPT CHECK")

        try:
            body = json.loads(flow.request.content)
        except json.JSONDecodeError:
            print("[Guardian] Could not parse request body — passing through")
            return

        user_messages = [
            m["content"] for m in body.get("messages", [])
            if m.get("role") == "user"
        ]
        if not user_messages:
            return

        prompt = user_messages[-1]
        flow.request.port   = 443
        flow.request.scheme = "https"
        print(f"[Guardian] Prompt: {prompt[:80]}")
        self._check_and_block(flow, prompt, "prompt")

    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept incoming responses and check replies with Guardian.

        Skips Guardian-generated blocked responses to avoid double-checking.

        Args:
            flow: The active mitmproxy HTTP flow.
        """
        if "api.openai.com" not in flow.request.pretty_host:
            return

        print(f"\n[Guardian] RESPONSE CHECK — status {flow.response.status_code}")

        try:
            body = json.loads(flow.response.content)
        except json.JSONDecodeError:
            return

        # Skip responses we already generated
        if body.get("id") == "blocked-by-guardian":
            return

        try:
            reply = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            print("[Guardian] Could not extract reply — skipping check")
            return

        print(f"[Guardian] Response: {reply[:80]}")
        self._check_and_block(flow, reply, "response")


addons = [GuardianAddon()]