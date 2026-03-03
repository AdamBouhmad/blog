#!/usr/bin/env python3
import base64
import json
import os
import sys
from urllib import parse, request


AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8888/callback"
SCOPES = [
    "user-read-currently-playing",
    "user-read-playback-state",
    "user-read-private",
]


def build_authorize_url(client_id: str, redirect_uri: str) -> str:
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": " ".join(SCOPES),
        "show_dialog": "true",
    }
    return f"{AUTH_URL}?{parse.urlencode(params)}"


def exchange_code(
    client_id: str, client_secret: str, redirect_uri: str, code: str
) -> dict:
    body = parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode("utf-8")

    token = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode(
        "utf-8"
    )

    req = request.Request(TOKEN_URL, data=body, method="POST")
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    client_id = os.getenv("SPOTIFY_CLIENT_ID", "").strip()
    client_secret = os.getenv("SPOTIFY_CLIENT_SECRET", "").strip()
    redirect_uri = os.getenv("SPOTIFY_REDIRECT_URI", DEFAULT_REDIRECT_URI).strip()

    if not client_id or not client_secret:
        print("Set SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET first.")
        return 1

    if len(sys.argv) == 1:
        print("Open this URL in your browser and authorize:\n")
        print(build_authorize_url(client_id, redirect_uri))
        print(
            "\nAfter approval, paste the full callback URL as the first argument to this script."
        )
        return 0

    callback_url = sys.argv[1]
    parsed = parse.urlparse(callback_url)
    query = parse.parse_qs(parsed.query)
    code = (query.get("code") or [""])[0]
    if not code:
        print("No authorization code found in callback URL.")
        return 1

    payload = exchange_code(client_id, client_secret, redirect_uri, code)
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        print("No refresh_token in response. Full response:")
        print(json.dumps(payload, indent=2))
        return 1

    print("Refresh token:\n")
    print(refresh_token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
