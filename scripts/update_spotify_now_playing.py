#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib import parse, request, error


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "data" / "spotify_now_playing.json"


def post_form(url: str, data: dict, headers: dict | None = None) -> dict:
    encoded = parse.urlencode(data).encode("utf-8")
    req = request.Request(url, data=encoded, method="POST")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_json(url: str, token: str) -> tuple[int, dict | None]:
    req = request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    try:
        with request.urlopen(req, timeout=20) as resp:
            status = resp.getcode()
            body = resp.read().decode("utf-8")
            return status, json.loads(body) if body else None
    except error.HTTPError as e:
        if e.code == 204:
            return 204, None
        body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"HTTP {e.code} from Spotify at {url}: {body}") from e


def fetch_access_token(client_id: str, client_secret: str, refresh_token: str) -> str:
    payload = post_form(
        "https://accounts.spotify.com/api/token",
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("Spotify token refresh succeeded but access_token missing")
    return token


def build_payload(token: str, default_profile_name: str) -> dict:
    now_status, now_data = get_json(
        "https://api.spotify.com/v1/me/player/currently-playing", token
    )

    profile_status, profile_data = get_json("https://api.spotify.com/v1/me", token)
    profile_name = default_profile_name
    if profile_status == 200 and profile_data:
        profile_name = profile_data.get("display_name") or default_profile_name

    payload = {
        "profile_name": profile_name,
        "is_playing": False,
        "track": "Not playing right now",
        "artist": "Spotify",
        "album_art_url": "",
        "song_url": "",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    if now_status == 200 and now_data:
        item = now_data.get("item") or {}
        artists = item.get("artists") or []
        artist_names = ", ".join([a.get("name", "") for a in artists if a.get("name")])
        images = (item.get("album") or {}).get("images") or []

        payload.update(
            {
                "is_playing": bool(now_data.get("is_playing")),
                "track": item.get("name") or payload["track"],
                "artist": artist_names or payload["artist"],
                "album_art_url": images[0].get("url") if images else "",
                "song_url": ((item.get("external_urls") or {}).get("spotify")) or "",
            }
        )

    return payload


def main() -> int:
    client_id = os.getenv("SPOTIFY_CLIENT_ID", "").strip()
    client_secret = os.getenv("SPOTIFY_CLIENT_SECRET", "").strip()
    refresh_token = os.getenv("SPOTIFY_REFRESH_TOKEN", "").strip()
    profile_name = (
        os.getenv("SPOTIFY_PROFILE_NAME", "Adam Bouhmad").strip() or "Adam Bouhmad"
    )

    if not client_id or not client_secret or not refresh_token:
        print("Missing Spotify credentials; skipping update.")
        return 0

    try:
        payload = build_payload(
            token=fetch_access_token(client_id, client_secret, refresh_token),
            default_profile_name=profile_name,
        )
    except Exception as exc:
        print(f"Failed to update spotify_now_playing.json: {exc}", file=sys.stderr)
        return 1

    OUTPUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Updated {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
