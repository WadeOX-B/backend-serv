import hashlib
import hmac
import os
import time
import json
import base64
import random
import uuid
import database

def _get_or_create_jwt_secret() -> bytes:
    env_sec = os.getenv("JWT_SECRET")
    if env_sec:
        return env_sec.encode('utf-8')
    secret_path = os.path.join(os.path.dirname(__file__), ".jwt_secret")
    try:
        if os.path.exists(secret_path):
            with open(secret_path, "r", encoding="utf-8") as f:
                saved = f.read().strip()
                if saved:
                    return saved.encode('utf-8')
        new_secret = os.urandom(48).hex()
        with open(secret_path, "w", encoding="utf-8") as f:
            f.write(new_secret)
        return new_secret.encode('utf-8')
    except Exception:
        return b"devora_discord_ultra_secure_secret_key_2026"

JWT_SECRET = _get_or_create_jwt_secret()


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}:{key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, key = stored_hash.split(":")
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hmac.compare_digest(new_key.hex(), key)
    except Exception:
        return False


def generate_tag(username: str) -> str:
    # Generates a 4-digit Discord tag 0001-9999
    return f"{random.randint(1, 9999):04d}"


def create_token(user_id: str, username: str) -> str:
    payload = {
        "uid": user_id,
        "un": username,
        "exp": int(time.time()) + (86400 * 30)  # 30 days
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(JWT_SECRET, payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_token(token: str):
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        # add padding
        pad = len(payload_b64) % 4
        if pad:
            payload_b64 += "=" * (4 - pad)
        
        expected_sig = hmac.new(JWT_SECRET, parts[0].encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode())
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def is_ceo(user):
    if not user:
        return False
    if user.get("email", "").lower() == "builder.hugo@gmail.com" or user.get("id") == "3b2b45d7-9268-4e5e-b477-caa75ec65105":
        return True
    badges = user.get("global_badges") or []
    if isinstance(badges, list) and "ceo" in badges:
        return True
    return False


def get_user_by_id(user_id: str):
    user = database.query_one("SELECT id, username, display_name, tag, email, avatar_url, banner_color, banner_url, bio, custom_status, presence_status, global_badges, is_bot, is_verified_bot, bot_app_id, orbs_points, ads_watched, last_orbs_daily, avatar_decoration, profile_effect, profile_frame, inventory, created_at FROM users WHERE id = ?", (user_id,))
    if user:
        badges = user.get("global_badges")
        if isinstance(badges, str):
            try:
                badges = json.loads(badges)
            except Exception:
                badges = []
        if not isinstance(badges, list):
            badges = []
            
        user["global_badges"] = badges
        user["is_ceo"] = is_ceo(user)
        user["is_bot"] = bool(user.get("is_bot", 0))
        user["is_verified_bot"] = bool(user.get("is_verified_bot", 0))
        user["orbs_points"] = int(user.get("orbs_points") or 0)
        user["eclats_points"] = user["orbs_points"]
        user["ads_watched"] = int(user.get("ads_watched") or 0)
        user["last_orbs_daily"] = user.get("last_orbs_daily")
        user["avatar_decoration"] = user.get("avatar_decoration") or ""
        user["profile_effect"] = user.get("profile_effect") or ""
        user["profile_frame"] = user.get("profile_frame") or ""

        inv = user.get("inventory")
        if isinstance(inv, str):
            try:
                inv = json.loads(inv)
            except Exception:
                inv = []
        if not isinstance(inv, list):
            inv = []
        user["inventory"] = inv
    return user
