import os
import sys
import json
import uuid
import time
from datetime import datetime
import asyncio
import re
from aiohttp import web, WSMsgType
import database
import auth

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# Initialize DB on startup
# Initialize DB and Official Server on startup
database.init_db()
database.ensure_official_server()
database.ensure_protect_bot()
database.ensure_bastion_system_user()

# Connected WebSocket clients: user_id -> set of ws_connections
connected_clients = {}
# Active channels per connection: ws -> channel_id
ws_channel_subscriptions = {}
# Typing statuses: channel_id -> {user_id: timestamp}
typing_users = {}

routes = web.RouteTableDef()


@routes.get("/api/ping")
@routes.get("/api/health")
async def api_health(request):
    return web.json_response({
        "status": "ok",
        "app": "BASTION",
        "version": "0.3.1",
        "database": database.DB_ENGINE
    })


def json_dumps(obj):
    return json.dumps(obj, default=str)


# --- Middleware for Auth ---
def get_auth_user(request):
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    elif "token" in request.query:
        token = request.query["token"]
    
    if not token:
        return None
    payload = auth.verify_token(token)
    if not payload:
        return None
    return auth.get_user_by_id(payload["uid"])


# --- WebSocket Broadcast Helpers ---
async def broadcast_to_channel(channel_id, message_data, exclude_ws=None):
    payload = json_dumps(message_data)
    to_remove = []
    for ws, sub_channel in list(ws_channel_subscriptions.items()):
        if sub_channel == channel_id and ws != exclude_ws:
            try:
                await ws.send_str(payload)
            except Exception:
                to_remove.append(ws)
    for ws in to_remove:
        ws_channel_subscriptions.pop(ws, None)


async def broadcast_to_all(message_data, exclude_ws=None):
    payload = json_dumps(message_data)
    for u_id, ws_set in list(connected_clients.items()):
        for ws in list(ws_set):
            if ws != exclude_ws:
                try:
                    await ws.send_str(payload)
                except Exception:
                    pass


async def broadcast_presence_change(user_id, status):
    await broadcast_to_all({
        "type": "PRESENCE_UPDATE",
        "userId": user_id,
        "status": status
    })


async def send_to_user(user_id, message_data):
    payload = json_dumps(message_data)
    if user_id in connected_clients:
        for ws in list(connected_clients[user_id]):
            try:
                await ws.send_str(payload)
            except Exception:
                pass

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")
UPLOAD_ATTACHMENTS_DIR = os.path.join(UPLOAD_DIR, "attachments")
UPLOAD_AVATARS_DIR = os.path.join(UPLOAD_DIR, "avatars")
UPLOAD_BANNERS_DIR = os.path.join(UPLOAD_DIR, "banners")
UPLOAD_SERVER_ICONS_DIR = os.path.join(UPLOAD_DIR, "server_icons")
UPLOAD_SERVER_BANNERS_DIR = os.path.join(UPLOAD_DIR, "server_banners")

for _d in [UPLOAD_DIR, UPLOAD_ATTACHMENTS_DIR, UPLOAD_AVATARS_DIR, UPLOAD_BANNERS_DIR, UPLOAD_SERVER_ICONS_DIR, UPLOAD_SERVER_BANNERS_DIR]:
    os.makedirs(_d, exist_ok=True)


def remove_local_upload_file(url_path):
    """Supprime un ancien fichier local s'il est situé dans static/uploads pour libérer de l'espace disque"""
    if not url_path or not isinstance(url_path, str):
        return
    if "/static/uploads/" in url_path:
        rel = url_path.split("/static/uploads/")[-1].strip("/\\")
        target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel))
        if target_path.startswith(UPLOAD_DIR) and os.path.isfile(target_path):
            try:
                os.remove(target_path)
                print(f"[STORAGE] Fichier remplacé supprimé du disque : {rel}")
            except Exception as e:
                print(f"[STORAGE] Erreur suppression ancien fichier {rel}: {e}")


def can_user_delete_message(user, message):
    """Vérifie si l'utilisateur a la permission de supprimer un message donné (auteur, propriétaire, modérateur avec rôle)"""
    if not user or not message:
        return False
    # 1. Auteur du message
    if str(message.get("user_id")) == str(user.get("id")):
        return True
    # 2. CEO de BASTION
    if auth.is_ceo(user):
        return True
    
    server_id = message.get("server_id")
    if not server_id:
        return False
    
    # 3. Propriétaire du serveur
    server = database.query_one("SELECT owner_id FROM servers WHERE id = ?", (server_id,))
    if server and str(server.get("owner_id")) == str(user.get("id")):
        return True
    
    # 4. Rôles serveur avec permission ADMINISTRATOR ou MANAGE_MESSAGES
    roles = database.query("""
        SELECT r.permissions FROM member_roles mr
        JOIN roles r ON mr.role_id = r.id
        WHERE mr.server_id = ? AND mr.user_id = ?
    """, (server_id, user["id"]))
    
    for r in roles:
        perms = r.get("permissions")
        if isinstance(perms, str):
            try:
                perms = json.loads(perms)
            except Exception:
                perms = []
        if isinstance(perms, list):
            perms_upper = [str(p).upper() for p in perms]
            if any(p in perms_upper for p in ["ADMINISTRATOR", "MANAGE_MESSAGES", "MODERATOR", "DELETE_MESSAGES"]):
                return True
    return False


def check_channel_access(user, channel, server=None, action="view"):
    """
    Vérifie les permissions d'un utilisateur sur un salon spécifique.
    action: 'view' | 'write' | 'react'
    Retourne (allowed: bool, reason: str)
    """
    if not user:
        return False, "Non authentifié"
    if not channel:
        return False, "Salon introuvable"

    server_id = channel.get("server_id")
    if not server and server_id:
        server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))

    # 1. Propriétaire du serveur
    if server and str(server.get("owner_id")) == str(user.get("id")):
        return True, ""

    # 2. BASTION CEO
    if auth.is_ceo(user):
        return True, ""

    # 3. Rôles et statut Administrateur
    user_roles_raw = database.query("""
        SELECT r.id, r.name, r.permissions 
        FROM member_roles mr
        JOIN roles r ON mr.role_id = r.id
        WHERE mr.server_id = ? AND mr.user_id = ?
    """, (server_id, user["id"]))

    user_roles_ids = [str(r["id"]) for r in user_roles_raw]

    has_admin = False
    for r in user_roles_raw:
        perms = r.get("permissions") or []
        if isinstance(perms, str):
            try:
                perms = json.loads(perms)
            except Exception:
                perms = []
        perms_upper = [str(p).upper() for p in perms]
        if r.get("name") in ["Owner", "Admin", "Administrateur"] or "ADMINISTRATOR" in perms_upper:
            has_admin = True
            break

    if has_admin:
        return True, ""

    # Vérifier l'appartenance au serveur
    membership = database.query_one("SELECT id FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
    if not membership:
        return False, "Vous ne faites pas partie de ce serveur."

    # Parser permissions_data
    perm_data = channel.get("permissions_data")
    perms_list = []
    if isinstance(perm_data, str) and perm_data:
        try:
            perms_list = json.loads(perm_data)
        except Exception:
            perms_list = []
    elif isinstance(perm_data, list):
        perms_list = perm_data

    user_override = next((p for p in perms_list if str(p.get("userId")) == str(user["id"])), None)

    # --- ÉTAPE A : PERMISSION DE VOIR (VIEW) ---
    is_private = (channel.get("is_private") == 1)
    can_view = not is_private

    role_allows_view = False
    role_denies_view = False

    for p in perms_list:
        rid = str(p.get("roleId")) if p.get("roleId") is not None else None
        if rid and rid in user_roles_ids:
            if p.get("canView") is True:
                role_allows_view = True
            elif p.get("canView") is False:
                role_denies_view = True

    if user_override:
        if user_override.get("canView") is True:
            can_view = True
        elif user_override.get("canView") is False:
            can_view = False
    elif is_private:
        can_view = role_allows_view
    else:
        if role_denies_view and not role_allows_view:
            can_view = False

    if not can_view:
        return False, "Ce salon est privé ou restreint pour votre rôle."

    if action == "view":
        return True, ""

    # --- ÉTAPE B : PERMISSION D'ÉCRIRE (WRITE) ---
    if action == "write":
        ch_type = channel.get("type", "text")
        if ch_type in ["announcement", "rules"] or channel.get("is_announcement") == 1:
            can_manage = False
            for r in user_roles_raw:
                perms = r.get("permissions") or []
                if isinstance(perms, str):
                    try:
                        perms = json.loads(perms)
                    except Exception:
                        perms = []
                perms_upper = [str(p).upper() for p in perms]
                if any(p in perms_upper for p in ["MANAGE_CHANNELS", "MANAGE_MESSAGES", "ADMINISTRATOR"]):
                    can_manage = True
                    break
            if not can_manage:
                return False, "Seuls les administrateurs et modérateurs peuvent publier dans ce salon."

        can_write = True
        role_allows_write = False
        role_denies_write = False

        for p in perms_list:
            rid = str(p.get("roleId")) if p.get("roleId") is not None else None
            if rid and rid in user_roles_ids:
                if p.get("canWrite") is True:
                    role_allows_write = True
                elif p.get("canWrite") is False:
                    role_denies_write = True

        if user_override:
            if user_override.get("canWrite") is False:
                can_write = False
            elif user_override.get("canWrite") is True:
                can_write = True
        elif role_denies_write and not role_allows_write:
            can_write = False

        if not can_write:
            return False, "Vous n'avez pas la permission d'envoyer des messages dans ce salon."
        return True, ""

    # --- ÉTAPE C : PERMISSION DE RÉAGIR (REACT) ---
    if action == "react":
        can_react = True
        role_allows_react = False
        role_denies_react = False

        for p in perms_list:
            rid = str(p.get("roleId")) if p.get("roleId") is not None else None
            if rid and rid in user_roles_ids:
                if p.get("canReact") is True:
                    role_allows_react = True
                elif p.get("canReact") is False:
                    role_denies_react = True

        if user_override:
            if user_override.get("canReact") is False:
                can_react = False
            elif user_override.get("canReact") is True:
                can_react = True
        elif role_denies_react and not role_allows_react:
            can_react = False

        if not can_react:
            return False, "Vous n'avez pas la permission d'ajouter des réactions dans ce salon."
        return True, ""

    return True, ""


async def cleanup_attachments_worker():
    """Tâche de fond sécurisée : supprime automatiquement les pièces jointes de chat vieilles de plus de 7 jours (1 semaine)"""
    while True:
        try:
            now = time.time()
            max_age = 7 * 24 * 3600  # 7 jours en secondes (604 800s)
            deleted_count = 0
            
            # Nettoyage du dossier attachments
            if os.path.exists(UPLOAD_ATTACHMENTS_DIR):
                for fname in os.listdir(UPLOAD_ATTACHMENTS_DIR):
                    fpath = os.path.join(UPLOAD_ATTACHMENTS_DIR, fname)
                    if os.path.isfile(fpath):
                        mtime = os.path.getmtime(fpath)
                        if (now - mtime) > max_age:
                            try:
                                os.remove(fpath)
                                deleted_count += 1
                                print(f"[SECURITY/CLEANUP] Pièce jointe expirée (+7 jours) supprimée : attachments/{fname}")
                            except Exception as e:
                                print(f"[SECURITY/CLEANUP] Erreur suppression {fname}: {e}")
            
            # Nettoyage des pièces jointes à la racine de static/uploads
            if os.path.exists(UPLOAD_DIR):
                for fname in os.listdir(UPLOAD_DIR):
                    fpath = os.path.join(UPLOAD_DIR, fname)
                    if os.path.isfile(fpath):
                        mtime = os.path.getmtime(fpath)
                        if (now - mtime) > max_age:
                            try:
                                os.remove(fpath)
                                deleted_count += 1
                                print(f"[SECURITY/CLEANUP] Fichier upload racine expiré (+7 jours) supprimé : uploads/{fname}")
                            except Exception:
                                pass
            
            if deleted_count > 0:
                print(f"[SECURITY/CLEANUP] Nettoyage 7 jours terminé : {deleted_count} fichier(s) expiré(s) purgé(s).")
        except Exception as err:
            print(f"[SECURITY/CLEANUP] Erreur boucle de nettoyage : {err}")
        
        # Vérification toutes les 3600 secondes (1 heure)
        await asyncio.sleep(3600)


# ==========================================================
# 1. AUTH ROUTES (SECURISÉES & ANTI-USURPATION)
# ==========================================================
@routes.post("/api/auth/register")
async def api_register(request):
    try:
        data = await request.json()
        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not username or len(username) < 2:
            return web.json_response({"error": "Le nom d'utilisateur doit contenir au moins 2 caractères."}, status=400)
        if not email or "@" not in email:
            return web.json_response({"error": "Adresse email invalide."}, status=400)
        if not password or len(password) < 6:
            return web.json_response({"error": "Le mot de passe doit faire au moins 6 caractères."}, status=400)

        # Protection Anti-Usurpation : vérification stricte du pseudo
        existing_username = database.query_one("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        if existing_username:
            return web.json_response({"error": f"Le pseudo '{username}' est déjà réservé par un autre compte."}, status=400)

        # Protection des noms réservés de l'équipe officielle
        is_real_ceo = (email == "builder.hugo@gmail.com")
        if username.lower() in ("wadeox", "bastion", "system", "admin", "moderateur", "staff") and not is_real_ceo:
            return web.json_response({"error": "Ce nom d'utilisateur est réservé au créateur et à l'équipe officielle BASTION."}, status=403)

        # Check existing email
        existing_email = database.query_one("SELECT id FROM users WHERE email = ?", (email,))
        if existing_email:
            return web.json_response({"error": "Cet email est déjà utilisé par un compte existant."}, status=400)

        user_id = str(uuid.uuid4())
        tag = auth.generate_tag(username)
        pwd_hash = auth.hash_password(password)
        
        # Attribution sécurisée des badges (seul le vrai CEO a les badges élites, les autres ont aucun badge par défaut)
        if is_real_ceo:
            badges = ["ceo", "owner", "developer", "moderator", "admin", "early_supporter", "vip", "verified", "staff"]
        else:
            badges = []

        avatar_url = f"https://api.dicebear.com/7.x/bottts/svg?seed={username}"

        database.execute("""
            INSERT INTO users (id, username, tag, email, password_hash, avatar_url, banner_color, bio, custom_status, presence_status, global_badges)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, tag, email, pwd_hash, avatar_url, "#5865F2", "Hey ! J'utilise BASTION.", "🎮 Nouveau sur BASTION", "online", badges))

        token = auth.create_token(user_id, username)
        user = auth.get_user_by_id(user_id)

        # Inscription automatique au serveur officiel de la communauté DEVORA
        database.add_user_to_official_server(user_id)

        # Create a default personal community server for the new user
        server_id = str(uuid.uuid4())
        database.execute("INSERT INTO servers (id, name, icon_url, description, owner_id) VALUES (?, ?, ?, ?, ?)",
                         (server_id, f"Serveur de {username}", avatar_url, "Bienvenue sur mon serveur !", user_id))
        
        # Add owner role
        role_id = str(uuid.uuid4())
        database.execute("INSERT INTO roles (id, server_id, name, color, icon, is_badge, permissions, position) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (role_id, server_id, "Owner", "#FEE75C", "👑", 1, ["ADMINISTRATOR"], 0))
        
        # Add member & member_role
        database.execute("INSERT INTO server_members (server_id, user_id) VALUES (?, ?)", (server_id, user_id))
        database.execute("INSERT INTO member_roles (server_id, user_id, role_id) VALUES (?, ?, ?)", (server_id, user_id, role_id))

        # Add default channels
        channels = [
            ("général", "text", "Salon principal pour discuter de tout et de rien"),
            ("annonces", "text", "Les dernières nouvelles du serveur"),
            ("Salon Vocal Général", "voice", "Venez parler en direct !")
        ]
        for idx, (c_name, c_type, c_topic) in enumerate(channels):
            cid = str(uuid.uuid4())
            database.execute("INSERT INTO channels (id, server_id, name, type, topic, position) VALUES (?, ?, ?, ?, ?, ?)",
                             (cid, server_id, c_name, c_type, c_topic, idx))

        return web.json_response({"token": token, "user": user})
    except Exception as e:
        return web.json_response({"error": f"Erreur serveur: {str(e)}"}, status=500)


@routes.post("/api/auth/login")
async def api_login(request):
    try:
        data = await request.json()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        user_row = database.query_one("SELECT * FROM users WHERE email = ?", (email,))
        if not user_row or not auth.verify_password(password, user_row["password_hash"]):
            return web.json_response({"error": "Identifiants incorrects. Vérifiez votre email et mot de passe."}, status=401)

        # Inscription automatique au serveur officiel de la communauté DEVORA
        database.add_user_to_official_server(user_row["id"])

        token = auth.create_token(user_row["id"], user_row["username"])
        user = auth.get_user_by_id(user_row["id"])
        return web.json_response({"token": token, "user": user})
    except Exception as e:
        return web.json_response({"error": f"Erreur: {str(e)}"}, status=500)


@routes.get("/api/auth/me")
async def api_me(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    # Assurer que l'utilisateur est bien dans le serveur officiel
    database.add_user_to_official_server(user["id"])
    return web.json_response({"user": user, "db_engine": database.DB_ENGINE})


@routes.put("/api/auth/profile")
async def api_update_profile(request):
    try:
        user = get_auth_user(request)
        if not user:
            return web.json_response({"error": "Non authentifié"}, status=401)
        
        try:
            data = await request.json()
        except Exception:
            data = {}

        # Username
        raw_username = data.get("username")
        if raw_username is not None and str(raw_username).strip():
            new_username = str(raw_username).strip()
        else:
            new_username = user.get("username") or "user"
        
        # Validation du pseudo si modifié
        if new_username.lower() != (user.get("username") or "").lower():
            existing = database.query_one("SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?", (new_username, user["id"]))
            if existing:
                return web.json_response({"error": "Ce nom d'utilisateur est déjà utilisé par un autre compte."}, status=400)
            
            if new_username.lower() in ("wadeox", "bastion", "system", "admin") and not auth.is_ceo(user):
                return web.json_response({"error": "Ce nom d'utilisateur est réservé au créateur BASTION."}, status=403)

        display_name = data.get("display_name") if "display_name" in data and data["display_name"] is not None else user.get("display_name")
        display_name = str(display_name or "").strip()

        bio = data.get("bio") if "bio" in data and data["bio"] is not None else user.get("bio")
        bio = str(bio or "")

        custom_status = data.get("custom_status") if "custom_status" in data and data["custom_status"] is not None else user.get("custom_status")
        custom_status = str(custom_status or "")

        avatar_url = data.get("avatar_url") if "avatar_url" in data and data["avatar_url"] is not None else user.get("avatar_url")
        avatar_url = str(avatar_url or "")

        banner_color = data.get("banner_color") if "banner_color" in data and data["banner_color"] is not None else user.get("banner_color")
        banner_color = str(banner_color or "#5865F2")

        banner_url = data.get("banner_url") if "banner_url" in data and data["banner_url"] is not None else user.get("banner_url")
        banner_url = str(banner_url or "")

        presence_status = data.get("presence_status") if "presence_status" in data and data["presence_status"] is not None else user.get("presence_status")
        presence_status = str(presence_status or "online")

        avatar_decoration = data.get("avatar_decoration") if "avatar_decoration" in data and data["avatar_decoration"] is not None else user.get("avatar_decoration")
        avatar_decoration = str(avatar_decoration or "")

        profile_effect = data.get("profile_effect") if "profile_effect" in data and data["profile_effect"] is not None else user.get("profile_effect")
        profile_effect = str(profile_effect or "")

        profile_frame = data.get("profile_frame") if "profile_frame" in data and data["profile_frame"] is not None else user.get("profile_frame")
        profile_frame = str(profile_frame or "")

        old_avatar = user.get("avatar_url") or ""
        old_banner = user.get("banner_url") or ""
        if avatar_url and avatar_url != old_avatar:
            remove_local_upload_file(old_avatar)
        if banner_url and banner_url != old_banner:
            remove_local_upload_file(old_banner)

        database.execute("""
            UPDATE users 
            SET username = ?, display_name = ?, bio = ?, custom_status = ?, avatar_url = ?, banner_color = ?, banner_url = ?, presence_status = ?,
                avatar_decoration = ?, profile_effect = ?, profile_frame = ?
            WHERE id = ?
        """, (new_username, display_name, bio, custom_status, avatar_url, banner_color, banner_url, presence_status,
              avatar_decoration, profile_effect, profile_frame, user["id"]))

        updated_user = auth.get_user_by_id(user["id"])
        await broadcast_presence_change(user["id"], presence_status)
        await broadcast_to_all({"type": "USER_UPDATED", "user": updated_user})
        return web.json_response({"user": updated_user})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return web.json_response({"error": f"Erreur serveur : {str(e)}"}, status=500)


@routes.put("/api/auth/email")
async def api_change_email(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    new_email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    if not new_email or "@" not in new_email:
        return web.json_response({"error": "Adresse e-mail invalide."}, status=400)
    
    user_row = database.query_one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
    if not user_row or not auth.verify_password(password, user_row["password_hash"]):
        return web.json_response({"error": "Mot de passe incorrect."}, status=400)
    
    existing = database.query_one("SELECT id FROM users WHERE LOWER(email) = ? AND id != ?", (new_email, user["id"]))
    if existing:
        return web.json_response({"error": "Cette adresse e-mail est déjà utilisée par un autre compte."}, status=400)
    
    database.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user["id"]))
    updated_user = auth.get_user_by_id(user["id"])
    return web.json_response({"user": updated_user, "message": "Adresse e-mail modifiée avec succès."})


@routes.put("/api/auth/password")
async def api_change_password(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    
    if len(new_password) < 6:
        return web.json_response({"error": "Le nouveau mot de passe doit contenir au moins 6 caractères."}, status=400)
    
    user_row = database.query_one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
    if not user_row or not auth.verify_password(old_password, user_row["password_hash"]):
        return web.json_response({"error": "Le mot de passe actuel est incorrect."}, status=400)
    
    new_hash = auth.hash_password(new_password)
    database.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
    return web.json_response({"success": True, "message": "Mot de passe modifié avec succès."})


# ==========================================================
# CONFORMITÉ LÉGALE & RGPD (Articles 15, 17, 20 RGPD & LCEN/DSA)
# ==========================================================

@routes.get("/api/users/me/export")
async def api_export_user_data(request):
    """RGPD Art. 20 - Droit à la portabilité des données personnelles."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    uid = user["id"]
    profile = auth.get_user_by_id(uid)
    if profile:
        profile.pop("password_hash", None)
        profile.pop("token", None)
    
    servers = database.query("""
        SELECT s.id, s.name, s.icon_url, sm.joined_at, sm.nickname
        FROM server_members sm
        JOIN servers s ON sm.server_id = s.id
        WHERE sm.user_id = ?
    """, (uid,))
    
    messages = database.query("""
        SELECT id, channel_id, server_id, content, created_at, attachments
        FROM messages
        WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 500
    """, (uid,))
    
    export_payload = {
        "export_date": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "legal_framework": "Conforme aux articles 15 et 20 du RGPD (Règlement UE 2016/679)",
        "profile": profile,
        "servers": servers or [],
        "recent_messages": messages or []
    }
    
    return web.json_response(export_payload)


@routes.delete("/api/users/me")
async def api_delete_account(request):
    """RGPD Art. 17 - Droit à l'effacement ('Droit à l'oubli')."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    password = data.get("password", "")
    
    user_row = database.query_one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
    if not user_row or not auth.verify_password(password, user_row["password_hash"]):
        return web.json_response({"error": "Mot de passe incorrect. Suppression refusée."}, status=400)
    
    uid = user["id"]
    try:
        # Anonymiser les messages envoyés
        database.execute("UPDATE messages SET content = '[Compte supprimé]' WHERE user_id = ?", (uid,))
        database.execute("DELETE FROM server_members WHERE user_id = ?", (uid,))
        database.execute("DELETE FROM friendships WHERE user1_id = ? OR user2_id = ?", (uid, uid))
        database.execute("DELETE FROM direct_messages WHERE sender_id = ? OR recipient_id = ?", (uid, uid))
        database.execute("DELETE FROM reactions WHERE user_id = ?", (uid,))
        database.execute("DELETE FROM users WHERE id = ?", (uid,))
        return web.json_response({"success": True, "message": "Votre compte et vos données ont été définitivement supprimés conformément au RGPD."})
    except Exception as e:
        print("[RGPD] Erreur suppression compte:", e)
        return web.json_response({"error": "Erreur lors de la suppression du compte."}, status=500)


@routes.post("/api/reports")
async def api_create_report(request):
    """LCEN Art. 6-I-5 & DSA - Notification de contenu illicite ou abusif."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    target_type = data.get("target_type", "message")
    target_id = data.get("target_id")
    reason = data.get("reason", "").strip()
    details = data.get("details", "").strip()
    
    if not target_id or not reason:
        return web.json_response({"error": "Cible et motif requis pour le signalement."}, status=400)
    
    try:
        database.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                reporter_id TEXT,
                target_type TEXT,
                target_id TEXT,
                reason TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        """)
        report_id = str(uuid.uuid4())
        database.execute("""
            INSERT INTO reports (id, reporter_id, target_type, target_id, reason, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (report_id, user["id"], target_type, target_id, reason, details))
        return web.json_response({"success": True, "message": "Signalement enregistré. Notre équipe examinera ce contenu rapidement."})
    except Exception as e:
        print("[REPORTS] Erreur création signalement:", e)
        return web.json_response({"error": "Erreur lors de l'enregistrement du signalement."}, status=500)


# ==========================================================
# BASTION ÉCLATS & EVOLUTION SYSTEM
# ==========================================================

@routes.get("/api/eclats/status")
@routes.get("/api/orbs/status")
async def api_eclats_status(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    user_data = auth.get_user_by_id(user["id"])
    eclats_points = user_data.get("eclats_points", 0)
    ads_watched = user_data.get("ads_watched", 0)
    last_daily = user_data.get("last_orbs_daily")
    
    daily_available = True
    next_daily_in_sec = 0
    if last_daily:
        try:
            last_dt = datetime.fromisoformat(last_daily)
            diff = (datetime.utcnow() - last_dt).total_seconds()
            if diff < 86400:
                daily_available = False
                next_daily_in_sec = int(86400 - diff)
        except Exception:
            daily_available = True

    return web.json_response({
        "eclats_points": eclats_points,
        "orbs_points": eclats_points,
        "ads_watched": ads_watched,
        "daily_available": daily_available,
        "next_daily_in_sec": next_daily_in_sec
    })


@routes.post("/api/eclats/watch-ad")
@routes.post("/api/orbs/watch-ad")
async def api_eclats_watch_ad(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = {}
    try:
        data = await request.json()
    except Exception:
        pass
    
    video_id = str(data.get("video_id") or "video_0")
    user_data = auth.get_user_by_id(user["id"])
    inventory = list(user_data.get("inventory") or [])
    
    claimed_key = f"quest_claimed_{video_id}"
    if claimed_key in inventory:
        return web.json_response({
            "error": "Tu as déjà récupéré la récompense pour cette vidéo !",
            "already_claimed": True
        }, status=400)
    
    current_ads = user_data.get("ads_watched", 0)
    is_first_ad = (current_ads == 0)
    points_earned = 500 if is_first_ad else 150

    inventory.append(claimed_key)
    # If this is the MW4/Division/video quest, also unlock nvg_tactical
    if video_id in ["division_trailer", "cod_trailer", "witcher_trailer"]:
        if "nvg_tactical" not in inventory:
            inventory.append("nvg_tactical")

    database.execute("""
        UPDATE users 
        SET ads_watched = ads_watched + 1, 
            orbs_points = orbs_points + ?,
            inventory = ?
        WHERE id = ?
    """, (points_earned, json.dumps(inventory), user["id"]))

    updated_user = auth.get_user_by_id(user["id"])
    await broadcast_to_all({"type": "USER_UPDATED", "user": updated_user})

    return web.json_response({
        "success": True,
        "points_earned": points_earned,
        "is_first_ad": is_first_ad,
        "eclats_points": updated_user["eclats_points"],
        "orbs_points": updated_user["orbs_points"],
        "ads_watched": updated_user["ads_watched"],
        "inventory": updated_user["inventory"],
        "user": updated_user
    })


@routes.post("/api/eclats/claim-daily")
@routes.post("/api/orbs/claim-daily")
async def api_eclats_claim_daily(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    user_data = auth.get_user_by_id(user["id"])
    last_daily = user_data.get("last_orbs_daily")

    if last_daily:
        try:
            last_dt = datetime.fromisoformat(last_daily)
            diff = (datetime.utcnow() - last_dt).total_seconds()
            if diff < 86400:
                hours_left = int((86400 - diff) // 3600)
                mins_left = int(((86400 - diff) % 3600) // 60)
                return web.json_response({
                    "error": f"Récompense déjà récupérée. Reviens dans {hours_left}h {mins_left}m."
                }, status=400)
        except Exception:
            pass

    bonus = 100
    now_iso = datetime.utcnow().isoformat()
    database.execute("""
        UPDATE users 
        SET orbs_points = orbs_points + ?, 
            last_orbs_daily = ? 
        WHERE id = ?
    """, (bonus, now_iso, user["id"]))

    updated_user = auth.get_user_by_id(user["id"])
    await broadcast_to_all({"type": "USER_UPDATED", "user": updated_user})

    return web.json_response({
        "success": True,
        "bonus": bonus,
        "eclats_points": updated_user["eclats_points"],
        "orbs_points": updated_user["orbs_points"],
        "user": updated_user
    })


@routes.post("/api/eclats/grant-test-points")
@routes.post("/api/orbs/grant-test-points")
async def api_eclats_grant_test_points(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    try:
        data = await request.json()
    except Exception:
        data = {}
    
    amount = int(data.get("amount", 2500))
    database.execute("""
        UPDATE users 
        SET orbs_points = orbs_points + ?,
            ads_watched = CASE WHEN ads_watched < 1 THEN 1 ELSE ads_watched END
        WHERE id = ?
    """, (amount, user["id"]))

    updated_user = auth.get_user_by_id(user["id"])
    await broadcast_to_all({"type": "USER_UPDATED", "user": updated_user})

    return web.json_response({
        "success": True,
        "amount": amount,
        "eclats_points": updated_user["eclats_points"],
        "orbs_points": updated_user["orbs_points"],
        "ads_watched": updated_user["ads_watched"],
        "user": updated_user
    })


# ==========================================
# BOUTIQUE DE PROFILS BASTION (SHOP API)
# ==========================================
SHOP_ITEMS = {
    # Avatar decorations
    "dragon_gold": {"name": "Dragon Céleste Doré", "type": "decoration", "price": 1200, "rarity": "legendary"},
    "cyber_visor": {"name": "Visière Tactique Cyber", "type": "decoration", "price": 900, "rarity": "epic"},
    "cat_rgb": {"name": "Casque Audio Chat RGB", "type": "decoration", "price": 850, "rarity": "rare"},
    "nvg_tactical": {"name": "Optique Nocturne NVG", "type": "decoration", "price": 700, "rarity": "rare"},
    "fire_aura": {"name": "Aura Solaire Flamboyante", "type": "decoration", "price": 1000, "rarity": "epic"},
    "magic_portal": {"name": "Vortex Arcanique Améthyste", "type": "decoration", "price": 1100, "rarity": "legendary"},

    # Profile effects (card frame wrapper like Image 2)
    "eclipse_solar": {"name": "Éclipse Solaire Cosmique", "type": "effect", "price": 1400, "rarity": "mythic"},
    "cyber_matrix": {"name": "Matrice Cyber Glitch", "type": "effect", "price": 1350, "rarity": "legendary"},
    "fire_embers": {"name": "Brasier Volcanique", "type": "effect", "price": 1200, "rarity": "epic"},
    "cherry_blossom": {"name": "Cerisiers Sakura", "type": "effect", "price": 1000, "rarity": "epic"},
    "lightning_storm": {"name": "Plasma Électromagnétique", "type": "effect", "price": 1250, "rarity": "epic"},

    # Professional Minimalist Banners
    "banner_obsidian": {"name": "Obsidienne Minimaliste", "type": "banner", "price": 900, "rarity": "rare"},
    "banner_eclipse": {"name": "Éclipse Stellaire Monochrome", "type": "banner", "price": 1100, "rarity": "epic"},
    "banner_tokyo_fog": {"name": "Brume Nocturne de Tokyo", "type": "banner", "price": 1000, "rarity": "rare"},
    "banner_blueprint": {"name": "Schéma Cyber Furtif", "type": "banner", "price": 950, "rarity": "rare"},
    "banner_ink_wave": {"name": "Vague d'Encre Monochrome", "type": "banner", "price": 1050, "rarity": "epic"},
    "banner_slate": {"name": "Crépuscule Ardoise", "type": "banner", "price": 850, "rarity": "rare"},
}


@routes.get("/api/shop/catalog")
async def api_shop_catalog(request):
    return web.json_response({"items": SHOP_ITEMS})


@routes.post("/api/shop/buy")
async def api_shop_buy(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    try:
        data = await request.json()
    except Exception:
        data = {}
        
    item_id = data.get("item_id")
    if not item_id or item_id not in SHOP_ITEMS:
        return web.json_response({"error": "Article introuvable dans la boutique."}, status=404)
    
    item = SHOP_ITEMS[item_id]
    price = item["price"]
    
    inventory = user.get("inventory") or []
    if item_id in inventory:
        return web.json_response({"error": "Tu possèdes déjà cet article !"}, status=400)
    
    user_points = int(user.get("orbs_points") or 0)
    if user_points < price:
        diff = price - user_points
        return web.json_response({
            "error": f"Éclats insuffisants ! Il te manque {diff:,} Éclats.",
            "missing_points": diff
        }, status=400)
    
    new_inventory = list(inventory)
    new_inventory.append(item_id)
    
    database.execute("""
        UPDATE users 
        SET orbs_points = orbs_points - ?,
            inventory = ?
        WHERE id = ?
    """, (price, json.dumps(new_inventory), user["id"]))
    
    updated_user = auth.get_user_by_id(user["id"])
    await broadcast_to_all({"type": "USER_UPDATED", "user": updated_user})
    
    return web.json_response({
        "success": True,
        "item_id": item_id,
        "item": item,
        "user": updated_user,
        "points_spent": price,
        "eclats_points": updated_user["eclats_points"],
        "orbs_points": updated_user["orbs_points"],
        "inventory": updated_user["inventory"]
    })


@routes.post("/api/shop/equip")
async def api_shop_equip(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    try:
        data = await request.json()
    except Exception:
        data = {}
        
    item_id = str(data.get("item_id", "") or "")
    item_type = data.get("item_type")  # 'decoration', 'effect', 'frame', 'banner'
    
    inventory = user.get("inventory") or []
    # Item can be unequipped (empty string) or must be in inventory (or free)
    if item_id and item_id not in inventory:
        return web.json_response({"error": "Tu ne possèdes pas cet article. Achète-le d'abord dans la Boutique !"}, status=403)
    
    if item_type == "decoration":
        database.execute("UPDATE users SET avatar_decoration = ? WHERE id = ?", (item_id, user["id"]))
    elif item_type == "effect":
        database.execute("UPDATE users SET profile_effect = ? WHERE id = ?", (item_id, user["id"]))
    elif item_type == "frame":
        database.execute("UPDATE users SET profile_frame = ? WHERE id = ?", (item_id, user["id"]))
    elif item_type == "banner":
        banner_url = data.get("banner_url", "")
        database.execute("UPDATE users SET banner_url = ? WHERE id = ?", (banner_url, user["id"]))
    else:
        return web.json_response({"error": "Type d'article invalide"}, status=400)
    
    updated_user = auth.get_user_by_id(user["id"])
    await broadcast_to_all({"type": "USER_UPDATED", "user": updated_user})
    return web.json_response({"success": True, "user": updated_user})



@routes.post("/api/auth/reset-password")
async def api_reset_password(request):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    new_password = data.get("new_password", "")

    if not email:
        return web.json_response({"error": "Veuillez renseigner votre adresse e-mail."}, status=400)

    if len(new_password) < 6:
        return web.json_response({"error": "Le nouveau mot de passe doit contenir au moins 6 caractères."}, status=400)

    user_row = database.query_one("SELECT id, username FROM users WHERE LOWER(email) = ?", (email,))
    if not user_row:
        return web.json_response({"error": "Aucun compte associé à cette adresse e-mail."}, status=404)

    new_hash = auth.hash_password(new_password)
    database.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_row["id"]))

    # Generate fresh auth token for immediate seamless login
    token = auth.create_token(user_row["id"], user_row["username"])
    full_user = auth.get_user_by_id(user_row["id"])

    return web.json_response({
        "success": True, 
        "token": token, 
        "user": full_user, 
        "message": "Mot de passe réinitialisé avec succès !"
    })


# ==========================================================
# 2. PANNEAU CEO & GESTION DES BADGES D'ÉQUIPE (EXCLUSIF CEO)
# ==========================================================
@routes.post("/api/admin/users/{user_id}/reset-password")
async def api_admin_reset_user_password(request):
    current_user = get_auth_user(request)
    if not current_user or not auth.is_ceo(current_user):
        return web.json_response({"error": "Accès strictement réservé au CEO BASTION."}, status=403)

    target_user_id = request.match_info["user_id"]
    data = await request.json()
    new_password = data.get("new_password", "")

    if len(new_password) < 6:
        return web.json_response({"error": "Le mot de passe doit contenir au moins 6 caractères."}, status=400)

    target_user = auth.get_user_by_id(target_user_id)
    if not target_user:
        return web.json_response({"error": "Utilisateur introuvable."}, status=404)

    new_hash = auth.hash_password(new_password)
    database.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, target_user_id))

    return web.json_response({
        "success": True,
        "message": f"Mot de passe de {target_user['username']} réinitialisé avec succès !"
    })


@routes.get("/api/admin/users")
async def api_admin_get_users(request):
    current_user = get_auth_user(request)
    if not current_user or not auth.is_ceo(current_user):
        return web.json_response({"error": "Accès strictement réservé au CEO BASTION."}, status=403)

    users_raw = database.query("""
        SELECT id, username, tag, email, avatar_url, banner_color, custom_status, presence_status, global_badges, created_at 
        FROM users 
        ORDER BY created_at ASC
    """)
    return web.json_response({"users": users_raw})


@routes.post("/api/admin/users/{user_id}/badges")
async def api_admin_set_user_badges(request):
    current_user = get_auth_user(request)
    if not current_user or not auth.is_ceo(current_user):
        return web.json_response({"error": "Accès strictement réservé au CEO BASTION."}, status=403)

    target_user_id = request.match_info["user_id"]
    data = await request.json()
    badges = data.get("badges")

    if not isinstance(badges, list):
        return web.json_response({"error": "Format de badges invalide (liste requise)."}, status=400)

    target_user = auth.get_user_by_id(target_user_id)
    if not target_user:
        return web.json_response({"error": "Utilisateur introuvable."}, status=404)

    database.execute("UPDATE users SET global_badges = ? WHERE id = ?", (badges, target_user_id))
    updated_user = auth.get_user_by_id(target_user_id)

    await broadcast_to_all({"type": "USER_UPDATED", "user": updated_user})
    return web.json_response({"success": True, "user": updated_user})


@routes.get("/api/admin/servers")
async def api_admin_get_servers(request):
    current_user = get_auth_user(request)
    if not current_user or not auth.is_ceo(current_user):
        return web.json_response({"error": "Accès strictement réservé au CEO BASTION."}, status=403)

    servers = database.query("""
        SELECT s.*, 
               u.username as owner_username,
               u.tag as owner_tag,
               (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
        FROM servers s
        LEFT JOIN users u ON s.owner_id = u.id
        ORDER BY (CASE WHEN s.id = 'devora-official-community' THEN 0 ELSE 1 END), s.created_at ASC
    """)
    return web.json_response({"servers": servers})


@routes.post("/api/admin/servers/{server_id}/badges")
async def api_admin_set_server_badges(request):
    current_user = get_auth_user(request)
    if not current_user or not auth.is_ceo(current_user):
        return web.json_response({"error": "Accès strictement réservé au CEO BASTION."}, status=403)

    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur introuvable."}, status=404)

    data = await request.json()
    is_official = 1 if data.get("is_official") else 0
    is_partner = 1 if data.get("is_partner") else 0
    
    database.execute("""
        UPDATE servers 
        SET is_official = ?, is_partner = ?
        WHERE id = ?
    """, (is_official, is_partner, server_id))

    updated_server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    await broadcast_to_all({
        "type": "SERVER_UPDATED",
        "server": updated_server
    })
    return web.json_response({"success": True, "server": updated_server})


# ==========================================================
# 3. SERVERS & CHANNELS
# ==========================================================
@routes.get("/api/servers")
async def api_get_servers(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    # Assurer que l'utilisateur a accès au serveur officiel de la communauté
    database.add_user_to_official_server(user["id"])

    servers = database.query("""
        SELECT s.*, 
            (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
        FROM servers s
        INNER JOIN server_members sm ON s.id = sm.server_id
        WHERE sm.user_id = ?
        ORDER BY (CASE WHEN s.id = 'devora-official-community' THEN 0 ELSE 1 END), s.created_at ASC
    """, (user["id"],))

    return web.json_response({"servers": servers})


@routes.post("/api/servers")
async def api_create_server(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    name = data.get("name", "").strip()
    if not name:
        return web.json_response({"error": "Le nom du serveur est obligatoire."}, status=400)
    
    icon_url = data.get("icon_url") or f"https://api.dicebear.com/7.x/identicon/svg?seed={name}"
    description = data.get("description", "")
    banner_url = data.get("banner_url") or "linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4338ca 100%)"
    server_id = str(uuid.uuid4())

    database.execute("INSERT INTO servers (id, name, icon_url, banner_url, description, owner_id) VALUES (?, ?, ?, ?, ?, ?)",
                     (server_id, name, icon_url, banner_url, description, user["id"]))

    # Default Owner Role
    owner_role_id = str(uuid.uuid4())
    database.execute("INSERT INTO roles (id, server_id, name, color, icon, is_badge, permissions, position) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (owner_role_id, server_id, "Owner", "#FEE75C", "👑", 1, ["ADMINISTRATOR"], 0))

    # Add Creator as Member & Assign Owner Role
    database.execute("INSERT INTO server_members (server_id, user_id) VALUES (?, ?)", (server_id, user["id"]))
    database.execute("INSERT INTO member_roles (server_id, user_id, role_id) VALUES (?, ?, ?)", (server_id, user["id"], owner_role_id))

    # Default Channels
    channels = [
        ("général", "text", "Discussion principale"),
        ("annonces", "text", "Annonces officielles"),
        ("Salon Vocal", "voice", "Vocal principal")
    ]
    for idx, (c_name, c_type, c_topic) in enumerate(channels):
        cid = str(uuid.uuid4())
        database.execute("INSERT INTO channels (id, server_id, name, type, topic, position) VALUES (?, ?, ?, ?, ?, ?)",
                         (cid, server_id, c_name, c_type, c_topic, idx))

    # Generate an invite code
    invite_code = f"DEV-{uuid.uuid4().hex[:6].upper()}"
    database.execute("INSERT INTO server_invites (code, server_id, creator_id) VALUES (?, ?, ?)",
                     (invite_code, server_id, user["id"]))

    return web.json_response({
        "id": server_id, 
        "name": name, 
        "icon_url": icon_url, 
        "banner_url": banner_url,
        "description": description, 
        "invite_code": invite_code
    })


@routes.put("/api/servers/{server_id}")
async def api_update_server(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur non trouvé."}, status=404)

    is_ceo = auth.is_ceo(user)
    if server["owner_id"] != user["id"] and not is_ceo:
        return web.json_response({"error": "Seul le propriétaire du serveur peut modifier ces paramètres."}, status=403)

    data = await request.json()
    name = (data.get("name") or server["name"]).strip() or server["name"]
    icon_url = data.get("icon_url") if "icon_url" in data else server.get("icon_url", "")
    description = data.get("description") if "description" in data else server.get("description", "")
    banner_url = data.get("banner_url") if "banner_url" in data else server.get("banner_url", "")
    banner_color = data.get("banner_color") if "banner_color" in data else server.get("banner_color", "#1e293b")
    system_channel_id = data.get("system_channel_id") if "system_channel_id" in data else server.get("system_channel_id", None)
    rules_channel_id = data.get("rules_channel_id") if "rules_channel_id" in data else server.get("rules_channel_id", None)
    announcement_channel_id = data.get("announcement_channel_id") if "announcement_channel_id" in data else server.get("announcement_channel_id", None)
    
    if is_ceo:
        is_official = int(data.get("is_official", server.get("is_official", 0)))
        is_partner = int(data.get("is_partner", server.get("is_partner", 0)))
        is_community = int(data.get("is_community", server.get("is_community", 0)))
        boost_level = int(data.get("boost_level", server.get("boost_level", 0)))
        boost_count = int(data.get("boost_count", server.get("boost_count", 0)))
        server_badge_type = str(data.get("server_badge_type", server.get("server_badge_type", "")))
    else:
        is_official = int(server.get("is_official", 0))
        is_partner = int(server.get("is_partner", 0))
        # Allow owner to toggle community
        is_community = int(data.get("is_community", server.get("is_community", 0)))
        boost_level = int(server.get("boost_level", 0))
        boost_count = int(server.get("boost_count", 0))
        server_badge_type = str(server.get("server_badge_type", ""))

    old_icon = server.get("icon_url") or ""
    old_banner = server.get("banner_url") or ""
    if icon_url and icon_url != old_icon:
        remove_local_upload_file(old_icon)
    if banner_url and banner_url != old_banner:
        remove_local_upload_file(old_banner)

    database.execute("""
        UPDATE servers 
        SET name = ?, icon_url = ?, description = ?, banner_url = ?, banner_color = ?, system_channel_id = ?,
            is_official = ?, is_partner = ?, is_community = ?, boost_level = ?, boost_count = ?, server_badge_type = ?,
            rules_channel_id = ?, announcement_channel_id = ?
        WHERE id = ?
    """, (name, icon_url, description, banner_url, banner_color, system_channel_id,
          is_official, is_partner, is_community, boost_level, boost_count, server_badge_type,
          rules_channel_id, announcement_channel_id, server_id))

    # Synchronize channel types with the newly selected community channels
    if rules_channel_id:
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'rules' AND id != ?", (server_id, rules_channel_id))
        database.execute("UPDATE channels SET type = 'rules' WHERE id = ? AND server_id = ?", (rules_channel_id, server_id))
        database.execute("UPDATE servers SET rules_enabled = 1 WHERE id = ?", (server_id,))
    elif "rules_channel_id" in data and not rules_channel_id:
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'rules'", (server_id,))

    if announcement_channel_id:
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'announcement' AND id != ?", (server_id, announcement_channel_id))
        database.execute("UPDATE channels SET type = 'announcement' WHERE id = ? AND server_id = ?", (announcement_channel_id, server_id))
    elif "announcement_channel_id" in data and not announcement_channel_id:
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'announcement'", (server_id,))

    updated_server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    updated_channels = database.query("SELECT * FROM channels WHERE server_id = ? ORDER BY position ASC", (server_id,))
    await broadcast_to_all({
        "type": "SERVER_UPDATED",
        "server": updated_server,
        "channels": updated_channels
    })

    return web.json_response({"server": updated_server, "updated_channels": updated_channels})


@routes.put("/api/servers/{server_id}/access")
async def api_update_server_access(request):
    """Alias for updating server community access and parameters."""
    return await api_update_server(request)



@routes.post("/api/servers/{server_id}/community/toggle")
async def api_toggle_community(request):
    """Toggle community mode for a server. When enabled, auto-creates special channels."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur non trouvé."}, status=404)

    is_ceo = auth.is_ceo(user)
    if server["owner_id"] != user["id"] and not is_ceo:
        return web.json_response({"error": "Seul le propriétaire peut activer la communauté."}, status=403)

    data = await request.json()
    enable = bool(data.get("enable", False))

    # Update is_community flag
    database.execute("UPDATE servers SET is_community = ? WHERE id = ?", (1 if enable else 0, server_id))

    created_channels = []

    if enable:
        # 1. Clean up any channels that had emoji prefixes or weird names
        like_emoji1 = '📢%'
        like_emoji2 = '📋%'
        like_mises = '%mises-à-jour-communauté%'
        database.execute("DELETE FROM channels WHERE server_id = ? AND (name LIKE ? OR name LIKE ? OR name LIKE ?)", (server_id, like_emoji1, like_emoji2, like_mises))

        # 2. Rules channel: Top-level (category_id = NULL), position = -200
        rules_ch = database.query_one("SELECT id FROM channels WHERE server_id = ? AND (type = 'rules' OR name = 'règles')", (server_id,))
        if not rules_ch:
            r_id = str(uuid.uuid4())
            database.execute(
                "INSERT INTO channels (id, server_id, name, type, topic, category_id, position, is_private) VALUES (?, ?, 'règles', 'rules', 'Règles officielles et charte de bonne conduite de la communauté.', NULL, -200, 0)",
                (r_id, server_id)
            )
            ch = database.query_one("SELECT * FROM channels WHERE id = ?", (r_id,))
            if ch:
                created_channels.append(ch)
            database.execute("UPDATE servers SET rules_channel_id = ?, rules_enabled = 1 WHERE id = ?", (r_id, server_id))
        else:
            # Keep existing channel where it is (respect user's category/position), just ensure type is correct
            database.execute("UPDATE channels SET name = 'règles', type = 'rules' WHERE id = ?", (rules_ch["id"],))
            database.execute("UPDATE servers SET rules_channel_id = ?, rules_enabled = 1 WHERE id = ?", (rules_ch["id"], server_id))

        # 3. Official announcements: Top-level (category_id = NULL), position = -100, private to server creator
        ann_ch = database.query_one("SELECT id FROM channels WHERE server_id = ? AND (type = 'announcement' OR name = 'annonces-officielles')", (server_id,))
        owner_perms = json.dumps([{"userId": server["owner_id"], "canView": True}])
        if not ann_ch:
            a_id = str(uuid.uuid4())
            database.execute(
                "INSERT INTO channels (id, server_id, name, type, topic, category_id, position, is_private, permissions_data) VALUES (?, ?, 'annonces-officielles', 'announcement', 'Salon officiel des mises à jour réservé au créateur du serveur.', NULL, -100, 1, ?)",
                (a_id, server_id, owner_perms)
            )
            ch = database.query_one("SELECT * FROM channels WHERE id = ?", (a_id,))
            if ch:
                created_channels.append(ch)
            database.execute("UPDATE servers SET announcement_channel_id = ? WHERE id = ?", (a_id, server_id))
        else:
            # Keep existing channel where it is (respect user's category/position), just ensure type & privacy are correct
            database.execute("UPDATE channels SET name = 'annonces-officielles', type = 'announcement', is_private = 1, permissions_data = ? WHERE id = ?", (owner_perms, ann_ch["id"]))
            database.execute("UPDATE servers SET announcement_channel_id = ? WHERE id = ?", (ann_ch["id"], server_id))

        # 4. If rules_enabled is not set, enable it and populate default rules if empty
        database.execute("UPDATE servers SET rules_enabled = 1 WHERE id = ? AND rules_enabled = 0", (server_id,))
        existing_rules = database.query_one("SELECT rules_list FROM servers WHERE id = ?", (server_id,))
        raw_r = existing_rules.get("rules_list") if existing_rules else None
        if not raw_r or raw_r in ["[]", '""', "null"]:
            default_rules = [
                {"title": "Respect mutuel & Bienveillance", "description": "Traitez tous les membres avec respect et courtoisie. Les insultes, le harcèlement, les menaces et les discriminations sont strictement interdits."},
                {"title": "Pas de spam ni de publicité non sollicitée", "description": "Ne floodez pas les salons avec des messages répétitifs et ne faites pas de promotion personnelle sans l'accord préalable des modérateurs."},
                {"title": "Contenu approprié", "description": "Tout contenu illégal, explicite, NSFW ou choquant est formellement interdit sur l'ensemble du serveur."},
                {"title": "Respect des thématiques des salons", "description": "Merci d'utiliser les salons textuels et vocaux conformément à leur objet dédié."},
                {"title": "Respect des décisions de modération", "description": "Suivez les directives données par l'équipe de modération et d'administration du serveur."}
            ]
            database.execute("UPDATE servers SET rules_list = ? WHERE id = ?", (json.dumps(default_rules), server_id))

    updated_server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    updated_channels = database.query("SELECT * FROM channels WHERE server_id = ? ORDER BY position ASC", (server_id,))

    # Broadcast updates
    for ch in created_channels:
        await broadcast_to_all({"type": "CHANNEL_CREATED", "serverId": server_id, "channel": ch})

    await broadcast_to_all({"type": "SERVER_UPDATED", "serverId": server_id, "server": updated_server})

    return web.json_response({
        "server": updated_server,
        "created_channels": created_channels,
        "channels": updated_channels,
        "community_enabled": enable
    })


@routes.post("/api/servers/{server_id}/community/create-channel")
async def api_create_community_channel_for_me(request):
    """Automatically creates a designated community channel (rules or announcement) for the server outside any category."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur non trouvé."}, status=404)
    
    is_ceo = auth.is_ceo(user)
    if server["owner_id"] != user["id"] and not is_ceo:
        return web.json_response({"error": "Seul le propriétaire ou un administrateur peut créer ce salon."}, status=403)

    data = await request.json()
    ch_type = data.get("channel_type", "announcement")

    # (No forced cleanup of categories - respect user's organization)

    ch_id = str(uuid.uuid4())
    if ch_type == "rules":
        name = "règles"
        topic = "Règles officielles et charte de bonne conduite de la communauté."
        # Clean up any old duplicate rules channel with emojis
        like_emoji_rules = '📋%'
        database.execute("DELETE FROM channels WHERE server_id = ? AND (name LIKE ? OR (type = 'rules' AND name != 'règles'))", (server_id, like_emoji_rules))
        # Reset any other rules channel to text
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'rules'", (server_id,))
        database.execute(
            "INSERT INTO channels (id, server_id, name, type, topic, category_id, position, is_private) VALUES (?, ?, 'règles', 'rules', ?, NULL, -200, 0)",
            (ch_id, server_id, topic)
        )
        # Ensure default rules are stored in servers table if none exist
        existing_rules = database.query_one("SELECT rules_list FROM servers WHERE id = ?", (server_id,))
        raw_r = existing_rules.get("rules_list") if existing_rules else None
        if not raw_r or raw_r in ["[]", '""', "null"]:
            default_rules = [
                {"title": "Respect mutuel & Bienveillance", "description": "Traitez tous les membres avec respect et courtoisie. Les insultes, le harcèlement, les menaces et les discriminations sont strictement interdits."},
                {"title": "Pas de spam ni de publicité non sollicitée", "description": "Ne floodez pas les salons avec des messages répétitifs et ne faites pas de promotion personnelle sans l'accord préalable des modérateurs."},
                {"title": "Contenu approprié", "description": "Tout contenu illégal, explicite, NSFW ou choquant est formellement interdit sur l'ensemble du serveur."},
                {"title": "Respect des thématiques des salons", "description": "Merci d'utiliser les salons textuels et vocaux conformément à leur objet dédié."},
                {"title": "Respect des décisions de modération", "description": "Suivez les directives données par l'équipe de modération et d'administration du serveur."}
            ]
            database.execute("UPDATE servers SET rules_channel_id = ?, rules_enabled = 1, rules_list = ? WHERE id = ?", (ch_id, json.dumps(default_rules), server_id))
        else:
            database.execute("UPDATE servers SET rules_channel_id = ?, rules_enabled = 1 WHERE id = ?", (ch_id, server_id))
    else:
        name = "annonces-officielles"
        topic = "Salon officiel des mises à jour réservé au créateur du serveur."
        # Clean up any old duplicate announcement channel with emojis or ugly names
        like_emoji_ann = '📢%'
        like_mises_ann = '%mises-à-jour-communauté%'
        database.execute("DELETE FROM channels WHERE server_id = ? AND (name LIKE ? OR name LIKE ?)", (server_id, like_emoji_ann, like_mises_ann))
        # Reset any previous announcement channel to text
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'announcement'", (server_id,))
        # Private channel restricted to the server creator by default
        owner_perms = json.dumps([{"userId": server["owner_id"], "canView": True}])
        database.execute(
            "INSERT INTO channels (id, server_id, name, type, topic, category_id, position, is_private, permissions_data) VALUES (?, ?, 'annonces-officielles', 'announcement', ?, NULL, -100, 1, ?)",
            (ch_id, server_id, topic, owner_perms)
        )
        database.execute("UPDATE servers SET announcement_channel_id = ? WHERE id = ?", (ch_id, server_id))

    new_channel = database.query_one("SELECT * FROM channels WHERE id = ?", (ch_id,))
    updated_server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    channels_list = database.query("SELECT * FROM channels WHERE server_id = ? ORDER BY position ASC", (server_id,))

    await broadcast_to_all({
        "type": "CHANNEL_CREATED",
        "serverId": server_id,
        "channel": new_channel
    })
    await broadcast_to_all({
        "type": "SERVER_UPDATED",
        "serverId": server_id,
        "server": updated_server
    })

    return web.json_response({
        "success": True,
        "channel": new_channel,
        "server": updated_server,
        "channels": channels_list
    })


@routes.post("/api/admin/broadcast-announcement")
async def api_broadcast_announcement(request):
    """Sends an official announcement message in the name of BASTION to community announcement channels."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    if not auth.is_ceo(user):
        return web.json_response({"error": "Action réservée à la direction BASTION."}, status=403)

    data = await request.json()
    title = (data.get("title") or "📢 Mise à jour & Annonce Officielle BASTION").strip()
    content = (data.get("content") or "").strip()
    if not content:
        return web.json_response({"error": "Le contenu de l'annonce ne peut pas être vide."}, status=400)

    category_tag = (data.get("tag") or "MISE À JOUR").strip().upper()
    image_url = (data.get("image_url") or "").strip() or None
    pin_message = bool(data.get("pin", True))
    target = data.get("target", "all")  # 'all' or 'server'
    target_server_id = data.get("server_id")

    database.ensure_bastion_system_user()

    # Determine target servers and their announcement channels
    servers_to_broadcast = []
    if target == "server" and target_server_id:
        srv = database.query_one("SELECT * FROM servers WHERE id = ?", (target_server_id,))
        if srv:
            servers_to_broadcast.append(srv)
    else:
        # All community servers, or all servers
        servers_to_broadcast = database.query("SELECT * FROM servers WHERE is_community = 1 OR id = 'devora-official-community'")
        if not servers_to_broadcast:
            servers_to_broadcast = database.query("SELECT * FROM servers")

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    now_iso = datetime.now().isoformat()

    # Build rich Discord-style announcement embed
    embed_color = "#5865F2"
    if "SÉCURITÉ" in category_tag or "ALERTE" in category_tag:
        embed_color = "#ED4245"
    elif "NOUVEAUTÉ" in category_tag or "EVENT" in category_tag:
        embed_color = "#00F5A0"
    elif "PATCH" in category_tag or "MAJ" in category_tag:
        embed_color = "#FEE75C"

    embed = {
        "title": f"[{category_tag}] {title}",
        "description": content,
        "color": embed_color,
        "author": {
            "name": "BASTION • Communications Officielles",
            "icon_url": "/static/bastion-logo.png"
        },
        "thumbnail": {"url": "/static/bastion-logo.png"},
        "footer": {
            "text": f"Diffusion officielle certifiée par BASTION • Publié par @{user['username']}",
            "icon_url": "/static/bastion-logo.png"
        },
        "timestamp": now_iso
    }
    if image_url:
        embed["image"] = {"url": image_url}

    sent_channels = []
    sent_servers = []

    for srv in servers_to_broadcast:
        # Find designated announcement channel
        ch_id = srv.get("announcement_channel_id")
        ch = None
        if ch_id:
            ch = database.query_one("SELECT * FROM channels WHERE id = ? AND server_id = ?", (ch_id, srv["id"]))
        if not ch:
            # Fallback to a channel of type 'announcement', or system_channel, or first text channel
            ch = database.query_one("SELECT * FROM channels WHERE server_id = ? AND type = 'announcement' LIMIT 1", (srv["id"],))
        if not ch:
            ch = database.query_one("SELECT * FROM channels WHERE server_id = ? AND type = 'text' ORDER BY position ASC LIMIT 1", (srv["id"],))

        if not ch:
            continue

        target_channel_id = ch["id"]
        msg_id = str(uuid.uuid4())

        # System user sends official announcements without cluttering member list

        database.execute("""
            INSERT INTO messages (id, channel_id, server_id, user_id, content, attachment_url, is_pinned, is_bot_message, embeds, created_at)
            VALUES (?, ?, ?, ?, '', NULL, ?, 1, ?, ?)
        """, (msg_id, target_channel_id, srv["id"], database.BASTION_SYSTEM_USER_ID, 1 if pin_message else 0, json.dumps([embed]), now_str))

        created_msg = {
            "id": msg_id,
            "channel_id": target_channel_id,
            "server_id": srv["id"],
            "user_id": database.BASTION_SYSTEM_USER_ID,
            "username": "BASTION",
            "display_name": "BASTION (Officiel)",
            "avatar_url": "/static/bastion-logo.png",
            "is_bot": True,
            "is_verified_bot": True,
            "content": "",
            "embeds": [embed],
            "is_pinned": pin_message,
            "created_at": now_str
        }

        await broadcast_to_channel(target_channel_id, {
            "type": "NEW_MESSAGE",
            "message": created_msg
        })

        sent_channels.append({"channel_name": ch["name"], "server_name": srv["name"], "channel_id": target_channel_id})
        sent_servers.append(srv["name"])

    return web.json_response({
        "success": True,
        "message": f"Annonce BASTION diffusée avec succès à {len(sent_channels)} salon(s) sur {len(sent_servers)} serveur(s) !",
        "count": len(sent_channels),
        "details": sent_channels
    })


@routes.get("/api/servers/{server_id}/integrations")
async def api_get_server_integrations(request):
    """Get bots/integrations installed on this server and Bastion Guard configuration."""
    try:
        user = get_auth_user(request)
        if not user:
            return web.json_response({"error": "Non authentifié"}, status=401)

        server_id = request.match_info["server_id"]
        server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if not server:
            return web.json_response({"error": "Serveur non trouvé."}, status=404)

        # Get all bot members of the server
        bot_members = database.query("""
            SELECT u.id, u.username, u.display_name, u.avatar_url, u.is_verified_bot, u.bot_app_id,
                   a.name as app_name, a.description as app_description, a.is_verified, a.server_count,
                   a.slash_commands, a.permissions_default
            FROM server_members sm
            JOIN users u ON u.id = sm.user_id AND u.is_bot = 1
            LEFT JOIN applications a ON a.bot_user_id = u.id
            WHERE sm.server_id = ?
        """, (server_id,))

        integrations = []
        for bot in bot_members:
            cmds = bot.get("slash_commands")
            if isinstance(cmds, str):
                try:
                    cmds = json.loads(cmds)
                except Exception:
                    cmds = []
            integrations.append({
                "id": bot["id"],
                "name": bot.get("app_name") or bot.get("display_name") or bot["username"],
                "description": bot.get("app_description") or "",
                "avatar_url": bot.get("avatar_url") or "/static/bastion-logo.png",
                "is_verified": bool(bot.get("is_verified", 0)),
                "commands": cmds or [],
                "permissions": bot.get("permissions_default", 8)
            })

        is_guard_present = database.is_protect_in_server(server_id)
        guard_config = database.get_server_protect_config(server_id)
        guard_app = database.get_application_by_id(database.PROTECT_APP_ID)

        return web.json_response({
            "integrations": integrations,
            "protect": {
                "is_present": is_guard_present,
                "config": guard_config,
                "app": guard_app
            }
        })
    except Exception as e:
        import traceback
        print(f"[INTEGRATIONS GET ERROR] {e}")
        traceback.print_exc()
        return web.json_response({"error": str(e)}, status=500)


@routes.post("/api/servers/{server_id}/integrations/protect/add")
async def api_add_protect_to_server(request):
    """Ajoute le bot officiel Bastion Guard au serveur"""
    try:
        user = get_auth_user(request)
        if not user:
            return web.json_response({"error": "Non authentifié"}, status=401)
        server_id = request.match_info["server_id"]
        res = database.add_protect_to_server(server_id, user["id"])
        if not res.get("success"):
            return web.json_response(res, status=400)

        # Message de bienvenue de Protect dans le premier salon textuel
        system_ch = database.query_one("SELECT * FROM channels WHERE server_id = ? AND type = 'text' ORDER BY position ASC LIMIT 1", (server_id,))
        if system_ch:
            msg_id = str(uuid.uuid4())
            welcome_text = "🛡️ **Bastion Guard (Bot Officiel)** est désormais actif sur ce serveur !\nBastion Guard assure la modération 24/7, la protection anti-raid, le système de tickets et l'accueil des membres.\nTapez `/setup` pour ouvrir l'assistant de configuration."
            embeds = [{
                "title": "🛡️ Bastion Guard • En ligne et Opérationnel",
                "description": welcome_text,
                "color": "#5865F2",
                "thumbnail": {"url": "/static/protect-logo.png"},
                "fields": [
                    {"name": "🎟️ Tickets", "value": "Créez vos salons d'assistance privés via `/ticket`", "inline": True},
                    {"name": "👋 Accueil", "value": "Souhaite la bienvenue automatiquement aux nouveaux membres", "inline": True},
                    {"name": "⚙️ Configuration", "value": "Utilisez la commande `/setup` ou allez dans Paramètres > Applications > Intégrations", "inline": False}
                ]
            }]
            components = [{
                "type": 1,
                "components": [
                    {"type": 2, "style": 1, "custom_id": "protect_setup_tickets", "label": "🎟️ Configurer Tickets", "emoji": "🎟️"},
                    {"type": 2, "style": 2, "custom_id": "protect_setup_welcome", "label": "👋 Configurer Accueil", "emoji": "👋"}
                ]
            }]
            database.execute("""
                INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message, embeds, components)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """, (msg_id, system_ch["id"], server_id, database.PROTECT_BOT_USER_ID, "", json_dumps(embeds), json_dumps(components)))

            await broadcast_to_channel(system_ch["id"], {
                "type": "NEW_MESSAGE",
                "message": {
                    "id": msg_id,
                    "channel_id": system_ch["id"],
                    "server_id": server_id,
                    "user_id": database.PROTECT_BOT_USER_ID,
                    "username": "BastionGuard",
                    "display_name": "Bastion Guard (Bot Officiel)",
                    "avatar_url": "/static/protect-logo.png",
                    "is_bot": True,
                    "is_verified_bot": True,
                    "content": "",
                    "embeds": embeds,
                    "components": components,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            })

        await broadcast_to_all({"type": "SERVER_UPDATED", "serverId": server_id})
        return web.json_response(res)
    except Exception as e:
        import traceback
        print(f"[INTEGRATIONS ADD ERROR] {e}")
        traceback.print_exc()
        return web.json_response({"success": False, "error": str(e)}, status=500)


@routes.post("/api/servers/{server_id}/integrations/protect/remove")
async def api_remove_protect_from_server(request):
    """Retire Protect du serveur"""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    res = database.remove_protect_from_server(server_id, user["id"])
    await broadcast_to_all({"type": "SERVER_UPDATED", "serverId": server_id})
    return web.json_response(res)


@routes.post("/api/servers/{server_id}/integrations/protect/config")
async def api_save_protect_config(request):
    """Sauvegarde la configuration Protect d'un serveur"""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    data = await request.json()
    cfg = database.save_server_protect_config(server_id, data)
    return web.json_response({"success": True, "config": cfg})


@routes.post("/api/servers/{server_id}/integrations/protect/send-ticket-panel")
async def api_send_ticket_panel(request):
    """Déploie le panneau de création de tickets Protect dans un salon textuel"""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    data = await request.json()
    channel_id = data.get("channel_id")
    channel = database.query_one("SELECT * FROM channels WHERE id = ? AND server_id = ?", (channel_id, server_id))
    if not channel:
        return web.json_response({"error": "Salon introuvable"}, status=404)

    title = data.get("title") or "📩 Support & Tickets"
    desc = data.get("description") or "Besoin d'aide ou d'une question pour l'équipe du serveur ? Cliquez sur le bouton ci-dessous pour ouvrir un ticket privé avec les modérateurs."

    msg_id = str(uuid.uuid4())
    embeds = [{
        "title": title,
        "description": desc,
        "color": "#5865F2",
        "thumbnail": {"url": "/static/protect-logo.png"},
        "footer": {"text": "Système de Ticket BASTION • Propulsé par Bastion Guard"}
    }]
    components = [{
        "type": 1,
        "components": [
            {
                "type": 2,
                "style": 1,
                "custom_id": "protect_open_ticket",
                "label": "📩 Ouvrir un ticket",
                "emoji": "📩"
            }
        ]
    }]

    database.execute("""
        INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message, embeds, components)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (msg_id, channel_id, server_id, database.PROTECT_BOT_USER_ID, "", json_dumps(embeds), json_dumps(components)))

    msg_obj = {
        "id": msg_id,
        "channel_id": channel_id,
        "server_id": server_id,
        "user_id": database.PROTECT_BOT_USER_ID,
        "username": "BastionGuard",
        "display_name": "Bastion Guard (Bot Officiel)",
        "avatar_url": "/static/protect-logo.png",
        "is_bot": True,
        "is_verified_bot": True,
        "content": "",
        "embeds": embeds,
        "components": components,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    await broadcast_to_channel(channel_id, {
        "type": "NEW_MESSAGE",
        "message": msg_obj
    })

    return web.json_response({"success": True, "message": msg_obj})


@routes.post("/api/servers/{server_id}/tickets/create")
async def api_create_ticket(request):
    """Crée un salon de ticket d'assistance privé pour un utilisateur"""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur non trouvé"}, status=404)

    # Récupérer ou créer la catégorie TICKETS
    ticket_cat = database.query_one("SELECT * FROM channel_categories WHERE server_id = ? AND UPPER(name) = 'TICKETS'", (server_id,))
    if not ticket_cat:
        cat_id = str(uuid.uuid4())
        database.execute("INSERT INTO channel_categories (id, server_id, name, position) VALUES (?, ?, 'TICKETS', 200)", (cat_id, server_id))
        ticket_cat = {"id": cat_id}

    ch_id = str(uuid.uuid4())
    raw_username = re.sub(r'[^a-zA-Z0-9_-]', '', user["username"].lower()) or "membre"
    ch_name = f"ticket-{raw_username[:15]}"
    topic = f"Ticket privé ouvert par @{user['username']} ({user['id']})"

    database.execute("""
        INSERT INTO channels (id, server_id, name, type, topic, is_private, category_id)
        VALUES (?, ?, ?, 'text', ?, 1, ?)
    """, (ch_id, server_id, ch_name, topic, ticket_cat["id"]))

    created_channel = database.query_one("SELECT * FROM channels WHERE id = ?", (ch_id,))

    # Message d'accueil du ticket par Protect
    msg_id = str(uuid.uuid4())
    welcome_ticket = f"Bonjour <@{user['username']}> ! 👋\nMerci d'avoir ouvert un ticket d'assistance. Un membre de l'équipe de modération va prendre en charge votre demande sous peu.\nVeuillez décrire en détail votre question ou votre problème ci-dessous."
    embeds = [{
        "title": f"🎟️ Ticket d'assistance : @{user['username']}",
        "description": welcome_ticket,
        "color": "#5865F2",
        "thumbnail": {"url": "/static/protect-logo.png"},
        "fields": [
            {"name": "Demandeur", "value": f"@{user['username']}", "inline": True},
            {"name": "Date d'ouverture", "value": datetime.now().strftime("%d/%m/%Y %H:%M"), "inline": True}
        ],
        "footer": {"text": "Bastion Guard • Protection & Assistance"}
    }]
    components = [{
        "type": 1,
        "components": [
            {
                "type": 2,
                "style": 4,
                "custom_id": "protect_close_ticket",
                "label": "🔒 Fermer le ticket",
                "emoji": "🔒"
            }
        ]
    }]

    database.execute("""
        INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message, embeds, components)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (msg_id, ch_id, server_id, database.PROTECT_BOT_USER_ID, "", json_dumps(embeds), json_dumps(components)))

    await broadcast_to_all({"type": "CHANNEL_CREATED", "serverId": server_id, "channel": created_channel})

    return web.json_response({"success": True, "channel": created_channel})


@routes.post("/api/servers/{server_id}/tickets/{channel_id}/close")
async def api_close_ticket(request):
    """Ferme et supprime un salon de ticket"""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]

    channel = database.query_one("SELECT * FROM channels WHERE id = ? AND server_id = ?", (channel_id, server_id))
    if not channel:
        return web.json_response({"error": "Salon introuvable"}, status=404)

    database.execute("DELETE FROM messages WHERE channel_id = ?", (channel_id,))
    database.execute("DELETE FROM channels WHERE id = ?", (channel_id,))

    await broadcast_to_all({
        "type": "CHANNEL_DELETED",
        "serverId": server_id,
        "channelId": channel_id
    })

    return web.json_response({"success": True})


@routes.get("/api/discover/bots")
async def api_discover_bots(request):
    """Retourne la liste des bots publics du répertoire d'applications Découvrir"""
    bots = database.query("""
        SELECT a.id as app_id, a.name as name, a.description, a.avatar_url, a.banner_url,
               a.is_verified, a.server_count, a.slash_commands, u.id as bot_user_id, u.username, u.tag
        FROM applications a
        JOIN users u ON a.bot_user_id = u.id
        WHERE a.public_bot = 1 OR a.id = ?
        ORDER BY (CASE WHEN a.id = ? THEN 0 ELSE 1 END), a.server_count DESC
    """, (database.PROTECT_APP_ID, database.PROTECT_APP_ID))

    result = []
    for b in bots:
        cmds = b.get("slash_commands")
        if isinstance(cmds, str):
            try:
                cmds = json.loads(cmds)
            except Exception:
                cmds = []
        result.append({
            "app_id": b["app_id"],
            "bot_user_id": b["bot_user_id"],
            "name": b["name"],
            "username": b["username"],
            "tag": b.get("tag") or "0000",
            "description": b.get("description") or "",
            "avatar_url": b.get("avatar_url") or "/static/protect-logo.png",
            "banner_url": b.get("banner_url") or "",
            "is_verified": bool(b.get("is_verified", 0)),
            "is_official": b["app_id"] == database.PROTECT_APP_ID,
            "server_count": max(1, b.get("server_count", 1)),
            "commands": cmds or []
        })
    return web.json_response({"bots": result})


@routes.delete("/api/servers/{server_id}")
async def api_delete_server(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur non trouvé."}, status=404)

    is_ceo = auth.is_ceo(user)
    if server["owner_id"] != user["id"] and not is_ceo:
        return web.json_response({"error": "Seul le propriétaire du serveur peut supprimer ce serveur."}, status=403)

    if server_id == "devora-official-community" and not is_ceo:
        return web.json_response({"error": "Le serveur officiel de la communauté ne peut pas être supprimé."}, status=403)

    # Clean cascading deletion of child tables to respect foreign keys
    try:
        database.execute("DELETE FROM messages WHERE server_id = ?", (server_id,))
    except Exception:
        pass
    try:
        database.execute("DELETE FROM server_invites WHERE server_id = ?", (server_id,))
    except Exception:
        pass
    try:
        database.execute("DELETE FROM member_roles WHERE server_id = ?", (server_id,))
    except Exception:
        pass
    try:
        database.execute("DELETE FROM server_members WHERE server_id = ?", (server_id,))
    except Exception:
        pass
    try:
        database.execute("DELETE FROM channels WHERE server_id = ?", (server_id,))
    except Exception:
        pass
    try:
        database.execute("DELETE FROM roles WHERE server_id = ?", (server_id,))
    except Exception:
        pass
    try:
        database.execute("DELETE FROM server_emojis WHERE server_id = ?", (server_id,))
    except Exception:
        pass

    # Finally delete the server itself
    database.execute("DELETE FROM servers WHERE id = ?", (server_id,))

    await broadcast_to_all({
        "type": "SERVER_DELETED",
        "serverId": server_id
    })

    return web.json_response({"success": True, "serverId": server_id})


@routes.get("/api/servers/{server_id}")
async def api_get_server_details(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur non trouvé."}, status=404)

    # Check if member
    membership = database.query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
    if not membership:
        return web.json_response({"error": "Vous ne faites pas partie de ce serveur."}, status=403)

    channels = database.query("SELECT * FROM channels WHERE server_id = ? ORDER BY position ASC, created_at ASC", (server_id,))
    roles = database.query("SELECT * FROM roles WHERE server_id = ? ORDER BY position ASC", (server_id,))
    categories = database.query("SELECT * FROM channel_categories WHERE server_id = ? ORDER BY position ASC", (server_id,))
    
    # Members with their user profiles and assigned roles
    members_raw = database.query("""
        SELECT u.id, u.username, u.display_name, u.tag, u.avatar_url, u.banner_color, u.banner_url, u.bio, u.custom_status, 
               u.presence_status, u.global_badges, u.is_bot, u.is_verified_bot, u.bot_app_id,
               u.avatar_decoration, u.profile_effect, u.profile_frame,
               sm.joined_at, sm.nickname, sm.server_avatar_url, sm.server_bio, sm.rules_accepted, sm.rules_accepted_at
        FROM server_members sm
        JOIN users u ON sm.user_id = u.id
        WHERE sm.server_id = ?
        ORDER BY sm.joined_at ASC
    """, (server_id,))

    member_roles_raw = database.query("""
        SELECT mr.user_id, r.id as role_id, r.name as role_name, r.color as role_color, r.icon as role_icon, r.is_badge
        FROM member_roles mr
        JOIN roles r ON mr.role_id = r.id
        WHERE mr.server_id = ?
    """, (server_id,))

    roles_by_user = {}
    for mr in member_roles_raw:
        u_id = mr["user_id"]
        if u_id not in roles_by_user:
            roles_by_user[u_id] = []
        roles_by_user[u_id].append({
            "id": mr["role_id"],
            "name": mr["role_name"],
            "color": mr["role_color"],
            "icon": mr["role_icon"],
            "is_badge": mr["is_badge"]
        })

    members = []
    for m in members_raw:
        m_dict = dict(m)
        m_dict["roles"] = roles_by_user.get(m["id"], [])
        is_bot = bool(m_dict.get("is_bot", 0))
        m_dict["is_bot"] = is_bot
        m_dict["is_verified_bot"] = bool(m_dict.get("is_verified_bot", 0))
        is_connected = (m["id"] in connected_clients and len(connected_clients[m["id"]]) > 0) or is_bot
        m_dict["is_online"] = is_connected and (m_dict.get("presence_status") != "offline")
        members.append(m_dict)

    # Get invite code
    invite = database.query_one("SELECT code FROM server_invites WHERE server_id = ? LIMIT 1", (server_id,))
    invite_code = invite["code"] if invite else None

    # Parse JSON fields for server object
    server_dict = dict(server)
    for json_field in ["rules_list", "discover_tags", "automod_rules", "welcome_channels"]:
        val = server_dict.get(json_field)
        if isinstance(val, str):
            try:
                server_dict[json_field] = json.loads(val)
            except Exception:
                server_dict[json_field] = []

    # Filter visible channels using permission system
    is_server_owner = (server["owner_id"] == user["id"])
    visible_channels = [ch for ch in channels if check_channel_access(user, ch, server, action="view")[0]]

    return web.json_response({
        "server": server_dict,
        "channels": visible_channels,
        "categories": categories,
        "roles": roles,
        "members": members,
        "invite_code": invite_code,
        "is_owner": is_server_owner,
        "membership": dict(membership) if membership else {}
    })


@routes.post("/api/servers/{server_id}/channels")
async def api_create_channel(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    data = await request.json()
    name = data.get("name", "").strip().lower().replace(" ", "-")
    channel_type = data.get("type", "text")
    topic = data.get("topic", "")
    is_private = 1 if data.get("is_private") else 0
    category_id = data.get("category_id", "")

    if not name:
        return web.json_response({"error": "Nom de salon requis."}, status=400)

    cid = str(uuid.uuid4())
    database.execute("INSERT INTO channels (id, server_id, name, type, topic, is_private, category_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (cid, server_id, name, channel_type, topic, is_private, category_id))

    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (cid,))
    database.add_audit_log(server_id, user["id"], "CHANNEL_CREATE", target_name=f"#{name}", details={"type": channel_type})
    await broadcast_to_all({"type": "CHANNEL_CREATED", "serverId": server_id, "channel": channel})
    return web.json_response({"channel": channel})


async def handle_protect_welcome(server_id, user):
    """Envoie automatiquement un message d'accueil de la part de Protect si activé"""
    try:
        if not database.is_protect_in_server(server_id):
            return
        cfg = database.get_server_protect_config(server_id)
        if not cfg.get("welcome_enabled", True):
            return

        server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if not server:
            return

        target_ch_id = cfg.get("welcome_channel_id")
        ch = None
        if target_ch_id:
            ch = database.query_one("SELECT * FROM channels WHERE id = ? AND server_id = ?", (target_ch_id, server_id))
        if not ch:
            ch = database.query_one("SELECT * FROM channels WHERE server_id = ? AND type = 'text' ORDER BY position ASC LIMIT 1", (server_id,))
        if not ch:
            return

        count_row = database.query_one("SELECT COUNT(*) as count FROM server_members WHERE server_id = ?", (server_id,))
        member_count = count_row["count"] if count_row else 1

        template = cfg.get("welcome_message") or "Bienvenue {user} sur **{server}** ! 🎉 Prends connaissance des règles et passe un excellent moment parmi nous."
        welcome_text = template.replace("{user}", f"<@{user.get('username', 'Membre')}>").replace("{server}", server.get("name", "Serveur")).replace("{members}", str(member_count))

        msg_id = str(uuid.uuid4())
        embeds = [{
            "title": f"👋 Bienvenue sur {server.get('name', 'le serveur')} !",
            "description": welcome_text,
            "color": "#5865F2",
            "footer": {"text": "Bastion Guard • Système de Bienvenue officiel"},
            "thumbnail": {"url": user.get("avatar_url") or "/static/bastion-logo.png"}
        }]

        database.execute("""
            INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message, embeds)
            VALUES (?, ?, ?, ?, ?, 1, ?)
        """, (msg_id, ch["id"], server_id, database.PROTECT_BOT_USER_ID, "", json_dumps(embeds)))

        await broadcast_to_channel(ch["id"], {
            "type": "NEW_MESSAGE",
            "message": {
                "id": msg_id,
                "channel_id": ch["id"],
                "server_id": server_id,
                "user_id": database.PROTECT_BOT_USER_ID,
                "username": "BastionGuard",
                "display_name": "Bastion Guard (Bot Officiel)",
                "avatar_url": "/static/protect-logo.png",
                "avatar_url": "/static/protect-logo.png",
                "is_bot": True,
                "is_verified_bot": True,
                "content": "",
                "embeds": embeds,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })
    except Exception as e:
        print(f"[PROTECT WELCOME ERROR] {e}")


@routes.post("/api/servers/join")
async def api_join_server(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    code = data.get("code", "").strip().upper()

    invite = database.query_one("SELECT * FROM server_invites WHERE UPPER(code) = ?", (code,))
    if not invite:
        return web.json_response({"error": "Code d'invitation invalide ou expiré."}, status=404)

    server_id = invite["server_id"]
    
    # Check if already in server
    existing = database.query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
    if not existing:
        database.execute("INSERT INTO server_members (server_id, user_id) VALUES (?, ?)", (server_id, user["id"]))
        database.execute("UPDATE server_invites SET uses = uses + 1 WHERE code = ?", (invite["code"],))
        
        server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        await broadcast_to_all({"type": "MEMBER_JOINED", "serverId": server_id, "userId": user["id"]})
        # Protect welcome trigger
        await handle_protect_welcome(server_id, user)

    return web.json_response({"success": True, "serverId": server_id})


# ==========================================================
# 4. SERVER ROLES & BADGES SYSTEM
# ==========================================================
@routes.post("/api/servers/{server_id}/roles")
async def api_create_role(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    data = await request.json()
    name = data.get("name", "Nouveau Rôle").strip()
    color = data.get("color", "#5865F2")
    icon = data.get("icon", "🛡️")
    is_badge = 1 if data.get("is_badge", True) else 0

    role_id = str(uuid.uuid4())
    database.execute("INSERT INTO roles (id, server_id, name, color, icon, is_badge) VALUES (?, ?, ?, ?, ?, ?)",
                     (role_id, server_id, name, color, icon, is_badge))

    role = database.query_one("SELECT * FROM roles WHERE id = ?", (role_id,))
    database.add_audit_log(server_id, user["id"], "ROLE_CREATE", target_name=f"@{name}", details={"color": color, "icon": icon})
    await broadcast_to_all({"type": "ROLE_CREATED", "serverId": server_id, "role": role})
    return web.json_response({"role": role})


@routes.post("/api/servers/{server_id}/members/{user_id}/roles")
async def api_toggle_member_role(request):
    current_user = get_auth_user(request)
    if not current_user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    target_user_id = request.match_info["user_id"]
    data = await request.json()
    role_id = data.get("role_id")

    # Verify authorization: Server Owner, Server Admin, or Bastion Staff/Moderator
    is_authorized = False
    if auth.is_ceo(current_user):
        is_authorized = True
    else:
        user_badges = current_user.get("global_badges", [])
        if any(b in user_badges for b in ("ceo", "owner", "admin", "moderator", "staff")):
            is_authorized = True
        else:
            server_row = database.query_one("SELECT owner_id FROM servers WHERE id = ?", (server_id,))
            if server_row and server_row.get("owner_id") == current_user["id"]:
                is_authorized = True
            else:
                user_roles = database.query("""
                    SELECT r.permissions, r.name FROM member_roles mr
                    JOIN roles r ON mr.role_id = r.id
                    WHERE mr.server_id = ? AND mr.user_id = ?
                """, (server_id, current_user["id"]))
                for r in user_roles:
                    r_name = (r.get("name") or "").lower()
                    if "admin" in r_name or "modérat" in r_name or "staff" in r_name:
                        is_authorized = True
                        break
                    perms = r.get("permissions") or []
                    if isinstance(perms, str):
                        try: perms = json.loads(perms)
                        except Exception: perms = []
                    if "ADMINISTRATOR" in perms or "MANAGE_ROLES" in perms:
                        is_authorized = True
                        break

    if not is_authorized:
        return web.json_response({
            "error": "Permission refusée. Vous devez être administrateur du serveur ou membre de l'équipe de modération officielle BASTION."
        }, status=403)

    role_info = database.query_one("SELECT name FROM roles WHERE id = ?", (role_id,))
    role_name = role_info["name"] if role_info else role_id

    # Check if assigned
    existing = database.query_one("SELECT * FROM member_roles WHERE server_id = ? AND user_id = ? AND role_id = ?",
                                  (server_id, target_user_id, role_id))
    if existing:
        database.execute("DELETE FROM member_roles WHERE server_id = ? AND user_id = ? AND role_id = ?",
                         (server_id, target_user_id, role_id))
        action = "removed"
    else:
        database.execute("INSERT INTO member_roles (server_id, user_id, role_id) VALUES (?, ?, ?)",
                         (server_id, target_user_id, role_id))
        action = "added"

    database.add_audit_log(server_id, current_user["id"], "MEMBER_ROLE_UPDATE", 
                           target_name=f"Utilisateur {target_user_id}", 
                           details={"action": action, "role_name": role_name})

    await broadcast_to_all({
        "type": "MEMBER_ROLE_UPDATED",
        "serverId": server_id,
        "userId": target_user_id,
        "roleId": role_id,
        "action": action
    })
    return web.json_response({"action": action})


@routes.put("/api/servers/{server_id}/roles/{role_id}")
async def api_update_role(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    role_id = request.match_info["role_id"]
    data = await request.json()
    
    name = data.get("name", "Rôle").strip() or "Rôle"
    color = data.get("color", "#99AAB5")
    icon = data.get("icon", "🛡️")
    is_badge = 1 if data.get("is_badge", True) else 0
    permissions = data.get("permissions", [])
    if not isinstance(permissions, list):
        permissions = []

    database.execute("""
        UPDATE roles 
        SET name = ?, color = ?, icon = ?, is_badge = ?, permissions = ?
        WHERE id = ? AND server_id = ?
    """, (name, color, icon, is_badge, permissions, role_id, server_id))

    role = database.query_one("SELECT * FROM roles WHERE id = ?", (role_id,))
    database.add_audit_log(server_id, user["id"], "ROLE_UPDATE", target_name=f"@{name}", details={"color": color})
    await broadcast_to_all({"type": "ROLE_UPDATED", "serverId": server_id, "role": role})
    return web.json_response({"role": role})


@routes.delete("/api/servers/{server_id}/roles/{role_id}")
async def api_delete_role(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    role_id = request.match_info["role_id"]

    role_info = database.query_one("SELECT name FROM roles WHERE id = ?", (role_id,))
    r_name = role_info["name"] if role_info else role_id

    database.execute("DELETE FROM member_roles WHERE role_id = ? AND server_id = ?", (role_id, server_id))
    database.execute("DELETE FROM roles WHERE id = ? AND server_id = ?", (role_id, server_id))

    database.add_audit_log(server_id, user["id"], "ROLE_DELETE", target_name=f"@{r_name}")
    await broadcast_to_all({"type": "ROLE_DELETED", "serverId": server_id, "roleId": role_id})
    return web.json_response({"success": True})


@routes.put("/api/servers/{server_id}/channels/{channel_id}")
async def api_update_channel(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]
    data = await request.json()

    name = data.get("name", "").strip().lower().replace(" ", "-")
    topic = data.get("topic", "")
    slowmode = int(data.get("slowmode", 0))
    content_visibility = data.get("content_visibility", "default")
    is_announcement = 1 if data.get("is_announcement") else 0
    is_private = 1 if data.get("is_private") else 0

    current_ch = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    current_type = current_ch["type"] if current_ch else "text"
    if is_announcement and current_type == "text":
        new_type = "announcement"
    elif not is_announcement and current_type == "announcement":
        new_type = "text"
    else:
        new_type = current_type

    import json as json_lib
    permissions_data = json_lib.dumps(data.get("permissions_data", []))

    if not name:
        return web.json_response({"error": "Nom de salon requis."}, status=400)

    category_id = data.get("category_id", "")

    database.execute("""UPDATE channels SET name = ?, topic = ?, slowmode = ?, 
        content_visibility = ?, is_announcement = ?, is_private = ?, type = ?,
        permissions_data = ?, category_id = ?
        WHERE id = ? AND server_id = ?""",
        (name, topic, slowmode, content_visibility, is_announcement, is_private, new_type,
         permissions_data, category_id, channel_id, server_id))

    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    database.add_audit_log(server_id, user["id"], "CHANNEL_UPDATE", target_name=f"#{name}")
    await broadcast_to_all({"type": "CHANNEL_UPDATED", "serverId": server_id, "channel": channel})
    return web.json_response({"channel": channel})


@routes.delete("/api/servers/{server_id}/channels/{channel_id}")
async def api_delete_channel(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]

    ch_info = database.query_one("SELECT name FROM channels WHERE id = ?", (channel_id,))
    ch_name = ch_info["name"] if ch_info else channel_id

    database.execute("DELETE FROM messages WHERE channel_id = ?", (channel_id,))
    database.execute("DELETE FROM channels WHERE id = ? AND server_id = ?", (channel_id, server_id))

    database.add_audit_log(server_id, user["id"], "CHANNEL_DELETE", target_name=f"#{ch_name}")
    await broadcast_to_all({"type": "CHANNEL_DELETED", "serverId": server_id, "channelId": channel_id})
    return web.json_response({"success": True})


@routes.get("/api/servers/{server_id}/channels/{channel_id}")
async def api_get_channel(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable."}, status=404)
    allowed, reason = check_channel_access(user, channel, action="view")
    if not allowed:
        return web.json_response({"error": reason or "Accès non autorisé."}, status=403)
    return web.json_response({"channel": channel})


# ==========================================================
# CHANNEL CATEGORIES CRUD
# ==========================================================
@routes.post("/api/servers/{server_id}/categories")
async def api_create_category(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    data = await request.json()
    name = data.get("name", "Nouvelle Catégorie").strip()
    if not name:
        return web.json_response({"error": "Nom de catégorie requis."}, status=400)
    cat_id = str(uuid.uuid4())
    max_pos = database.query_one("SELECT MAX(position) as mp FROM channel_categories WHERE server_id = ?", (server_id,))
    pos = (max_pos["mp"] or 0) + 1 if max_pos else 0
    database.execute("INSERT INTO channel_categories (id, server_id, name, position) VALUES (?, ?, ?, ?)",
                     (cat_id, server_id, name, pos))
    cat = database.query_one("SELECT * FROM channel_categories WHERE id = ?", (cat_id,))
    database.add_audit_log(server_id, user["id"], "CATEGORY_CREATE", target_name=name)
    await broadcast_to_all({"type": "CATEGORY_CREATED", "serverId": server_id, "category": cat})
    return web.json_response({"category": cat})


@routes.put("/api/servers/{server_id}/categories/{category_id}")
async def api_update_category(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    category_id = request.match_info["category_id"]
    data = await request.json()
    name = data.get("name", "").strip()
    if not name:
        return web.json_response({"error": "Nom requis."}, status=400)
    database.execute("UPDATE channel_categories SET name = ? WHERE id = ? AND server_id = ?",
                     (name, category_id, server_id))
    cat = database.query_one("SELECT * FROM channel_categories WHERE id = ?", (category_id,))
    await broadcast_to_all({"type": "CATEGORY_UPDATED", "serverId": server_id, "category": cat})
    return web.json_response({"category": cat})


@routes.delete("/api/servers/{server_id}/categories/{category_id}")
async def api_delete_category(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    category_id = request.match_info["category_id"]
    # Unassign channels from this category
    database.execute("UPDATE channels SET category_id = '' WHERE category_id = ? AND server_id = ?",
                     (category_id, server_id))
    database.execute("DELETE FROM channel_categories WHERE id = ? AND server_id = ?",
                     (category_id, server_id))
    database.add_audit_log(server_id, user["id"], "CATEGORY_DELETE", target_name=category_id)
    await broadcast_to_all({"type": "CATEGORY_DELETED", "serverId": server_id, "categoryId": category_id})
    return web.json_response({"success": True})


@routes.put("/api/servers/{server_id}/channels/{channel_id}/move")
async def api_move_channel(request):
    """Move a channel to a different category."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]
    data = await request.json()
    category_id = data.get("category_id", "")
    position = data.get("position", 0)
    database.execute("UPDATE channels SET category_id = ?, position = ? WHERE id = ? AND server_id = ?",
                     (category_id, position, channel_id, server_id))
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    await broadcast_to_all({"type": "CHANNEL_MOVED", "serverId": server_id, "channel": channel})
    return web.json_response({"channel": channel})


@routes.put("/api/servers/{server_id}/channels/reorder")
async def api_reorder_channels(request):
    """Batch reorder channels in a server or category."""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    data = await request.json()
    channel_orders = data.get("channels", [])
    for item in channel_orders:
        cid = item.get("id")
        pos = item.get("position", 0)
        cat_id = item.get("category_id")
        if cat_id is not None:
            database.execute(
                "UPDATE channels SET position = ?, category_id = ? WHERE id = ? AND server_id = ?",
                (pos, cat_id, cid, server_id)
            )
        else:
            database.execute(
                "UPDATE channels SET position = ? WHERE id = ? AND server_id = ?",
                (pos, cid, server_id)
            )
    await broadcast_to_all({"type": "CHANNELS_REORDERED", "serverId": server_id, "channels": channel_orders})
    return web.json_response({"success": True})


# ==========================================================
# THREADS API
# ==========================================================
@routes.post("/api/servers/{server_id}/channels/{channel_id}/threads")
async def api_create_thread(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable."}, status=404)
    allowed, reason = check_channel_access(user, channel, action="write")
    if not allowed:
        return web.json_response({"error": reason or "Permission refusée."}, status=403)

    data = await request.json()
    message_id = data.get("message_id", "")
    name = data.get("name", "Nouveau fil").strip()
    if not name:
        return web.json_response({"error": "Nom du fil requis."}, status=400)
    thread_id = str(uuid.uuid4())
    database.execute("""
        INSERT INTO threads (id, channel_id, server_id, message_id, name, creator_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (thread_id, channel_id, server_id, message_id, name, user["id"]))
    thread = database.query_one("SELECT * FROM threads WHERE id = ?", (thread_id,))
    database.add_audit_log(server_id, user["id"], "THREAD_CREATE", target_name=name)
    await broadcast_to_all({"type": "THREAD_CREATED", "serverId": server_id, "channelId": channel_id, "thread": thread})
    return web.json_response({"thread": thread})


@routes.get("/api/servers/{server_id}/channels/{channel_id}/threads")
async def api_get_threads(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable."}, status=404)
    allowed, reason = check_channel_access(user, channel, action="view")
    if not allowed:
        return web.json_response({"error": reason or "Accès non autorisé."}, status=403)

    threads = database.query("""
        SELECT t.*, u.username as creator_name, u.avatar_url as creator_avatar
        FROM threads t
        LEFT JOIN users u ON t.creator_id = u.id
        WHERE t.channel_id = ? AND t.is_archived = 0
        ORDER BY t.last_message_at DESC
    """, (channel_id,))
    return web.json_response({"threads": threads})


@routes.get("/api/threads/{thread_id}/messages")
async def api_get_thread_messages(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    thread_id = request.match_info["thread_id"]
    messages = database.query("""
        SELECT tm.*, u.username, u.display_name, u.avatar_url, u.tag
        FROM thread_messages tm
        LEFT JOIN users u ON tm.user_id = u.id
        WHERE tm.thread_id = ?
        ORDER BY tm.created_at ASC
    """, (thread_id,))
    return web.json_response({"messages": messages})


@routes.post("/api/threads/{thread_id}/messages")
async def api_send_thread_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    thread_id = request.match_info["thread_id"]
    data = await request.json()
    content = data.get("content", "").strip()
    if not content:
        return web.json_response({"error": "Contenu requis."}, status=400)
    msg_id = str(uuid.uuid4())
    database.execute("""
        INSERT INTO thread_messages (id, thread_id, user_id, content)
        VALUES (?, ?, ?, ?)
    """, (msg_id, thread_id, user["id"], content))
    database.execute("UPDATE threads SET message_count = message_count + 1, last_message_at = CURRENT_TIMESTAMP WHERE id = ?",
                     (thread_id,))
    msg = database.query_one("""
        SELECT tm.*, u.username, u.display_name, u.avatar_url, u.tag
        FROM thread_messages tm
        LEFT JOIN users u ON tm.user_id = u.id
        WHERE tm.id = ?
    """, (msg_id,))
    thread = database.query_one("SELECT * FROM threads WHERE id = ?", (thread_id,))
    if thread:
        await broadcast_to_all({"type": "THREAD_MESSAGE", "threadId": thread_id, "channelId": thread["channel_id"], "serverId": thread["server_id"], "message": msg})
    return web.json_response({"message": msg})


@routes.put("/api/threads/{thread_id}")
async def api_update_thread(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    thread_id = request.match_info["thread_id"]
    data = await request.json()
    if "is_archived" in data:
        database.execute("UPDATE threads SET is_archived = ? WHERE id = ?", (1 if data["is_archived"] else 0, thread_id))
    if "is_locked" in data:
        database.execute("UPDATE threads SET is_locked = ? WHERE id = ?", (1 if data["is_locked"] else 0, thread_id))
    if "name" in data:
        database.execute("UPDATE threads SET name = ? WHERE id = ?", (data["name"].strip(), thread_id))
    thread = database.query_one("SELECT * FROM threads WHERE id = ?", (thread_id,))
    if thread:
        await broadcast_to_all({"type": "THREAD_UPDATED", "threadId": thread_id, "serverId": thread["server_id"], "thread": thread})
    return web.json_response({"thread": thread})


# ==========================================================
# FORUM CHANNELS API
# ==========================================================

# --- Forum Tags ---
@routes.get("/api/servers/{server_id}/channels/{channel_id}/forum/tags")
async def api_get_forum_tags(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    channel_id = request.match_info["channel_id"]
    tags = database.query("SELECT * FROM forum_tags WHERE channel_id = ? ORDER BY position ASC", (channel_id,))
    return web.json_response({"tags": tags})


@routes.post("/api/servers/{server_id}/channels/{channel_id}/forum/tags")
async def api_create_forum_tag(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]
    data = await request.json()
    name = data.get("name", "").strip()
    if not name:
        return web.json_response({"error": "Nom du tag requis."}, status=400)
    tag_id = str(uuid.uuid4())
    emoji = data.get("emoji", "🏷️")
    color = data.get("color", "#5865F2")
    database.execute("""
        INSERT INTO forum_tags (id, channel_id, server_id, name, emoji, color)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (tag_id, channel_id, server_id, name, emoji, color))
    tag = database.query_one("SELECT * FROM forum_tags WHERE id = ?", (tag_id,))
    await broadcast_to_all({"type": "FORUM_TAG_CREATED", "serverId": server_id, "channelId": channel_id, "tag": tag})
    return web.json_response({"tag": tag})


@routes.delete("/api/servers/{server_id}/channels/{channel_id}/forum/tags/{tag_id}")
async def api_delete_forum_tag(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]
    tag_id = request.match_info["tag_id"]
    database.execute("DELETE FROM forum_tags WHERE id = ?", (tag_id,))
    await broadcast_to_all({"type": "FORUM_TAG_DELETED", "serverId": server_id, "channelId": channel_id, "tagId": tag_id})
    return web.json_response({"success": True})


# --- Forum Posts ---
@routes.get("/api/servers/{server_id}/channels/{channel_id}/forum/posts")
async def api_get_forum_posts(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable."}, status=404)
    allowed, reason = check_channel_access(user, channel, action="view")
    if not allowed:
        return web.json_response({"error": reason or "Accès non autorisé."}, status=403)

    sort = request.query.get("sort", "recent")  # recent, popular, oldest
    tag_filter = request.query.get("tag", "")

    order_clause = "ORDER BY fp.is_pinned DESC, fp.last_reply_at DESC"
    if sort == "popular":
        order_clause = "ORDER BY fp.is_pinned DESC, fp.reply_count DESC"
    elif sort == "oldest":
        order_clause = "ORDER BY fp.is_pinned DESC, fp.created_at ASC"

    posts = database.query(f"""
        SELECT fp.*, u.username as author_name, u.display_name as author_display_name,
               u.avatar_url as author_avatar, u.tag as author_tag
        FROM forum_posts fp
        LEFT JOIN users u ON fp.author_id = u.id
        WHERE fp.channel_id = ?
        {order_clause}
    """, (channel_id,))

    # Parse tags JSON for each post
    import json as json_lib
    for post in posts:
        if isinstance(post.get("tags"), str):
            try:
                post["tags"] = json_lib.loads(post["tags"])
            except Exception:
                post["tags"] = []
        elif post.get("tags") is None:
            post["tags"] = []

    # Apply tag filter client-side
    if tag_filter:
        posts = [p for p in posts if tag_filter in (p.get("tags") or [])]

    tags = database.query("SELECT * FROM forum_tags WHERE channel_id = ? ORDER BY position ASC", (channel_id,))
    return web.json_response({"posts": posts, "tags": tags})


@routes.post("/api/servers/{server_id}/channels/{channel_id}/forum/posts")
async def api_create_forum_post(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable."}, status=404)
    allowed, reason = check_channel_access(user, channel, action="write")
    if not allowed:
        return web.json_response({"error": reason or "Permission refusée."}, status=403)

    data = await request.json()
    title = data.get("title", "").strip()
    content = data.get("content", "").strip()
    tags = data.get("tags", [])
    if not title:
        return web.json_response({"error": "Titre du post requis."}, status=400)
    if not content:
        return web.json_response({"error": "Contenu du post requis."}, status=400)

    import json as json_lib
    post_id = str(uuid.uuid4())
    tags_json = json_lib.dumps(tags) if isinstance(tags, list) else "[]"

    database.execute("""
        INSERT INTO forum_posts (id, channel_id, server_id, author_id, title, content, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (post_id, channel_id, server_id, user["id"], title, content, tags_json))

    post = database.query_one("""
        SELECT fp.*, u.username as author_name, u.display_name as author_display_name,
               u.avatar_url as author_avatar, u.tag as author_tag
        FROM forum_posts fp
        LEFT JOIN users u ON fp.author_id = u.id
        WHERE fp.id = ?
    """, (post_id,))
    if post and isinstance(post.get("tags"), str):
        try:
            post["tags"] = json_lib.loads(post["tags"])
        except Exception:
            post["tags"] = []

    database.add_audit_log(server_id, user["id"], "FORUM_POST_CREATE", target_name=title)
    await broadcast_to_all({"type": "FORUM_POST_CREATED", "serverId": server_id, "channelId": channel_id, "post": post})
    return web.json_response({"post": post})


@routes.get("/api/servers/{server_id}/forum/posts/{post_id}")
async def api_get_forum_post(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    post_id = request.match_info["post_id"]
    post = database.query_one("""
        SELECT fp.*, u.username as author_name, u.display_name as author_display_name,
               u.avatar_url as author_avatar, u.tag as author_tag
        FROM forum_posts fp
        LEFT JOIN users u ON fp.author_id = u.id
        WHERE fp.id = ?
    """, (post_id,))
    if not post:
        return web.json_response({"error": "Post introuvable."}, status=404)

    import json as json_lib
    if isinstance(post.get("tags"), str):
        try:
            post["tags"] = json_lib.loads(post["tags"])
        except Exception:
            post["tags"] = []

    replies = database.query("""
        SELECT fr.*, u.username as author_name, u.display_name as author_display_name,
               u.avatar_url as author_avatar, u.tag as author_tag
        FROM forum_replies fr
        LEFT JOIN users u ON fr.author_id = u.id
        WHERE fr.post_id = ?
        ORDER BY fr.is_solution DESC, fr.created_at ASC
    """, (post_id,))

    return web.json_response({"post": post, "replies": replies})


@routes.put("/api/servers/{server_id}/forum/posts/{post_id}")
async def api_update_forum_post(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    post_id = request.match_info["post_id"]
    post = database.query_one("SELECT * FROM forum_posts WHERE id = ?", (post_id,))
    if not post:
        return web.json_response({"error": "Post introuvable."}, status=404)

    data = await request.json()
    if "is_pinned" in data:
        database.execute("UPDATE forum_posts SET is_pinned = ? WHERE id = ?", (1 if data["is_pinned"] else 0, post_id))
    if "is_locked" in data:
        database.execute("UPDATE forum_posts SET is_locked = ? WHERE id = ?", (1 if data["is_locked"] else 0, post_id))
    if "is_solved" in data:
        database.execute("UPDATE forum_posts SET is_solved = ? WHERE id = ?", (1 if data["is_solved"] else 0, post_id))

    updated = database.query_one("""
        SELECT fp.*, u.username as author_name, u.display_name as author_display_name,
               u.avatar_url as author_avatar, u.tag as author_tag
        FROM forum_posts fp LEFT JOIN users u ON fp.author_id = u.id WHERE fp.id = ?
    """, (post_id,))

    import json as json_lib
    if updated and isinstance(updated.get("tags"), str):
        try:
            updated["tags"] = json_lib.loads(updated["tags"])
        except Exception:
            updated["tags"] = []

    await broadcast_to_all({"type": "FORUM_POST_UPDATED", "serverId": server_id, "post": updated})
    return web.json_response({"post": updated})


@routes.delete("/api/servers/{server_id}/forum/posts/{post_id}")
async def api_delete_forum_post(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    post_id = request.match_info["post_id"]
    post = database.query_one("SELECT * FROM forum_posts WHERE id = ?", (post_id,))
    if not post:
        return web.json_response({"error": "Post introuvable."}, status=404)
    # Only author or server owner can delete
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if post["author_id"] != user["id"] and (not server or server["owner_id"] != user["id"]):
        return web.json_response({"error": "Non autorisé."}, status=403)

    database.execute("DELETE FROM forum_replies WHERE post_id = ?", (post_id,))
    database.execute("DELETE FROM forum_posts WHERE id = ?", (post_id,))
    database.add_audit_log(server_id, user["id"], "FORUM_POST_DELETE", target_name=post.get("title", ""))
    await broadcast_to_all({"type": "FORUM_POST_DELETED", "serverId": server_id, "channelId": post["channel_id"], "postId": post_id})
    return web.json_response({"success": True})


# --- Forum Replies ---
@routes.post("/api/servers/{server_id}/forum/posts/{post_id}/replies")
async def api_create_forum_reply(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    post_id = request.match_info["post_id"]
    post = database.query_one("SELECT * FROM forum_posts WHERE id = ?", (post_id,))
    if not post:
        return web.json_response({"error": "Post introuvable."}, status=404)
    if post.get("is_locked"):
        return web.json_response({"error": "Ce post est verrouillé."}, status=403)

    data = await request.json()
    content = data.get("content", "").strip()
    if not content:
        return web.json_response({"error": "Contenu requis."}, status=400)

    reply_id = str(uuid.uuid4())
    database.execute("""
        INSERT INTO forum_replies (id, post_id, author_id, content)
        VALUES (?, ?, ?, ?)
    """, (reply_id, post_id, user["id"], content))

    database.execute("""
        UPDATE forum_posts SET reply_count = reply_count + 1, last_reply_at = CURRENT_TIMESTAMP WHERE id = ?
    """, (post_id,))

    reply = database.query_one("""
        SELECT fr.*, u.username as author_name, u.display_name as author_display_name,
               u.avatar_url as author_avatar, u.tag as author_tag
        FROM forum_replies fr LEFT JOIN users u ON fr.author_id = u.id WHERE fr.id = ?
    """, (reply_id,))

    await broadcast_to_all({"type": "FORUM_REPLY_CREATED", "serverId": server_id, "channelId": post["channel_id"], "postId": post_id, "reply": reply})
    return web.json_response({"reply": reply})


@routes.put("/api/servers/{server_id}/forum/replies/{reply_id}/solution")
async def api_mark_solution(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    reply_id = request.match_info["reply_id"]
    reply = database.query_one("SELECT * FROM forum_replies WHERE id = ?", (reply_id,))
    if not reply:
        return web.json_response({"error": "Réponse introuvable."}, status=404)
    post = database.query_one("SELECT * FROM forum_posts WHERE id = ?", (reply["post_id"],))
    if not post or post["author_id"] != user["id"]:
        server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if not server or server["owner_id"] != user["id"]:
            return web.json_response({"error": "Seul l'auteur du post peut marquer une solution."}, status=403)

    # Unmark all other solutions first
    database.execute("UPDATE forum_replies SET is_solution = 0 WHERE post_id = ?", (reply["post_id"],))
    database.execute("UPDATE forum_replies SET is_solution = 1 WHERE id = ?", (reply_id,))
    database.execute("UPDATE forum_posts SET is_solved = 1 WHERE id = ?", (reply["post_id"],))

    await broadcast_to_all({"type": "FORUM_SOLUTION_MARKED", "serverId": server_id, "postId": reply["post_id"], "replyId": reply_id})
    return web.json_response({"success": True})


@routes.put("/api/servers/{server_id}/access")
async def api_update_server_access(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server or server["owner_id"] != user["id"]:
        return web.json_response({"error": "Non autorisé."}, status=403)

    data = await request.json()
    access_mode = data.get("access_mode", "invite_only")
    age_restricted = 1 if data.get("age_restricted") else 0
    rules_enabled = 1 if data.get("rules_enabled") else 0
    import json as json_lib
    rules_list = json_lib.dumps(data.get("rules_list", []))
    
    banner_url = data.get("banner_url", "")
    description = data.get("description", "")
    discover_description = data.get("discover_description") or description
    raw_tags = data.get("discover_tags", [])
    if isinstance(raw_tags, list):
        discover_tags = json_lib.dumps(raw_tags[:2])
    elif isinstance(raw_tags, str):
        try:
            parsed = json_lib.loads(raw_tags)
            discover_tags = json_lib.dumps(parsed[:2] if isinstance(parsed, list) else [])
        except Exception:
            discover_tags = "[]"
    else:
        discover_tags = "[]"
    category = data.get("category", "community")
    welcome_enabled = 1 if data.get("welcome_enabled") else 0
    welcome_message = data.get("welcome_message", "").strip()
    raw_welcome_channels = data.get("welcome_channels", [])
    if isinstance(raw_welcome_channels, list):
        welcome_channels = json_lib.dumps(raw_welcome_channels)
    elif isinstance(raw_welcome_channels, str):
        welcome_channels = raw_welcome_channels
    else:
        welcome_channels = "[]"

    rules_channel_id = data.get("rules_channel_id")
    if rules_channel_id == "":
        rules_channel_id = None
        
    announcement_channel_id = data.get("announcement_channel_id")
    if announcement_channel_id == "":
        announcement_channel_id = None

    database.execute("""UPDATE servers SET 
        access_mode = ?, age_restricted = ?, rules_enabled = ?, rules_list = ?,
        banner_url = ?, description = ?, discover_description = ?, discover_tags = ?, category = ?,
        welcome_enabled = ?, welcome_message = ?, welcome_channels = ?,
        rules_channel_id = ?, announcement_channel_id = ?
        WHERE id = ?""",
        (access_mode, age_restricted, rules_enabled, rules_list,
         banner_url, description, discover_description, discover_tags, category,
         welcome_enabled, welcome_message, welcome_channels,
         rules_channel_id, announcement_channel_id, server_id))

    # Convert the selected rules channel to type 'rules'
    if rules_channel_id:
        database.execute("UPDATE channels SET type = 'rules' WHERE id = ? AND server_id = ?", (rules_channel_id, server_id))
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'rules' AND id != ?", (server_id, rules_channel_id))
    else:
        # If deselected, revert old rules channels to 'text'
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'rules'", (server_id,))

    # Convert the selected announcements channel to type 'announcement'
    if announcement_channel_id:
        database.execute("UPDATE channels SET type = 'announcement' WHERE id = ? AND server_id = ?", (announcement_channel_id, server_id))
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'announcement' AND id != ?", (server_id, announcement_channel_id))
    else:
        # If deselected, revert old announcement channels to 'text'
        database.execute("UPDATE channels SET type = 'text' WHERE server_id = ? AND type = 'announcement'", (server_id,))

    updated = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    updated_channels = database.query("SELECT * FROM channels WHERE server_id = ? ORDER BY position ASC", (server_id,))

    # Broadcast access, server & channels update
    await broadcast_to_all({
        "type": "SERVER_UPDATED",
        "serverId": server_id,
        "server": dict(updated) if updated else {},
        "channels": updated_channels
    })
    await broadcast_to_all({
        "type": "SERVER_ACCESS_UPDATED",
        "serverId": server_id,
        "server": dict(updated) if updated else {}
    })
    return web.json_response({"server": updated, "channels": updated_channels})


@routes.put("/api/servers/{server_id}/profile")
async def api_update_server_profile(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    membership = database.query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
    if not membership:
        return web.json_response({"error": "Vous ne faites pas partie de ce serveur."}, status=403)
    
    data = await request.json()
    nickname = (data.get("nickname") or "").strip()[:50] or None
    server_avatar_url = (data.get("server_avatar_url") or "").strip() or None
    server_bio = (data.get("server_bio") or "").strip()[:255] or None

    database.execute("""
        UPDATE server_members
        SET nickname = ?, server_avatar_url = ?, server_bio = ?
        WHERE server_id = ? AND user_id = ?
    """, (nickname, server_avatar_url, server_bio, server_id, user["id"]))

    updated_mem = database.query_one("""
        SELECT u.id, u.username, u.display_name, u.tag, u.avatar_url, u.banner_color, u.banner_url, u.bio, u.custom_status,
               u.presence_status, u.global_badges, u.is_bot, u.is_verified_bot, u.bot_app_id,
               u.avatar_decoration, u.profile_effect, u.profile_frame,
               sm.joined_at, sm.nickname, sm.server_avatar_url, sm.server_bio, sm.rules_accepted, sm.rules_accepted_at
        FROM server_members sm
        JOIN users u ON sm.user_id = u.id
        WHERE sm.server_id = ? AND sm.user_id = ?
    """, (server_id, user["id"]))

    await broadcast_to_all({
        "type": "MEMBER_PROFILE_UPDATED",
        "serverId": server_id,
        "userId": user["id"],
        "nickname": nickname,
        "server_avatar_url": server_avatar_url,
        "server_bio": server_bio,
        "member": dict(updated_mem) if updated_mem else {}
    })

    return web.json_response({"success": True, "member": dict(updated_mem) if updated_mem else {}})


@routes.post("/api/servers/{server_id}/accept-rules")
async def api_accept_server_rules(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    membership = database.query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
    if not membership:
        return web.json_response({"error": "Vous ne faites pas partie de ce serveur."}, status=403)
    
    database.execute("""
        UPDATE server_members
        SET rules_accepted = 1, rules_accepted_at = CURRENT_TIMESTAMP
        WHERE server_id = ? AND user_id = ?
    """, (server_id, user["id"]))

    database.add_audit_log(server_id, user["id"], "MEMBER_RULES_ACCEPTED", target_name=user.get("username", "Membre"), details={"user_id": user["id"]})

    await broadcast_to_all({
        "type": "MEMBER_RULES_ACCEPTED",
        "serverId": server_id,
        "userId": user["id"]
    })

    return web.json_response({"success": True, "rules_accepted": 1})


@routes.get("/api/servers/{server_id}/invites")
async def api_get_server_invites(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    invites = database.query("""
        SELECT si.*, u.username as creator_name, u.avatar_url as creator_avatar
        FROM server_invites si
        LEFT JOIN users u ON si.creator_id = u.id
        WHERE si.server_id = ?
        ORDER BY si.created_at DESC
    """, (server_id,))
    return web.json_response({"invites": invites})


@routes.get("/api/discover/servers")
async def api_discover_servers(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    # Get all servers with access_mode = 'discovery'
    servers = database.query("""
        SELECT s.*, 
            (SELECT COUNT(*) FROM server_members WHERE server_id = s.id) as member_count,
            (SELECT COUNT(*) FROM channels WHERE server_id = s.id) as channel_count
        FROM servers s
        WHERE s.access_mode = 'discovery'
        ORDER BY member_count DESC
    """)
    
    import json as json_lib
    result = []
    for s in servers:
        tags = []
        raw_tags = s.get("discover_tags") or "[]"
        try:
            tags = json_lib.loads(raw_tags) if isinstance(raw_tags, str) else raw_tags
        except Exception:
            tags = []
            
        rules = []
        raw_rules = s.get("rules_list") or "[]"
        try:
            rules = json_lib.loads(raw_rules) if isinstance(raw_rules, str) else raw_rules
        except Exception:
            rules = []

        result.append({
            "id": s["id"],
            "name": s["name"],
            "icon": s.get("icon_url") or s.get("icon") or s.get("avatar_url") or "",
            "description": s.get("discover_description") or s.get("description") or "",
            "banner_url": s.get("banner_url") or "",
            "banner_color": s.get("banner_color") or "",
            "category": s.get("category") or "community",
            "tags": tags[:2] if isinstance(tags, list) else [],
            "age_restricted": s.get("age_restricted", 0),
            "rules_enabled": s.get("rules_enabled", 0),
            "rules_list": rules if isinstance(rules, list) else [],
            "is_official": s.get("is_official", 0),
            "is_partner": s.get("is_partner", 0),
            "boost_level": s.get("boost_level", 0),
            "server_badge_type": s.get("server_badge_type", ""),
            "member_count": s.get("member_count", 0),
            "channel_count": s.get("channel_count", 0),
            "created_at": str(s.get("created_at") or "")
        })
    
    return web.json_response({"servers": result})


@routes.post("/api/servers/{server_id}/join")
async def api_join_server(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    
    # Check server exists
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur introuvable."}, status=404)

    # Check if already a member
    existing = database.query_one(
        "SELECT * FROM server_members WHERE server_id = ? AND user_id = ?",
        (server_id, user["id"])
    )
    if existing:
        return web.json_response({"success": True, "already_member": True, "message": "Tu es déjà membre de ce serveur.", "server": server})
    
    database.execute(
        "INSERT INTO server_members (server_id, user_id) VALUES (?, ?)",
        (server_id, user["id"])
    )
    
    await broadcast_to_all({
        "type": "MEMBER_JOINED",
        "serverId": server_id,
        "user": {"id": user["id"], "username": user["username"]}
    })
    
    # Protect welcome trigger
    await handle_protect_welcome(server_id, user)
    
    return web.json_response({"success": True, "already_member": False, "server": server})


# ==========================================================
# 3.1. SERVER AUDIT LOGS, MODERATION & AUTOMOD
# ==========================================================
@routes.get("/api/servers/{server_id}/audit-logs")
async def api_get_server_audit_logs(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur non trouvé"}, status=404)
    membership = database.query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
    if not membership:
        return web.json_response({"error": "Non membre de ce serveur"}, status=403)
    
    logs = database.get_server_audit_logs(server_id, limit=100)
    return web.json_response({"audit_logs": logs})


@routes.post("/api/servers/{server_id}/members/{user_id}/kick")
async def api_kick_member(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    target_user_id = request.match_info["user_id"]
    data = await request.json() if request.can_read_body else {}
    reason = data.get("reason", "Expulsé par un modérateur")

    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur introuvable"}, status=404)
    if str(target_user_id) == str(server["owner_id"]):
        return web.json_response({"error": "Impossible d'expulser le propriétaire du serveur"}, status=403)

    target_user = auth.get_user_by_id(target_user_id)
    target_name = target_user["username"] if target_user else f"Utilisateur {target_user_id}"

    database.execute("DELETE FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, target_user_id))
    database.execute("DELETE FROM member_roles WHERE server_id = ? AND user_id = ?", (server_id, target_user_id))
    
    database.add_audit_log(server_id, user["id"], "MEMBER_KICK", target_name=target_name, reason=reason)

    await broadcast_to_all({
        "type": "MEMBER_KICKED",
        "serverId": server_id,
        "userId": target_user_id
    })
    return web.json_response({"success": True})


@routes.post("/api/servers/{server_id}/members/{user_id}/ban")
async def api_ban_member(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    target_user_id = request.match_info["user_id"]
    data = await request.json() if request.can_read_body else {}
    reason = data.get("reason", "Banni par un modérateur")

    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur introuvable"}, status=404)
    if str(target_user_id) == str(server["owner_id"]):
        return web.json_response({"error": "Impossible de bannir le propriétaire du serveur"}, status=403)

    target_user = auth.get_user_by_id(target_user_id)
    target_name = target_user["username"] if target_user else f"Utilisateur {target_user_id}"

    database.execute("DELETE FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, target_user_id))
    database.execute("DELETE FROM member_roles WHERE server_id = ? AND user_id = ?", (server_id, target_user_id))

    database.add_audit_log(server_id, user["id"], "MEMBER_BAN", target_name=target_name, reason=reason)

    await broadcast_to_all({
        "type": "MEMBER_BANNED",
        "serverId": server_id,
        "userId": target_user_id
    })
    return web.json_response({"success": True})


@routes.get("/api/servers/{server_id}/automod")
async def api_get_server_automod(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT automod_rules FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur introuvable"}, status=404)
    rules_raw = server.get("automod_rules")
    if isinstance(rules_raw, str):
        try:
            rules = json.loads(rules_raw)
        except Exception:
            rules = []
    elif isinstance(rules_raw, list):
        rules = rules_raw
    else:
        rules = []
    return web.json_response({"automod_rules": rules})


@routes.post("/api/servers/{server_id}/automod")
async def api_save_server_automod(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    data = await request.json()
    rules = data.get("automod_rules", [])
    if not isinstance(rules, list):
        rules = []
    rules_json = json.dumps(rules)
    database.execute("UPDATE servers SET automod_rules = ? WHERE id = ?", (rules_json, server_id))
    database.add_audit_log(server_id, user["id"], "AUTOMOD_UPDATE", target_name="Règles AutoMod", details={"rules_count": len(rules)})
    return web.json_response({"success": True, "automod_rules": rules})


UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@routes.post("/api/upload")
async def api_upload_file(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    category = request.query.get("category", "attachment").lower()

    reader = await request.multipart()
    field = await reader.next()
    if not field or not field.filename:
        return web.json_response({"error": "Aucun fichier sélectionné."}, status=400)

    filename = field.filename
    ext = os.path.splitext(filename)[1].lower().lstrip(".")
    
    video_exts = {"mp4", "webm", "mov", "mkv", "avi"}
    doc_exts = {"pdf", "txt", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "zip", "rar", "7z", "tar", "gz", "json", "csv", "py", "js", "html", "css", "md"}
    audio_exts = {"mp3", "wav", "ogg", "m4a", "aac", "flac"}
    image_exts = {"png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico"}

    # BASTION Ultra-Upload : 250 Mo gratuit pour tout type de fichier (surpasse largement Discord)
    max_size = 250 * 1024 * 1024
    if ext in video_exts:
        file_type = "video"
    elif ext in doc_exts:
        file_type = "document"
    elif ext in audio_exts:
        file_type = "audio"
    elif ext in image_exts:
        file_type = "image"
    else:
        file_type = "document"

    clean_base = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    if category == "avatar":
        target_dir = UPLOAD_AVATARS_DIR
        safe_name = f"avatar_{uuid.uuid4().hex[:10]}_{clean_base}"
        rel_url = f"/static/uploads/avatars/{safe_name}"
    elif category == "banner":
        target_dir = UPLOAD_BANNERS_DIR
        safe_name = f"banner_{uuid.uuid4().hex[:10]}_{clean_base}"
        rel_url = f"/static/uploads/banners/{safe_name}"
    elif category == "server_icon":
        target_dir = UPLOAD_SERVER_ICONS_DIR
        safe_name = f"sicon_{uuid.uuid4().hex[:10]}_{clean_base}"
        rel_url = f"/static/uploads/server_icons/{safe_name}"
    elif category == "server_banner":
        target_dir = UPLOAD_SERVER_BANNERS_DIR
        safe_name = f"sbanner_{uuid.uuid4().hex[:10]}_{clean_base}"
        rel_url = f"/static/uploads/server_banners/{safe_name}"
    else:
        target_dir = UPLOAD_ATTACHMENTS_DIR
        safe_name = f"att_{uuid.uuid4().hex[:10]}_{clean_base}"
        rel_url = f"/static/uploads/attachments/{safe_name}"

    file_path = os.path.join(target_dir, safe_name)

    size = 0
    with open(file_path, "wb") as f:
        while True:
            chunk = await field.read_chunk(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_size:
                f.close()
                try:
                    os.remove(file_path)
                except Exception:
                    pass
                limit_str = "100 Mo pour les vidéos" if file_type == "video" else "30 Mo pour les documents"
                return web.json_response({"error": f"Fichier trop volumineux. La limite est de {limit_str}."}, status=400)
            f.write(chunk)

    if size < 1024 * 1024:
        size_formatted = f"{size / 1024:.1f} Ko"
    else:
        size_formatted = f"{size / (1024 * 1024):.1f} Mo"

    return web.json_response({
        "url": rel_url,
        "filename": filename,
        "size": size,
        "size_formatted": size_formatted,
        "file_type": file_type,
        "category": category,
        "ext": ext
    })


@routes.post("/api/servers/{server_id}/invites")
async def api_create_server_invite(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    code = f"DEV-{uuid.uuid4().hex[:6].upper()}"

    database.execute("INSERT INTO server_invites (code, server_id, creator_id, uses, max_uses) VALUES (?, ?, ?, 0, 0)",
                     (code, server_id, user["id"]))

    invite = database.query_one("SELECT * FROM server_invites WHERE code = ?", (code,))
    return web.json_response({"invite": invite})


@routes.delete("/api/servers/{server_id}/invites/{code}")
async def api_delete_server_invite(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    code = request.match_info["code"]
    database.execute("DELETE FROM server_invites WHERE code = ? AND server_id = ?", (code, server_id))
    return web.json_response({"success": True})


@routes.delete("/api/servers/{server_id}/members/{user_id}")
async def api_kick_member(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    target_user_id = request.match_info["user_id"]
    
    target_user = auth.get_user_by_id(target_user_id)
    target_name = target_user["username"] if target_user else f"Utilisateur {target_user_id}"

    database.execute("DELETE FROM member_roles WHERE server_id = ? AND user_id = ?", (server_id, target_user_id))
    database.execute("DELETE FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, target_user_id))

    database.add_audit_log(server_id, user["id"], "MEMBER_KICK", target_name=target_name, reason="Expulsé par un modérateur")

    await broadcast_to_all({"type": "MEMBER_KICKED", "serverId": server_id, "userId": target_user_id})
    return web.json_response({"success": True})


@routes.get("/api/servers/{server_id}/emojis")
async def api_get_server_emojis(request):
    server_id = request.match_info["server_id"]
    emojis = database.query("SELECT * FROM emojis WHERE server_id = ? ORDER BY created_at DESC", (server_id,))
    return web.json_response({"emojis": emojis})


@routes.post("/api/servers/{server_id}/emojis")
async def api_create_server_emoji(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    data = await request.json()
    name = data.get("name", "").strip().replace(":", "")
    image_url = data.get("image_url", "").strip()
    if not name or not image_url:
        return web.json_response({"error": "Nom et URL d'image requis pour l'émoji."}, status=400)
    
    emoji_id = str(uuid.uuid4())
    database.execute("INSERT INTO emojis (id, server_id, name, image_url, creator_id) VALUES (?, ?, ?, ?, ?)",
                     (emoji_id, server_id, name, image_url, user["id"]))
    emoji = database.query_one("SELECT * FROM emojis WHERE id = ?", (emoji_id,))
    return web.json_response({"emoji": emoji})


@routes.delete("/api/servers/{server_id}/emojis/{emoji_id}")
async def api_delete_server_emoji(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    emoji_id = request.match_info["emoji_id"]
    database.execute("DELETE FROM emojis WHERE id = ? AND server_id = ?", (emoji_id, server_id))
    return web.json_response({"success": True})


# ==========================================================
# SOUNDBOARD API
# ==========================================================
@routes.get("/api/servers/{server_id}/soundboard")
async def api_get_server_soundboard(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    sounds = database.query("SELECT * FROM soundboard_sounds WHERE server_id = ? ORDER BY created_at ASC", (server_id,))
    return web.json_response({"sounds": sounds or []})


@routes.post("/api/servers/{server_id}/soundboard")
async def api_create_server_sound(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    data = await request.json()
    name = (data.get("name") or "").strip()
    audio_url = (data.get("audio_url") or "").strip()
    emoji = (data.get("emoji") or "🔊").strip()
    volume = float(data.get("volume", 1.0))
    if not name or not audio_url:
        return web.json_response({"error": "Nom et URL audio requis."}, status=400)
    
    sound_id = str(uuid.uuid4())
    database.execute("""
        INSERT INTO soundboard_sounds (id, server_id, user_id, name, emoji, audio_url, volume)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (sound_id, server_id, user["id"], name, emoji, audio_url, volume))
    sound = database.query_one("SELECT * FROM soundboard_sounds WHERE id = ?", (sound_id,))
    return web.json_response({"sound": sound})


@routes.delete("/api/servers/{server_id}/soundboard/{sound_id}")
async def api_delete_server_sound(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    sound_id = request.match_info["sound_id"]
    database.execute("DELETE FROM soundboard_sounds WHERE id = ? AND server_id = ?", (sound_id, server_id))
    return web.json_response({"success": True})


# Cache for server member roles: server_id -> (timestamp, roles_map)
_server_roles_cache = {}

def get_server_roles_map(server_id):
    now = time.time()
    if server_id in _server_roles_cache:
        ts, rmap = _server_roles_cache[server_id]
        if now - ts < 60:
            return rmap
    roles_raw = database.query("""
        SELECT mr.user_id, r.name, r.color, r.icon, r.is_badge
        FROM member_roles mr
        JOIN roles r ON mr.role_id = r.id
        WHERE mr.server_id = ?
    """, (server_id,))
    roles_map = {}
    for r in roles_raw:
        if r["user_id"] not in roles_map:
            roles_map[r["user_id"]] = []
        roles_map[r["user_id"]].append(r)
    _server_roles_cache[server_id] = (now, roles_map)
    return roles_map


# ==========================================================
# 5. MESSAGES & REACTIONS
# ==========================================================
@routes.get("/api/channels/{channel_id}/messages/search")
async def api_search_channel_messages(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    channel_id = request.match_info["channel_id"]
    q = (request.query.get("q") or "").strip()
    if not q:
        return web.json_response({"messages": []})

    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon non trouvé"}, status=404)

    server_id = channel["server_id"]
    allowed, reason = check_channel_access(user, channel, action="view")
    if not allowed:
        return web.json_response({"error": "Accès refusé"}, status=403)

    like_q = f"%{q}%"
    messages_raw = database.query("""
        SELECT m.*, u.username, u.display_name, u.avatar_url, u.tag
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.channel_id = ? AND m.content LIKE ?
        ORDER BY m.created_at DESC
        LIMIT 50
    """, (channel_id, like_q))

    return web.json_response({"messages": messages_raw or []})


@routes.get("/api/dms/{recipient_id}/messages/search")
async def api_search_dm_messages(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    recipient_id = request.match_info["recipient_id"]
    q = (request.query.get("q") or "").strip()
    if not q:
        return web.json_response({"messages": []})

    like_q = f"%{q}%"
    messages_raw = database.query("""
        SELECT dm.*, u.username, u.display_name, u.avatar_url, u.tag
        FROM direct_messages dm
        JOIN users u ON dm.sender_id = u.id
        WHERE ((dm.sender_id = ? AND dm.recipient_id = ?) OR (dm.sender_id = ? AND dm.recipient_id = ?))
          AND dm.content LIKE ?
        ORDER BY dm.created_at DESC
        LIMIT 50
    """, (user["id"], recipient_id, recipient_id, user["id"], like_q))

    return web.json_response({"messages": messages_raw or []})


@routes.get("/api/channels/{channel_id}/messages")
async def api_get_messages(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon non trouvé"}, status=404)

    server_id = channel["server_id"]

    allowed, reason = check_channel_access(user, channel, action="view")
    if not allowed:
        return web.json_response({"error": reason or "Ce salon est privé ou restreint."}, status=403)

    messages_raw = database.query("""
        SELECT m.*, u.username, u.display_name, u.tag, u.avatar_url, u.banner_color, u.global_badges, u.is_bot, u.is_verified_bot,
               sm.nickname, sm.server_avatar_url
        FROM messages m
        JOIN users u ON m.user_id = u.id
        LEFT JOIN server_members sm ON (sm.server_id = ? AND sm.user_id = m.user_id)
        WHERE m.channel_id = ?
        ORDER BY m.created_at ASC
        LIMIT 100
    """, (server_id, channel_id))

    if not messages_raw:
        return web.json_response({"messages": [], "channel": channel})

    roles_map = get_server_roles_map(server_id)

    # Get reactions
    reactions_raw = database.query("""
        SELECT r.message_id, r.emoji, r.user_id, u.username
        FROM reactions r
        JOIN users u ON r.user_id = u.id
        WHERE r.message_id IN (SELECT id FROM messages WHERE channel_id = ?)
    """, (channel_id,))

    reactions_map = {}
    for r in reactions_raw:
        mid = r["message_id"]
        if mid not in reactions_map:
            reactions_map[mid] = {}
        emoji = r["emoji"]
        if emoji not in reactions_map[mid]:
            reactions_map[mid][emoji] = {"count": 0, "users": [], "hasReacted": False}
        reactions_map[mid][emoji]["count"] += 1
        reactions_map[mid][emoji]["users"].append(r["username"])
        if r["user_id"] == user["id"]:
            reactions_map[mid][emoji]["hasReacted"] = True

    # Resolve reply_to messages
    reply_ids = [m["reply_to_id"] for m in messages_raw if m.get("reply_to_id")]
    reply_map = {}
    if reply_ids:
        placeholders = ",".join(["?"] * len(reply_ids))
        replied_msgs = database.query(f"""
            SELECT m.id, m.content, m.attachment_url, u.username, u.display_name, u.avatar_url
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id IN ({placeholders})
        """, tuple(reply_ids))
        for rm in (replied_msgs or []):
            reply_map[rm["id"]] = {
                "id": rm["id"],
                "author_name": rm.get("display_name") or rm.get("username") or "Utilisateur",
                "avatar_url": rm.get("avatar_url"),
                "content": rm.get("content") or ("Fichier joint" if rm.get("attachment_url") else "")
            }

    formatted = []
    for m in messages_raw:
        m_dict = dict(m)
        m_dict["roles"] = roles_map.get(m["user_id"], [])
        m_dict["reactions"] = reactions_map.get(m["id"], {})
        m_dict["is_bot"] = bool(m_dict.get("is_bot", 0))
        m_dict["is_verified_bot"] = bool(m_dict.get("is_verified_bot", 0))
        if m_dict.get("poll_data"):
            try:
                m_dict["poll"] = json.loads(m_dict["poll_data"])
            except Exception:
                m_dict["poll"] = None
        if m_dict.get("reply_to_id") and m_dict["reply_to_id"] in reply_map:
            m_dict["reply_to"] = reply_map[m_dict["reply_to_id"]]
        else:
            m_dict["reply_to"] = None
        formatted.append(m_dict)

    return web.json_response({"messages": formatted, "channel": channel})


@routes.post("/api/channels/{channel_id}/messages")
async def api_send_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable"}, status=404)

    allowed, reason = check_channel_access(user, channel, action="write")
    if not allowed:
        return web.json_response({"error": reason or "Vous n'avez pas la permission d'écrire dans ce salon."}, status=403)

    data = await request.json()
    content = data.get("content", "").strip()
    attachment_url = data.get("attachment_url")
    poll = data.get("poll")

    if not content and not attachment_url and not poll:
        return web.json_response({"error": "Message vide."}, status=400)

    server_id = channel["server_id"]

    # Rules screening validation check
    server_info = database.query_one("SELECT owner_id, automod_rules, rules_enabled FROM servers WHERE id = ?", (server_id,))
    if server_info and server_info.get("rules_enabled") == 1 and server_info.get("owner_id") != user["id"]:
        user_mem = database.query_one("SELECT rules_accepted FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
        if not user_mem or not user_mem.get("rules_accepted"):
            return web.json_response({"error": "Vous devez valider le règlement du serveur avant de pouvoir envoyer des messages."}, status=403)

    # AutoMod Protection Check
    if server_info and server_info.get("automod_rules"):
        raw_r = server_info.get("automod_rules")
        try:
            automod_rules = json.loads(raw_r) if isinstance(raw_r, str) else (raw_r or [])
        except Exception:
            automod_rules = []
        if isinstance(automod_rules, list):
            for rule in automod_rules:
                if not rule.get("enabled", True):
                    continue
                rtype = rule.get("type")
                if rtype == "anti_invite" and content:
                    if re.search(r"(discord\.(gg|io|me|li)|bastion\.app\/invite|chat\.whatsapp\.com|t\.me\/)", content, re.IGNORECASE):
                        database.add_audit_log(server_id, user["id"], "AUTOMOD_BLOCK", target_name=f"#{channel['name']}", reason="Lien d'invitation externe bloqué")
                        return web.json_response({"error": "🛡️ AutoMod: Les liens d'invitations externes ne sont pas autorisés sur ce serveur."}, status=403)
                elif rtype == "keyword_filter" and content:
                    kw_list = rule.get("keywords", [])
                    for kw in kw_list:
                        if kw.strip() and kw.strip().lower() in content.lower():
                            database.add_audit_log(server_id, user["id"], "AUTOMOD_BLOCK", target_name=f"#{channel['name']}", reason=f"Mot clé prohibé '{kw.strip()}'")
                            return web.json_response({"error": "🛡️ AutoMod: Votre message contient un terme interdit par les règles du serveur."}, status=403)
                elif rtype == "anti_caps" and content and len(content) > 10:
                    letters = [c for c in content if c.isalpha()]
                    if letters:
                        upper_count = sum(1 for c in letters if c.isupper())
                        if (upper_count / len(letters)) >= 0.70:
                            database.add_audit_log(server_id, user["id"], "AUTOMOD_BLOCK", target_name=f"#{channel['name']}", reason="Excès de majuscules (Anti-Caps)")
                            return web.json_response({"error": "🛡️ AutoMod: Merci de ne pas abuser des majuscules (Anti-Caps activé)."}, status=403)

    msg_id = str(uuid.uuid4())
    is_bot = 1 if user.get("is_bot") else 0
    poll_data_json = json.dumps(poll) if poll else ""

    send_as_bastion = bool(data.get("send_as_bastion") and auth.is_ceo(user))
    author_id = database.BASTION_SYSTEM_USER_ID if send_as_bastion else user["id"]
    if send_as_bastion:
        database.ensure_bastion_system_user()

    reply_to_id = data.get("reply_to_id")
    database.execute("""
        INSERT INTO messages (id, channel_id, server_id, user_id, content, attachment_url, is_bot_message, poll_data, reply_to_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (msg_id, channel_id, server_id, author_id, content, attachment_url, 1 if (is_bot or send_as_bastion) else 0, poll_data_json, reply_to_id))

    reply_to_obj = None
    if reply_to_id:
        rm = database.query_one("""
            SELECT m.id, m.content, m.attachment_url, u.username, u.display_name, u.avatar_url
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        """, (reply_to_id,))
        if rm:
            reply_to_obj = {
                "id": rm["id"],
                "author_name": rm.get("display_name") or rm.get("username") or "Utilisateur",
                "avatar_url": rm.get("avatar_url"),
                "content": rm.get("content") or ("Fichier joint" if rm.get("attachment_url") else "")
            }

    # Fetch complete message object for broadcast
    roles_raw = database.query("""
        SELECT r.name, r.color, r.icon, r.is_badge
        FROM member_roles mr
        JOIN roles r ON mr.role_id = r.id
        WHERE mr.server_id = ? AND mr.user_id = ?
    """, (server_id, user["id"]))

    mem_prof = database.query_one("SELECT nickname, server_avatar_url FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user["id"]))
    server_nick = mem_prof.get("nickname") if mem_prof else None
    server_avatar = mem_prof.get("server_avatar_url") if mem_prof else None

    if send_as_bastion:
        msg_obj = {
            "id": msg_id,
            "channel_id": channel_id,
            "server_id": server_id,
            "user_id": database.BASTION_SYSTEM_USER_ID,
            "username": "BASTION",
            "display_name": "BASTION (Officiel)",
            "nickname": "BASTION (Officiel)",
            "server_avatar_url": "/static/bastion-logo.png",
            "tag": "0000",
            "avatar_url": "/static/bastion-logo.png",
            "banner_color": "#5865F2",
            "global_badges": ["verified", "developer", "staff"],
            "is_bot": True,
            "is_verified_bot": True,
            "roles": [{"name": "Système Officiel", "color": "#5865F2", "icon": "🛡️", "is_badge": 1}],
            "content": content,
            "attachment_url": attachment_url,
            "poll": poll,
            "is_pinned": 0,
            "reactions": {},
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    else:
        msg_obj = {
            "id": msg_id,
            "channel_id": channel_id,
            "server_id": server_id,
            "user_id": user["id"],
            "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "nickname": server_nick,
        "server_avatar_url": server_avatar,
        "tag": user["tag"],
        "avatar_url": user["avatar_url"],
        "banner_color": user["banner_color"],
        "global_badges": user.get("global_badges") or [],
        "is_bot": bool(user.get("is_bot", 0)),
        "is_verified_bot": bool(user.get("is_verified_bot", 0)),
        "roles": roles_raw,
        "content": content,
        "attachment_url": attachment_url,
        "poll": poll,
        "is_pinned": 0,
        "reactions": {},
        "reply_to_id": reply_to_id,
        "reply_to": reply_to_obj,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Broadcast to all users connected to the channel
    await broadcast_to_channel(channel_id, {
        "type": "NEW_MESSAGE",
        "message": msg_obj
    })

    # Dispatch to Gateway Bots
    discord_msg = format_msg_for_discord(msg_obj)
    await dispatch_to_bots_in_server(server_id, "MESSAGE_CREATE", discord_msg)

    return web.json_response({"message": msg_obj})


@routes.post("/api/messages/{message_id}/poll/vote")
async def api_vote_poll(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    message_id = request.match_info["message_id"]
    msg = database.query_one("SELECT * FROM messages WHERE id = ?", (message_id,))
    if not msg:
        return web.json_response({"error": "Message introuvable"}, status=404)

    poll_data_raw = msg.get("poll_data")
    if not poll_data_raw:
        return web.json_response({"error": "Ce message ne contient aucun sondage"}, status=400)

    try:
        poll = json.loads(poll_data_raw)
    except Exception:
        return web.json_response({"error": "Données du sondage invalides"}, status=500)

    data = await request.json()
    option_id = data.get("option_id")
    if not option_id:
        return web.json_response({"error": "ID d'option manquant"}, status=400)

    user_id = user["id"]
    voters = poll.get("voters", {})
    multiselect = poll.get("multiselect", False)

    user_votes = voters.get(user_id, [])
    if isinstance(user_votes, str):
        user_votes = [user_votes]

    if option_id in user_votes:
        # Retirer le vote
        user_votes.remove(option_id)
    else:
        if not multiselect:
            user_votes = [option_id]
        else:
            user_votes.append(option_id)

    if user_votes:
        voters[user_id] = user_votes
    else:
        if user_id in voters:
            del voters[user_id]

    poll["voters"] = voters

    # Recalculer les votes par option
    options = poll.get("options", [])
    total_votes = 0
    for opt in options:
        opt_id = opt["id"]
        count = sum(1 for vlist in voters.values() if opt_id in vlist)
        opt["votes"] = count
        total_votes += count

    poll["options"] = options
    poll["totalVotes"] = total_votes

    # Sauvegarder en BDD
    database.execute("UPDATE messages SET poll_data = ? WHERE id = ?", (json.dumps(poll), message_id))

    # Diffuser la mise à jour du sondage via WebSocket
    await broadcast_to_channel(msg["channel_id"], {
        "type": "POLL_UPDATE",
        "message_id": message_id,
        "channel_id": msg["channel_id"],
        "poll": poll
    })

    return web.json_response({"poll": poll})


@routes.put("/api/messages/{message_id}")
async def api_edit_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    msg_id = request.match_info["message_id"]
    message = database.query_one("SELECT * FROM messages WHERE id = ?", (msg_id,))
    if not message:
        return web.json_response({"error": "Message introuvable"}, status=404)
    
    if str(message["user_id"]) != str(user["id"]):
        return web.json_response({"error": "Vous ne pouvez modifier que vos propres messages."}, status=403)
        
    data = await request.json()
    new_content = data.get("content", "").strip()
    if not new_content and not message.get("attachment_url"):
        return web.json_response({"error": "Le message ne peut pas être vide."}, status=400)
        
    database.execute("UPDATE messages SET content = ?, is_edited = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_content, msg_id))
    
    updated_msg = database.query_one("SELECT * FROM messages WHERE id = ?", (msg_id,))
    
    await broadcast_to_channel(message["channel_id"], {
        "type": "MESSAGE_UPDATED",
        "messageId": msg_id,
        "channelId": message["channel_id"],
        "content": new_content,
        "is_edited": 1,
        "updated_at": str(updated_msg.get("updated_at") or "")
    })
    
    return web.json_response({"success": True, "message": updated_msg})


@routes.delete("/api/messages/{message_id}")
async def api_delete_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    msg_id = request.match_info["message_id"]
    message = database.query_one("SELECT * FROM messages WHERE id = ?", (msg_id,))
    if not message:
        return web.json_response({"error": "Message introuvable"}, status=404)
        
    if not can_user_delete_message(user, message):
        return web.json_response({"error": "Vous n'avez pas la permission de supprimer ce message."}, status=403)
        
    # Delete reactions & message
    database.execute("DELETE FROM reactions WHERE message_id = ?", (msg_id,))
    database.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    
    await broadcast_to_channel(message["channel_id"], {
        "type": "MESSAGE_DELETED",
        "messageId": msg_id,
        "channelId": message["channel_id"]
    })

    await dispatch_to_bots_in_server(message["server_id"], "MESSAGE_DELETE", {
        "id": msg_id,
        "channel_id": message["channel_id"],
        "guild_id": message["server_id"]
    })
    
    return web.json_response({"success": True, "messageId": msg_id})


@routes.put("/api/channels/{channel_id}/messages/{message_id}/pin")
async def api_toggle_pin_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    channel_id = request.match_info["channel_id"]
    msg_id = request.match_info["message_id"]

    message = database.query_one("SELECT * FROM messages WHERE id = ? AND channel_id = ?", (msg_id, channel_id))
    if not message:
        return web.json_response({"error": "Message introuvable"}, status=404)

    new_pin_status = 0 if message.get("is_pinned", 0) else 1
    database.execute("UPDATE messages SET is_pinned = ? WHERE id = ?", (new_pin_status, msg_id))

    channel = database.query_one("SELECT server_id FROM channels WHERE id = ?", (channel_id,))
    if channel and channel.get("server_id"):
        action = "MESSAGE_PIN" if new_pin_status else "MESSAGE_UNPIN"
        database.add_audit_log(channel["server_id"], user["id"], action, target_name=f"Message {msg_id[:8]}")

    await broadcast_to_channel(channel_id, {
        "type": "MESSAGE_PINNED",
        "messageId": msg_id,
        "channelId": channel_id,
        "isPinned": bool(new_pin_status)
    })

    return web.json_response({
        "success": True,
        "is_pinned": bool(new_pin_status),
        "message_id": msg_id
    })


@routes.get("/api/channels/{channel_id}/pins")
async def api_get_channel_pins(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    channel_id = request.match_info["channel_id"]
    pins_raw = database.query("""
        SELECT m.*, u.username, u.display_name, u.avatar_url, u.tag
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.channel_id = ? AND m.is_pinned = 1
        ORDER BY m.created_at DESC
    """, (channel_id,))

    return web.json_response({"pins": pins_raw})


@routes.post("/api/messages/{message_id}/reactions")
async def api_toggle_reaction(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    msg_id = request.match_info["message_id"]
    data = await request.json()
    emoji = data.get("emoji", "👍")

    msg = database.query_one("SELECT * FROM messages WHERE id = ?", (msg_id,))
    if not msg:
        return web.json_response({"error": "Message introuvable"}, status=404)

    ch = database.query_one("SELECT * FROM channels WHERE id = ?", (msg["channel_id"],))
    if ch:
        allowed, reason = check_channel_access(user, ch, action="react")
        if not allowed:
            return web.json_response({"error": reason or "Vous n'avez pas la permission de réagir dans ce salon."}, status=403)

    existing = database.query_one("SELECT * FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
                                  (msg_id, user["id"], emoji))
    if existing:
        database.execute("DELETE FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
                         (msg_id, user["id"], emoji))
        action = "removed"
    else:
        database.execute("INSERT INTO reactions (message_id, user_id, emoji) VALUES (?, ?, ?)",
                         (msg_id, user["id"], emoji))
        action = "added"

    await broadcast_to_channel(msg["channel_id"], {
        "type": "REACTION_UPDATE",
        "messageId": msg_id,
        "emoji": emoji,
        "userId": user["id"],
        "username": user["username"],
        "action": action
    })

    return web.json_response({"success": True, "action": action})


# ==========================================================
# 6. SERVER INVITES GENERATION
# ==========================================================
@routes.post("/api/servers/{server_id}/invites")
async def api_create_server_invite(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    server_id = request.match_info["server_id"]
    server = database.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return web.json_response({"error": "Serveur introuvable"}, status=404)

    # Generate a fresh unique invite code
    code = f"DEVORA-{uuid.uuid4().hex[:6].upper()}"
    database.execute("INSERT INTO server_invites (code, server_id, creator_id) VALUES (?, ?, ?)",
                     (code, server_id, user["id"]))
    
    return web.json_response({"code": code, "server_id": server_id})


# ==========================================================
# 7. USER PROFILE LOOKUP
# ==========================================================
@routes.get("/api/users/{user_id}")
async def api_get_user_profile(request):
    current_user = get_auth_user(request)
    if not current_user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    user_id = request.match_info["user_id"]
    user = auth.get_user_by_id(user_id)
    if not user:
        return web.json_response({"error": "Utilisateur introuvable"}, status=404)
    
    # Check relationship with current_user
    friendship = database.query_one("""
        SELECT * FROM friendships 
        WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
    """, (current_user["id"], user_id, user_id, current_user["id"]))
    
    rel_status = "none"
    if friendship:
        if friendship["status"] == "accepted":
            rel_status = "friends"
        elif friendship["action_user_id"] == current_user["id"]:
            rel_status = "outgoing_request"
        else:
            rel_status = "incoming_request"

    # Mutual servers
    mutual_servers = database.query("""
        SELECT s.id, s.name, s.icon_url 
        FROM servers s
        JOIN server_members sm1 ON s.id = sm1.server_id AND sm1.user_id = ?
        JOIN server_members sm2 ON s.id = sm2.server_id AND sm2.user_id = ?
    """, (current_user["id"], user_id))

    is_online = user_id in connected_clients and len(connected_clients[user_id]) > 0
    return web.json_response({
        "user": user,
        "relationship": rel_status,
        "is_online": is_online or user.get("presence_status") != "offline",
        "mutual_servers": mutual_servers
    })


# ==========================================================
# 8. FRIENDS & FRIEND REQUESTS
# ==========================================================
@routes.get("/api/friends")
async def api_get_friends(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    uid = user["id"]
    # 1. Accepted Friends
    friends_rows = database.query("""
        SELECT u.id, u.username, u.tag, u.avatar_url, u.banner_color, u.bio, 
               u.custom_status, u.presence_status, u.global_badges, f.created_at as friendship_date
        FROM friendships f
        JOIN users u ON (CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END) = u.id
        WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = 'accepted'
    """, (uid, uid, uid))

    friends = []
    for fr in friends_rows:
        d = dict(fr)
        is_conn = fr["id"] in connected_clients and len(connected_clients[fr["id"]]) > 0
        d["is_online"] = is_conn or d.get("presence_status") != "offline"
        friends.append(d)

    # 2. Incoming Requests (someone else sent a request TO me)
    incoming_rows = database.query("""
        SELECT u.id, u.username, u.tag, u.avatar_url, u.custom_status, u.global_badges, f.created_at
        FROM friendships f
        JOIN users u ON u.id = f.action_user_id
        WHERE ((f.user_id = ? OR f.friend_id = ?) AND f.status = 'pending' AND f.action_user_id != ?)
    """, (uid, uid, uid))

    # 3. Outgoing Requests (I sent a request to someone else)
    outgoing_rows = database.query("""
        SELECT u.id, u.username, u.tag, u.avatar_url, u.custom_status, u.global_badges, f.created_at
        FROM friendships f
        JOIN users u ON u.id = (CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END)
        WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = 'pending' AND f.action_user_id = ?
    """, (uid, uid, uid, uid))

    return web.json_response({
        "friends": friends,
        "incoming": incoming_rows,
        "outgoing": outgoing_rows
    })


@routes.post("/api/friends/request")
async def api_send_friend_request(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    target_id = data.get("user_id")
    target_tag = data.get("tag", "").strip()
    target_username = data.get("username", "").strip()

    target_user = None
    if target_id:
        target_user = auth.get_user_by_id(target_id)
    elif target_username:
        # Check if full pseudo#1234 or separate
        if "#" in target_username:
            parts = target_username.split("#")
            target_username = parts[0].strip()
            target_tag = parts[1].strip()
        
        if target_tag:
            target_user = database.query_one("SELECT * FROM users WHERE LOWER(username) = LOWER(?) AND tag = ?", (target_username, target_tag))
        else:
            target_user = database.query_one("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (target_username,))

    if not target_user:
        return web.json_response({"error": "Utilisateur introuvable. Vérifiez le pseudo et le tag (ex: Pseudo#1234)."}, status=404)

    if target_user["id"] == user["id"]:
        return web.json_response({"error": "Vous ne pouvez pas vous ajouter vous-même en ami !"}, status=400)

    # Check existing
    existing = database.query_one("""
        SELECT * FROM friendships 
        WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
    """, (user["id"], target_user["id"], target_user["id"], user["id"]))

    if existing:
        if existing["status"] == "accepted":
            return web.json_response({"error": "Vous êtes déjà amis avec cet utilisateur."}, status=400)
        elif existing["status"] == "pending":
            if existing["action_user_id"] == user["id"]:
                return web.json_response({"error": "Une demande d'ami est déjà en attente."}, status=400)
            else:
                # Target had sent a request -> auto-accept
                database.execute("UPDATE friendships SET status = 'accepted' WHERE id = ?", (existing["id"],))
                await send_to_user(target_user["id"], {
                    "type": "FRIEND_ACCEPTED",
                    "friend": user
                })
                return web.json_response({"success": True, "status": "accepted", "message": f"Vous êtes maintenant ami avec {target_user['username']} ! 🎉"})

    # Create pending friendship
    database.execute("""
        INSERT INTO friendships (user_id, friend_id, status, action_user_id)
        VALUES (?, ?, 'pending', ?)
    """, (user["id"], target_user["id"], user["id"]))

    # Notify target user via WebSocket
    await send_to_user(target_user["id"], {
        "type": "FRIEND_REQUEST_RECEIVED",
        "sender": user
    })

    return web.json_response({"success": True, "status": "pending", "message": f"Demande d'ami envoyée à {target_user['username']}#{target_user['tag']} ! 🚀"})


@routes.post("/api/friends/accept")
async def api_accept_friend(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    friend_id = data.get("user_id")

    database.execute("""
        UPDATE friendships SET status = 'accepted'
        WHERE ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?))
          AND status = 'pending'
    """, (user["id"], friend_id, friend_id, user["id"]))

    target_user = auth.get_user_by_id(friend_id)
    if target_user:
        await send_to_user(friend_id, {
            "type": "FRIEND_ACCEPTED",
            "friend": user
        })

    return web.json_response({"success": True})


@routes.post("/api/friends/reject")
async def api_reject_friend(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    friend_id = data.get("user_id")

    database.execute("""
        DELETE FROM friendships
        WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
    """, (user["id"], friend_id, friend_id, user["id"]))

    return web.json_response({"success": True})


@routes.post("/api/friends/remove")
async def api_remove_friend(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    data = await request.json()
    friend_id = data.get("user_id")

    database.execute("""
        DELETE FROM friendships
        WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
    """, (user["id"], friend_id, friend_id, user["id"]))

    await send_to_user(friend_id, {
        "type": "FRIEND_REMOVED",
        "friendId": user["id"]
    })

    return web.json_response({"success": True})


# ==========================================================
# 9. DIRECT MESSAGES (DM)
# ==========================================================
@routes.get("/api/dms")
async def api_get_dms_list(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    uid = user["id"]
    # Get distinct conversational partners
    dms_users = database.query("""
        SELECT u.id, u.username, u.tag, u.avatar_url, u.custom_status, u.presence_status, u.global_badges,
               (SELECT dm.content FROM direct_messages dm 
                WHERE (dm.sender_id = u.id AND dm.recipient_id = ?) OR (dm.sender_id = ? AND dm.recipient_id = u.id)
                ORDER BY dm.created_at DESC LIMIT 1) as last_message,
               (SELECT dm.created_at FROM direct_messages dm 
                WHERE (dm.sender_id = u.id AND dm.recipient_id = ?) OR (dm.sender_id = ? AND dm.recipient_id = u.id)
                ORDER BY dm.created_at DESC LIMIT 1) as last_message_date
        FROM users u
        WHERE u.id IN (
            SELECT DISTINCT CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END
            FROM direct_messages
            WHERE sender_id = ? OR recipient_id = ?
        )
        ORDER BY last_message_date DESC
    """, (uid, uid, uid, uid, uid, uid, uid))

    res = []
    for r in dms_users:
        d = dict(r)
        is_conn = r["id"] in connected_clients and len(connected_clients[r["id"]]) > 0
        d["is_online"] = is_conn or d.get("presence_status") != "offline"
        res.append(d)

    return web.json_response({"dms": res})


@routes.get("/api/dms/{recipient_id}")
async def api_get_dm_messages(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    recipient_id = request.match_info["recipient_id"]
    recipient = auth.get_user_by_id(recipient_id)
    if not recipient:
        return web.json_response({"error": "Utilisateur introuvable"}, status=404)
    
    uid = user["id"]
    messages = database.query("""
        SELECT dm.*, u.username, u.tag, u.avatar_url, u.banner_color, u.global_badges
        FROM direct_messages dm
        JOIN users u ON dm.sender_id = u.id
        WHERE (dm.sender_id = ? AND dm.recipient_id = ?) OR (dm.sender_id = ? AND dm.recipient_id = ?)
        ORDER BY dm.created_at ASC
        LIMIT 100
    """, (uid, recipient_id, recipient_id, uid))

    is_conn = recipient_id in connected_clients and len(connected_clients[recipient_id]) > 0
    recipient["is_online"] = is_conn or recipient.get("presence_status") != "offline"

    return web.json_response({
        "recipient": recipient,
        "messages": messages
    })


@routes.post("/api/dms/{recipient_id}")
async def api_send_dm_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    recipient_id = request.match_info["recipient_id"]
    recipient = auth.get_user_by_id(recipient_id)
    if not recipient:
        return web.json_response({"error": "Destinataire introuvable"}, status=404)

    data = await request.json()
    content = data.get("content", "").strip()
    if not content:
        return web.json_response({"error": "Message vide"}, status=400)

    dm_id = str(uuid.uuid4())
    database.execute("""
        INSERT INTO direct_messages (id, sender_id, recipient_id, content)
        VALUES (?, ?, ?, ?)
    """, (dm_id, user["id"], recipient_id, content))

    dm_obj = {
        "id": dm_id,
        "sender_id": user["id"],
        "recipient_id": recipient_id,
        "username": user["username"],
        "tag": user["tag"],
        "avatar_url": user["avatar_url"],
        "banner_color": user["banner_color"],
        "global_badges": user.get("global_badges") or [],
        "content": content,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Send in real-time to recipient only (sender gets the message from API response)
    await send_to_user(recipient_id, {"type": "NEW_DIRECT_MESSAGE", "message": dm_obj})

    return web.json_response({"message": dm_obj})


@routes.put("/api/dms/messages/{message_id}")
async def api_edit_dm_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    msg_id = request.match_info["message_id"]
    message = database.query_one("SELECT * FROM direct_messages WHERE id = ?", (msg_id,))
    if not message:
        return web.json_response({"error": "Message privé introuvable"}, status=404)
        
    if str(message["sender_id"]) != str(user["id"]):
        return web.json_response({"error": "Vous ne pouvez modifier que vos propres messages."}, status=403)
        
    data = await request.json()
    new_content = data.get("content", "").strip()
    if not new_content:
        return web.json_response({"error": "Message vide"}, status=400)
        
    database.execute("UPDATE direct_messages SET content = ? WHERE id = ?", (new_content, msg_id))
    
    # Notify recipient
    await send_to_user(message["recipient_id"], {
        "type": "DM_MESSAGE_UPDATED",
        "messageId": msg_id,
        "senderId": user["id"],
        "content": new_content
    })
    
    return web.json_response({"success": True, "messageId": msg_id, "content": new_content})


@routes.delete("/api/dms/messages/{message_id}")
async def api_delete_dm_message(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    
    msg_id = request.match_info["message_id"]
    message = database.query_one("SELECT * FROM direct_messages WHERE id = ?", (msg_id,))
    if not message:
        return web.json_response({"error": "Message privé introuvable"}, status=404)
        
    if str(message["sender_id"]) != str(user["id"]):
        return web.json_response({"error": "Vous ne pouvez supprimer que vos propres messages."}, status=403)
        
    database.execute("DELETE FROM direct_messages WHERE id = ?", (msg_id,))
    
    # Notify recipient
    await send_to_user(message["recipient_id"], {
        "type": "DM_MESSAGE_DELETED",
        "messageId": msg_id,
        "senderId": user["id"]
    })
    
    return web.json_response({"success": True, "messageId": msg_id})


# ==========================================================
# 6. WEBSOCKET REAL-TIME HANDLER
# ==========================================================
# In-memory Voice & Stage states
active_voice_states = {}   # server_id -> channel_id -> { user_id: { ... } }
active_stage_states = {}   # channel_id -> { "topic": str, "is_active": bool, "host_id": str, "started_at": str }
user_active_voice = {}     # user_id -> { "server_id": str, "channel_id": str, "channel_type": str }


@routes.get("/api/servers/{server_id}/voice-states")
async def api_get_server_voice_states(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    server_id = request.match_info["server_id"]
    return web.json_response({
        "voice_states": active_voice_states.get(server_id, {}),
        "stage_states": active_stage_states
    })


# ==========================================================
# 6. WEBSOCKET REAL-TIME HANDLER
# ==========================================================
@routes.get("/ws")
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    authenticated_user = None

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    event_type = data.get("type")

                    # Handshake Auth
                    if event_type == "AUTH":
                        token = data.get("token")
                        payload = auth.verify_token(token)
                        if payload:
                            authenticated_user = auth.get_user_by_id(payload["uid"])
                            u_id = authenticated_user["id"]
                            if u_id not in connected_clients:
                                connected_clients[u_id] = set()
                            connected_clients[u_id].add(ws)

                            # Preserve user's presence or default to online
                            current_pres = authenticated_user.get("presence_status") or "online"
                            if current_pres == "offline":
                                current_pres = "online"
                                database.execute("UPDATE users SET presence_status = 'online' WHERE id = ?", (u_id,))
                            await broadcast_presence_change(u_id, current_pres)

                            await ws.send_str(json.dumps({
                                "type": "AUTH_OK",
                                "user": authenticated_user,
                                "stage_states": active_stage_states
                            }))
                        else:
                            await ws.send_str(json.dumps({"type": "AUTH_ERROR", "error": "Token invalide"}))

                    # Join Channel (Text subscription)
                    elif event_type == "JOIN_CHANNEL":
                        channel_id = data.get("channelId")
                        ws_channel_subscriptions[ws] = channel_id
                        await ws.send_str(json.dumps({"type": "CHANNEL_JOINED", "channelId": channel_id}))

                    # Typing event
                    elif event_type == "TYPING":
                        if authenticated_user:
                            channel_id = data.get("channelId")
                            await broadcast_to_channel(channel_id, {
                                "type": "USER_TYPING",
                                "channelId": channel_id,
                                "user": {
                                    "id": authenticated_user["id"],
                                    "username": authenticated_user["username"]
                                }
                            }, exclude_ws=ws)

                    # ==========================================
                    # VOICE & STAGE CONFERENCE REAL-TIME EVENTS
                    # ==========================================
                    elif event_type == "VOICE_JOIN":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            server_id = data.get("serverId")
                            channel_id = data.get("channelId")
                            channel_type = data.get("channelType", "voice")

                            # Clean up old voice channel if user was already connected somewhere
                            if u_id in user_active_voice:
                                old_info = user_active_voice.pop(u_id, None)
                                if old_info:
                                    old_s = old_info["server_id"]
                                    old_c = old_info["channel_id"]
                                    if old_s in active_voice_states and old_c in active_voice_states[old_s]:
                                        active_voice_states[old_s][old_c].pop(u_id, None)
                                        await broadcast_to_all({
                                            "type": "VOICE_USER_LEFT",
                                            "serverId": old_s,
                                            "channelId": old_c,
                                            "userId": u_id
                                        })

                            active_voice_states.setdefault(server_id, {}).setdefault(channel_id, {})
                            
                            is_stage = channel_type == "stage"
                            stage_info = active_stage_states.get(channel_id, {"topic": "", "is_active": False, "host_id": None})
                            
                            # For stage channels, speakers are host or approved speakers
                            is_speaker = False
                            if is_stage:
                                if stage_info.get("is_active") and stage_info.get("host_id") == u_id:
                                    is_speaker = True
                                elif not stage_info.get("is_active"):
                                    is_speaker = False
                            else:
                                is_speaker = True

                            voice_member = {
                                "id": u_id,
                                "username": authenticated_user["username"],
                                "display_name": authenticated_user.get("display_name") or authenticated_user["username"],
                                "avatar_url": authenticated_user.get("avatar_url") or "",
                                "global_badges": authenticated_user.get("global_badges") or [],
                                "is_muted": bool(data.get("isMuted", False)),
                                "is_deaf": bool(data.get("isDeaf", False)),
                                "is_speaking": False,
                                "is_video": bool(data.get("isVideo", False)),
                                "is_screen": bool(data.get("isScreen", False)),
                                "is_speaker": is_speaker,
                                "hand_raised": False,
                                "joined_at": datetime.utcnow().isoformat()
                            }

                            active_voice_states[server_id][channel_id][u_id] = voice_member
                            user_active_voice[u_id] = {
                                "server_id": server_id,
                                "channel_id": channel_id,
                                "channel_type": channel_type
                            }

                            # Send initial room state to connecting user
                            await ws.send_str(json.dumps({
                                "type": "VOICE_INITIAL_STATE",
                                "serverId": server_id,
                                "channelId": channel_id,
                                "channelType": channel_type,
                                "participants": list(active_voice_states[server_id][channel_id].values()),
                                "stage": stage_info
                            }))

                            # Broadcast new member to everyone
                            await broadcast_to_all({
                                "type": "VOICE_USER_JOINED",
                                "serverId": server_id,
                                "channelId": channel_id,
                                "channelType": channel_type,
                                "user": voice_member
                            })

                    elif event_type == "VOICE_LEAVE":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            v_info = user_active_voice.pop(u_id, None)
                            if v_info:
                                s_id = v_info["server_id"]
                                c_id = v_info["channel_id"]
                                if s_id in active_voice_states and c_id in active_voice_states[s_id]:
                                    active_voice_states[s_id][c_id].pop(u_id, None)
                                await broadcast_to_all({
                                    "type": "VOICE_USER_LEFT",
                                    "serverId": s_id,
                                    "channelId": c_id,
                                    "userId": u_id
                                })

                    elif event_type == "VOICE_STATE_UPDATE":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            v_info = user_active_voice.get(u_id)
                            if v_info:
                                s_id = v_info["server_id"]
                                c_id = v_info["channel_id"]
                                mem = active_voice_states.get(s_id, {}).get(c_id, {}).get(u_id)
                                if mem:
                                    if "isMuted" in data: mem["is_muted"] = bool(data["isMuted"])
                                    if "isDeaf" in data: mem["is_deaf"] = bool(data["isDeaf"])
                                    if "isSpeaking" in data: mem["is_speaking"] = bool(data["isSpeaking"])
                                    if "isVideo" in data: mem["is_video"] = bool(data["isVideo"])
                                    if "isScreen" in data: mem["is_screen"] = bool(data["isScreen"])
                                    await broadcast_to_all({
                                        "type": "VOICE_STATE_CHANGED",
                                        "serverId": s_id,
                                        "channelId": c_id,
                                        "userId": u_id,
                                        "state": mem
                                    })

                    elif event_type == "STAGE_START":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            server_id = data.get("serverId")
                            channel_id = data.get("channelId")
                            topic = data.get("topic", "Discussion communautaire en direct").strip()
                            active_stage_states[channel_id] = {
                                "topic": topic,
                                "is_active": True,
                                "host_id": u_id,
                                "started_at": datetime.utcnow().isoformat()
                            }
                            # Set host as active speaker
                            if server_id in active_voice_states and channel_id in active_voice_states[server_id]:
                                host_mem = active_voice_states[server_id][channel_id].get(u_id)
                                if host_mem:
                                    host_mem["is_speaker"] = True
                                    host_mem["hand_raised"] = False

                            await broadcast_to_all({
                                "type": "STAGE_STARTED",
                                "serverId": server_id,
                                "channelId": channel_id,
                                "stage": active_stage_states[channel_id],
                                "hostId": u_id
                            })

                    elif event_type == "STAGE_END":
                        if authenticated_user:
                            server_id = data.get("serverId")
                            channel_id = data.get("channelId")
                            active_stage_states[channel_id] = {
                                "topic": "",
                                "is_active": False,
                                "host_id": None
                            }
                            # Move speakers back to listeners
                            if server_id in active_voice_states and channel_id in active_voice_states[server_id]:
                                for mem in active_voice_states[server_id][channel_id].values():
                                    mem["is_speaker"] = False
                                    mem["hand_raised"] = False

                            await broadcast_to_all({
                                "type": "STAGE_ENDED",
                                "serverId": server_id,
                                "channelId": channel_id
                            })

                    elif event_type == "STAGE_RAISE_HAND":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            server_id = data.get("serverId")
                            channel_id = data.get("channelId")
                            raised = bool(data.get("raised", True))
                            if server_id in active_voice_states and channel_id in active_voice_states[server_id]:
                                mem = active_voice_states[server_id][channel_id].get(u_id)
                                if mem:
                                    mem["hand_raised"] = raised
                            await broadcast_to_all({
                                "type": "STAGE_HAND_UPDATED",
                                "serverId": server_id,
                                "channelId": channel_id,
                                "userId": u_id,
                                "raised": raised
                            })

                    elif event_type == "STAGE_SET_SPEAKER":
                        if authenticated_user:
                            server_id = data.get("serverId")
                            channel_id = data.get("channelId")
                            target_id = data.get("targetUserId")
                            is_speaker = bool(data.get("isSpeaker", True))
                            if server_id in active_voice_states and channel_id in active_voice_states[server_id]:
                                mem = active_voice_states[server_id][channel_id].get(target_id)
                                if mem:
                                    mem["is_speaker"] = is_speaker
                                    mem["hand_raised"] = False
                            await broadcast_to_all({
                                "type": "STAGE_SPEAKER_UPDATED",
                                "serverId": server_id,
                                "channelId": channel_id,
                                "userId": target_id,
                                "isSpeaker": is_speaker
                            })

                    elif event_type == "VOICE_SIGNAL":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            target_id = data.get("targetUserId")
                            if target_id and target_id in connected_clients:
                                signal_payload = json.dumps({
                                    "type": "VOICE_SIGNAL",
                                    "fromUserId": u_id,
                                    "signal": data.get("signal")
                                })
                                for client_ws in connected_clients[target_id]:
                                    try:
                                        await client_ws.send_str(signal_payload)
                                    except:
                                        pass

                    elif event_type in ("SOUNDBOARD_PLAY", "VOICE_SOUNDBOARD_PLAY"):
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            sound = data.get("sound") or {}
                            server_id = data.get("serverId") or (user_active_voice.get(u_id, {}).get("server_id"))
                            channel_id = data.get("channelId") or (user_active_voice.get(u_id, {}).get("channel_id"))
                            await broadcast_to_all({
                                "type": "SOUNDBOARD_PLAY",
                                "sound": sound,
                                "userId": u_id,
                                "username": authenticated_user["username"],
                                "displayName": authenticated_user.get("display_name") or authenticated_user["username"],
                                "avatarUrl": authenticated_user.get("avatar_url"),
                                "serverId": server_id,
                                "channelId": channel_id
                            })

                    # ==========================================
                    # 1-to-1 PRIVATE DM CALL REAL-TIME EVENTS
                    # ==========================================
                    elif event_type == "DM_CALL_START":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            target_id = data.get("targetUserId")
                            is_video = bool(data.get("isVideo", False))
                            call_id = data.get("callId") or f"call_{u_id}_{int(time.time())}"
                            
                            if target_id and target_id in connected_clients and len(connected_clients[target_id]) > 0:
                                payload = json.dumps({
                                    "type": "DM_CALL_INCOMING",
                                    "callId": call_id,
                                    "fromUser": {
                                        "id": authenticated_user["id"],
                                        "username": authenticated_user["username"],
                                        "avatar": authenticated_user.get("avatar"),
                                        "custom_status": authenticated_user.get("custom_status")
                                    },
                                    "isVideo": is_video
                                })
                                for client_ws in connected_clients[target_id]:
                                    try:
                                        await client_ws.send_str(payload)
                                    except:
                                        pass
                            else:
                                await ws.send_str(json.dumps({
                                    "type": "DM_CALL_UNAVAILABLE",
                                    "targetUserId": target_id,
                                    "callId": call_id,
                                    "reason": "L'utilisateur est hors-ligne"
                                }))

                    elif event_type == "DM_CALL_ACCEPT":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            target_id = data.get("targetUserId")
                            call_id = data.get("callId")
                            if target_id and target_id in connected_clients:
                                payload = json.dumps({
                                    "type": "DM_CALL_ACCEPTED",
                                    "callId": call_id,
                                    "fromUserId": u_id,
                                    "user": {
                                        "id": authenticated_user["id"],
                                        "username": authenticated_user["username"],
                                        "avatar": authenticated_user.get("avatar")
                                    }
                                })
                                for client_ws in connected_clients[target_id]:
                                    try:
                                        await client_ws.send_str(payload)
                                    except:
                                        pass

                    elif event_type == "DM_CALL_REJECT":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            target_id = data.get("targetUserId")
                            call_id = data.get("callId")
                            reason = data.get("reason") or "Appel refusé"
                            if target_id and target_id in connected_clients:
                                payload = json.dumps({
                                    "type": "DM_CALL_REJECTED",
                                    "callId": call_id,
                                    "fromUserId": u_id,
                                    "reason": reason
                                })
                                for client_ws in connected_clients[target_id]:
                                    try:
                                        await client_ws.send_str(payload)
                                    except:
                                        pass

                    elif event_type == "DM_CALL_END":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            target_id = data.get("targetUserId")
                            call_id = data.get("callId")
                            if target_id and target_id in connected_clients:
                                payload = json.dumps({
                                    "type": "DM_CALL_ENDED",
                                    "callId": call_id,
                                    "fromUserId": u_id
                                })
                                for client_ws in connected_clients[target_id]:
                                    try:
                                        await client_ws.send_str(payload)
                                    except:
                                        pass

                    elif event_type == "DM_CALL_SIGNAL":
                        if authenticated_user:
                            u_id = authenticated_user["id"]
                            target_id = data.get("targetUserId")
                            call_id = data.get("callId")
                            if target_id and target_id in connected_clients:
                                payload = json.dumps({
                                    "type": "DM_CALL_SIGNAL",
                                    "callId": call_id,
                                    "fromUserId": u_id,
                                    "signal": data.get("signal")
                                })
                                for client_ws in connected_clients[target_id]:
                                    try:
                                        await client_ws.send_str(payload)
                                    except:
                                        pass

                except Exception as e:
                    print(f"[WS ERROR] {e}")

            elif msg.type == WSMsgType.ERROR:
                print(f"[WS] Connection closed with error: {ws.exception()}")

    finally:
        # Cleanup on disconnect
        ws_channel_subscriptions.pop(ws, None)
        if authenticated_user:
            u_id = authenticated_user["id"]
            if u_id in user_active_voice:
                v_info = user_active_voice.pop(u_id, None)
                if v_info:
                    s_id = v_info["server_id"]
                    c_id = v_info["channel_id"]
                    if s_id in active_voice_states and c_id in active_voice_states[s_id]:
                        active_voice_states[s_id][c_id].pop(u_id, None)
                    await broadcast_to_all({
                        "type": "VOICE_USER_LEFT",
                        "serverId": s_id,
                        "channelId": c_id,
                        "userId": u_id
                    })

            if u_id in connected_clients:
                connected_clients[u_id].discard(ws)
                if not connected_clients[u_id]:
                    del connected_clients[u_id]
                    database.execute("UPDATE users SET presence_status = 'offline' WHERE id = ?", (u_id,))
                    await broadcast_presence_change(u_id, "offline")

    return ws


# ==========================================================
# 6.5 BASTION BOT & DEVELOPER PORTAL API
# ==========================================================

@routes.get("/api/developers/applications")
async def api_get_developer_applications(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    apps = database.get_user_applications(user["id"])
    return web.json_response({"applications": apps})


@routes.post("/api/developers/applications")
async def api_create_developer_application(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    data = await request.json()
    name = (data.get("name") or "").strip()
    if not name:
        return web.json_response({"error": "Nom de l'application / du bot requis."}, status=400)
    description = data.get("description", "")
    avatar_url = data.get("avatar_url", "")
    public_bot = 1 if data.get("public_bot", True) else 0

    app = database.create_bot_application(user["id"], name, description, avatar_url, public_bot)
    return web.json_response({"application": app})


@routes.get("/api/developers/applications/{app_id}")
async def api_get_developer_application_details(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    app_id = request.match_info["app_id"]
    app = database.get_application_by_id(app_id)
    if not app:
        return web.json_response({"error": "Application introuvable."}, status=404)
    if app["owner_id"] != user["id"] and not auth.is_ceo(user):
        return web.json_response({"error": "Accès non autorisé à cette application."}, status=403)
    return web.json_response({"application": app})


@routes.put("/api/developers/applications/{app_id}")
async def api_update_developer_application(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    app_id = request.match_info["app_id"]
    app = database.get_application_by_id(app_id)
    if not app or (app["owner_id"] != user["id"] and not auth.is_ceo(user)):
        return web.json_response({"error": "Application introuvable ou accès refusé."}, status=403)

    data = await request.json()
    updated_app = database.update_application(app_id, data)
    return web.json_response({"application": updated_app})


@routes.post("/api/developers/applications/{app_id}/reset-token")
async def api_reset_bot_token(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    app_id = request.match_info["app_id"]
    app = database.get_application_by_id(app_id)
    if not app or (app["owner_id"] != user["id"] and not auth.is_ceo(user)):
        return web.json_response({"error": "Accès refusé."}, status=403)

    new_token = database.reset_application_token(app_id)
    return web.json_response({"token": new_token})


@routes.post("/api/developers/applications/{app_id}/request-verification")
async def api_request_bot_verification(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    app_id = request.match_info["app_id"]
    app = database.get_application_by_id(app_id)
    if not app or (app["owner_id"] != user["id"] and not auth.is_ceo(user)):
        return web.json_response({"error": "Accès refusé."}, status=403)

    reason = ""
    try:
        if request.can_read_body:
            data = await request.json()
            reason = data.get("reason", "")
    except Exception:
        reason = ""

    res = database.request_bot_verification(app_id, reason)
    return web.json_response(res)


@routes.get("/api/admin/bot-applications")
async def api_admin_get_bot_applications(request):
    user = get_auth_user(request)
    if not user or not auth.is_ceo(user):
        return web.json_response({"error": "Accès réservé au CEO / Administration."}, status=403)
    apps = database.get_all_applications_admin()
    return web.json_response({"applications": apps})


@routes.post("/api/admin/bot-applications/{app_id}/verify")
async def api_admin_verify_bot_application(request):
    user = get_auth_user(request)
    if not user or not auth.is_ceo(user):
        return web.json_response({"error": "Accès réservé au CEO / Administration."}, status=403)
    app_id = request.match_info["app_id"]
    is_verified = True
    try:
        if request.can_read_body:
            data = await request.json()
            is_verified = bool(data.get("is_verified", True))
    except Exception:
        is_verified = True

    success = database.verify_bot_application_admin(app_id, is_verified)
    if not success:
        return web.json_response({"error": "Application introuvable."}, status=404)
    return web.json_response({"success": True, "is_verified": is_verified})


@routes.delete("/api/developers/applications/{app_id}")
async def api_delete_developer_application(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)
    app_id = request.match_info["app_id"]
    success = database.delete_application(app_id, user["id"])
    if not success and not auth.is_ceo(user):
        return web.json_response({"error": "Impossible de supprimer cette application."}, status=400)
    return web.json_response({"success": True})


@routes.get("/api/oauth2/bot-info/{app_id}")
async def api_get_oauth_bot_info(request):
    app_id = request.match_info["app_id"]
    info = database.get_bot_invite_info(app_id)
    if not info:
        return web.json_response({"error": "Bot introuvable."}, status=404)
    return web.json_response({"bot": info})


@routes.post("/api/oauth2/authorize-bot")
async def api_authorize_bot_to_server(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Veuillez vous connecter pour autoriser ce bot."}, status=401)

    data = await request.json()
    app_id = data.get("app_id")
    server_id = data.get("server_id")
    permissions = data.get("permissions", 8)

    if not app_id or not server_id:
        return web.json_response({"error": "Paramètres app_id et server_id requis."}, status=400)

    res = database.add_bot_to_server(app_id, server_id, user["id"], permissions)
    if not res.get("success"):
        return web.json_response(res, status=400)

    app = database.get_application_by_id(app_id)

    # Broadcast bot joined event
    await broadcast_to_all({
        "type": "MEMBER_JOINED",
        "serverId": server_id,
        "user": {
            "id": app["bot_user_id"],
            "username": app["name"],
            "display_name": app["name"],
            "tag": app.get("bot_tag", "0000"),
            "avatar_url": app.get("avatar_url") or "/static/bastion-logo.png",
            "is_bot": True,
            "is_verified_bot": bool(app.get("is_verified", 0))
        }
    })

    # Find general channel to send a friendly bot welcome announcement
    general_ch = database.query_one("SELECT id FROM channels WHERE server_id = ? AND type = 'text' ORDER BY position ASC LIMIT 1", (server_id,))
    if general_ch:
        welcome_msg_id = str(uuid.uuid4())
        verified_tag = " [✔ VÉRIFIÉ]" if app.get("is_verified") else ""
        welcome_text = f"🤖 **{app['name']}{verified_tag}** a rejoint le serveur ! Tapez `/help` ou `/` pour découvrir ses commandes."
        database.execute("""
            INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (welcome_msg_id, general_ch["id"], server_id, app["bot_user_id"], welcome_text))

        await broadcast_to_channel(general_ch["id"], {
            "type": "NEW_MESSAGE",
            "message": {
                "id": welcome_msg_id,
                "channel_id": general_ch["id"],
                "server_id": server_id,
                "user_id": app["bot_user_id"],
                "username": app["name"],
                "display_name": app["name"],
                "tag": app.get("bot_tag", "0000"),
                "avatar_url": app.get("avatar_url") or "/static/bastion-logo.png",
                "is_bot": True,
                "is_verified_bot": bool(app.get("is_verified", 0)),
                "content": welcome_text,
                "roles": [],
                "reactions": {},
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        })

    return web.json_response(res)


@routes.get("/api/channels/{channel_id}/slash-commands")
async def api_get_channel_slash_commands(request):
    channel_id = request.match_info["channel_id"]
    cmds = database.get_channel_slash_commands(channel_id)
    return web.json_response({"commands": cmds})


@routes.post("/api/channels/{channel_id}/slash-commands/execute")
async def api_execute_channel_slash_command(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable"}, status=404)

    data = await request.json()
    bot_user_id = data.get("bot_user_id")
    command_name = data.get("command", "").strip().lstrip("/")
    args_text = data.get("args", "")

    if not command_name:
        return web.json_response({"error": "Commande invalide."}, status=400)

    # If no specific bot_user_id provided, find the first bot with this command
    if not bot_user_id:
        all_cmds = database.get_channel_slash_commands(channel_id)
        for c in all_cmds:
            if c["name"].lower() == command_name.lower():
                bot_user_id = c["bot_user_id"]
                break

    if not bot_user_id:
        # Fallback to general system response if no bot has this command
        return web.json_response({"error": f"Aucun bot présent ne gère la commande `/{command_name}`."}, status=404)

    res_msg = database.execute_bot_command(bot_user_id, channel_id, channel["server_id"], command_name, user["id"], args_text)
    if not res_msg:
        return web.json_response({"error": "Échec d'exécution de la commande."}, status=500)

    # Broadcast bot response to channel
    await broadcast_to_channel(channel_id, {
        "type": "NEW_MESSAGE",
        "message": res_msg
    })

    return web.json_response({"success": True, "message": res_msg})


@routes.post("/api/developers/applications/{app_id}/test-message")
async def api_test_bot_message_playground(request):
    """Envoi de message de test depuis la console développeur"""
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    app_id = request.match_info["app_id"]
    app = database.get_application_by_id(app_id)
    if not app or (app["owner_id"] != user["id"] and not auth.is_ceo(user)):
        return web.json_response({"error": "Accès refusé."}, status=403)

    data = await request.json()
    channel_id = data.get("channel_id")
    content = data.get("content", "").strip()

    if not channel_id or not content:
        return web.json_response({"error": "Salon et contenu requis."}, status=400)

    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable."}, status=404)

    msg_id = str(uuid.uuid4())
    database.execute("""
        INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message)
        VALUES (?, ?, ?, ?, ?, 1)
    """, (msg_id, channel_id, channel["server_id"], app["bot_user_id"], content))

    msg_obj = {
        "id": msg_id,
        "channel_id": channel_id,
        "server_id": channel["server_id"],
        "user_id": app["bot_user_id"],
        "username": app["name"],
        "display_name": app["name"],
        "tag": app.get("bot_tag", "0000"),
        "avatar_url": app.get("avatar_url") or "/static/bastion-logo.png",
        "is_bot": True,
        "is_verified_bot": bool(app.get("is_verified", 0)),
        "content": content,
        "roles": [],
        "reactions": {},
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    await broadcast_to_channel(channel_id, {
        "type": "NEW_MESSAGE",
        "message": msg_obj
    })

    return web.json_response({"success": True, "message": msg_obj})


# ==========================================================
# 6.5 DISCORD-COMPATIBLE GATEWAY & REST API V10 (BOT PLATFORM)
# ==========================================================
connected_bots = {}  # bot_user_id -> set of ws
bot_ws_to_id = {}    # ws -> bot_user_id
pending_interactions = {}  # token -> dict


async def dispatch_to_bots_in_server(server_id, event_name, event_data):
    """Envoie un événement Gateway (MESSAGE_CREATE, etc.) aux bots présents sur ce serveur"""
    if not server_id:
        return
    bots_on_server = database.query("""
        SELECT u.id FROM users u
        JOIN server_members sm ON u.id = sm.user_id
        WHERE sm.server_id = ? AND u.is_bot = 1
    """, (server_id,))

    payload = json_dumps({
        "op": 0,
        "t": event_name,
        "d": event_data
    })

    for b in bots_on_server:
        b_id = str(b["id"])
        if b_id in connected_bots:
            for ws in list(connected_bots[b_id]):
                try:
                    await ws.send_str(payload)
                except Exception:
                    pass


async def dispatch_to_bot(bot_user_id, event_name, event_data):
    """Envoie un événement direct (ex: INTERACTION_CREATE) à un bot connecté"""
    b_id = str(bot_user_id)
    if b_id in connected_bots:
        payload = json_dumps({
            "op": 0,
            "t": event_name,
            "d": event_data
        })
        for ws in list(connected_bots[b_id]):
            try:
                await ws.send_str(payload)
            except Exception:
                pass


def format_msg_for_discord(msg_obj):
    """Formate un message Bastion au format Discord REST v10"""
    embeds = msg_obj.get("embeds", [])
    if isinstance(embeds, str):
        try:
            embeds = json.loads(embeds)
        except Exception:
            embeds = []
    
    components = msg_obj.get("components", [])
    if isinstance(components, str):
        try:
            components = json.loads(components)
        except Exception:
            components = []

    return {
        "id": str(msg_obj["id"]),
        "type": 0,
        "content": msg_obj.get("content", ""),
        "channel_id": str(msg_obj["channel_id"]),
        "guild_id": str(msg_obj.get("server_id", "")),
        "author": {
            "id": str(msg_obj["user_id"]),
            "username": msg_obj.get("username", "Utilisateur"),
            "global_name": msg_obj.get("display_name"),
            "avatar": msg_obj.get("avatar_url"),
            "discriminator": str(msg_obj.get("tag") or "0000"),
            "bot": bool(msg_obj.get("is_bot", 0))
        },
        "attachments": [{"url": msg_obj["attachment_url"]}] if msg_obj.get("attachment_url") else [],
        "embeds": embeds,
        "components": components,
        "pinned": bool(msg_obj.get("is_pinned", 0)),
        "mention_everyone": False,
        "tts": False,
        "timestamp": msg_obj.get("created_at") if isinstance(msg_obj.get("created_at"), str) else datetime.utcnow().isoformat(),
        "edited_timestamp": None,
        "flags": msg_obj.get("flags", 0)
    }


# --- GATEWAY WEBSOCKET ENDPOINT ---
@routes.get("/gateway")
@routes.get("/api/v10/gateway")
@routes.get("/api/gateway")
async def discord_gateway_ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    authenticated_bot = None

    # Opcode 10: HELLO
    await ws.send_str(json.dumps({
        "op": 10,
        "d": {
            "heartbeat_interval": 41250,
            "_trace": ["bastion-gateway-fra"]
        }
    }))

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    payload = json.loads(msg.data)
                except Exception:
                    continue

                op = payload.get("op")
                d = payload.get("d", {})

                if op == 1:  # HEARTBEAT
                    await ws.send_str(json.dumps({"op": 11}))  # HEARTBEAT_ACK

                elif op == 2:  # IDENTIFY
                    token = d.get("token", "").strip().replace("Bot ", "").replace("Bearer ", "")
                    app = database.get_application_by_token(token)
                    if not app:
                        print(f"[GATEWAY] Identification bot échouée.")
                        await ws.close(code=4004, message=b"Authentication failed")
                        return ws

                    authenticated_bot = app
                    bot_user_id = str(app["bot_user_id"])

                    if bot_user_id not in connected_bots:
                        connected_bots[bot_user_id] = set()
                    connected_bots[bot_user_id].add(ws)
                    bot_ws_to_id[ws] = bot_user_id

                    print(f"[GATEWAY] [BOT] Bot connecte : {app['name']} ({bot_user_id})")

                    # Get bot guilds
                    guilds = database.get_bot_guilds_discord(bot_user_id)
                    unavailable_guilds = [{"id": g["id"], "unavailable": False} for g in guilds]

                    # Opcode 0: READY
                    ready_payload = {
                        "op": 0,
                        "t": "READY",
                        "d": {
                            "v": 10,
                            "user": database.get_discord_user(bot_user_id),
                            "guilds": unavailable_guilds,
                            "session_id": str(uuid.uuid4()),
                            "resume_gateway_url": "ws://localhost:8080/gateway",
                            "shard": [0, 1],
                            "application": {
                                "id": str(app["id"]),
                                "flags": 0
                            }
                        }
                    }
                    await ws.send_str(json_dumps(ready_payload))

                    # Dispatch GUILD_CREATE for each guild
                    for g in guilds:
                        await ws.send_str(json_dumps({
                            "op": 0,
                            "t": "GUILD_CREATE",
                            "d": g
                        }))

            elif msg.type == WSMsgType.ERROR:
                print(f"[GATEWAY] WS error: {ws.exception()}")

    finally:
        if ws in bot_ws_to_id:
            b_id = bot_ws_to_id.pop(ws, None)
            if b_id and b_id in connected_bots:
                connected_bots[b_id].discard(ws)
                if not connected_bots[b_id]:
                    connected_bots.pop(b_id, None)
        print(f"[GATEWAY] Bot déconnecté.")

    return ws


# --- DISCORD REST API V10 ENDPOINTS ---
@routes.get("/api/v10/gateway/bot")
@routes.get("/api/gateway/bot")
async def api_v10_gateway_bot(request):
    return web.json_response({
        "url": "ws://localhost:8080/gateway",
        "shards": 1,
        "session_start_limit": {
            "total": 1000,
            "remaining": 999,
            "reset_after": 14400000,
            "max_concurrency": 1
        }
    })


@routes.get("/api/v10/users/@me")
@routes.get("/api/v1/bot/me")
async def api_v10_users_me(request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bot ", "").replace("Bearer ", "").strip()
    app = database.get_application_by_token(token)
    if not app:
        return web.json_response({"error": "Token Bot invalide ou non autorisé."}, status=401)
    
    bot_user = database.get_discord_user(app["bot_user_id"])
    return web.json_response(bot_user or app)


# Deploy / Put Application Commands
@routes.put("/api/v10/applications/{application_id}/commands")
@routes.put("/api/v10/applications/{application_id}/guilds/{guild_id}/commands")
async def api_v10_deploy_commands(request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bot ", "").replace("Bearer ", "").strip()
    app = database.get_application_by_token(token)
    if not app:
        return web.json_response({"error": "Non autorisé."}, status=401)

    app_id = request.match_info.get("application_id")
    body = await request.json()
    commands_list = body if isinstance(body, list) else body.get("body", [])

    # Format and save in application database
    saved_commands = []
    for cmd in commands_list:
        cmd_copy = dict(cmd)
        if not cmd_copy.get("id"):
            cmd_copy["id"] = str(uuid.uuid4())
        cmd_copy["application_id"] = app_id
        saved_commands.append(cmd_copy)

    database.update_application_commands(app["id"], saved_commands)
    print(f"[REST] 🚀 {len(saved_commands)} commandes déployées pour l'application {app['name']}.")
    return web.json_response(saved_commands)


@routes.get("/api/v10/applications/{application_id}/commands")
async def api_v10_get_commands(request):
    app_id = request.match_info["application_id"]
    app = database.get_application_by_id(app_id)
    if not app:
        return web.json_response({"error": "Application introuvable"}, status=404)
    cmds = app.get("slash_commands", [])
    if isinstance(cmds, str):
        try:
            cmds = json.loads(cmds)
        except Exception:
            cmds = []
    return web.json_response(cmds)


# Send Message
@routes.post("/api/v10/channels/{channel_id}/messages")
@routes.post("/api/v1/channels/{channel_id}/messages")
async def api_v10_send_channel_message(request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bot ", "").replace("Bearer ", "").strip()
    app = database.get_application_by_token(token)
    if not app:
        return web.json_response({"error": "Token de Bot BASTION invalide."}, status=401)

    channel_id = request.match_info["channel_id"]
    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable."}, status=404)

    data = await request.json()
    content = data.get("content", "")
    embeds = data.get("embeds", [])
    components = data.get("components", [])
    flags = data.get("flags", 0)
    attachment_url = data.get("attachment_url")

    msg_id = str(uuid.uuid4())
    database.execute("""
        INSERT INTO messages (id, channel_id, server_id, user_id, content, attachment_url, is_bot_message, embeds, components, flags)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    """, (msg_id, channel_id, channel["server_id"], app["bot_user_id"], content, attachment_url, json_dumps(embeds), json_dumps(components), flags))

    msg_obj = {
        "id": msg_id,
        "channel_id": channel_id,
        "server_id": channel["server_id"],
        "user_id": app["bot_user_id"],
        "username": app["name"],
        "display_name": app["name"],
        "tag": app.get("bot_tag", "0000"),
        "avatar_url": app.get("avatar_url") or "/static/bastion-logo.png",
        "is_bot": True,
        "is_verified_bot": bool(app.get("is_verified", 0)),
        "content": content,
        "embeds": embeds,
        "components": components,
        "flags": flags,
        "attachment_url": attachment_url,
        "roles": [],
        "reactions": {},
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    await broadcast_to_channel(channel_id, {
        "type": "NEW_MESSAGE",
        "message": msg_obj
    })

    discord_msg = format_msg_for_discord(msg_obj)
    await dispatch_to_bots_in_server(channel["server_id"], "MESSAGE_CREATE", discord_msg)

    return web.json_response(discord_msg)


# Delete Message
@routes.delete("/api/v10/channels/{channel_id}/messages/{message_id}")
async def api_v10_delete_message(request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bot ", "").replace("Bearer ", "").strip()
    app = database.get_application_by_token(token)
    if not app:
        return web.json_response({"error": "Non autorisé."}, status=401)

    channel_id = request.match_info["channel_id"]
    message_id = request.match_info["message_id"]

    msg = database.query_one("SELECT * FROM messages WHERE id = ?", (message_id,))
    if msg:
        database.execute("DELETE FROM reactions WHERE message_id = ?", (message_id,))
        database.execute("DELETE FROM messages WHERE id = ?", (message_id,))

        await broadcast_to_channel(channel_id, {
            "type": "MESSAGE_DELETED",
            "messageId": message_id,
            "channelId": channel_id
        })
        await dispatch_to_bots_in_server(msg["server_id"], "MESSAGE_DELETE", {
            "id": message_id,
            "channel_id": channel_id,
            "guild_id": msg["server_id"]
        })

    return web.Response(status=204)


# Interaction Callbacks (Bot responding to Slash command / Button / Menu)
@routes.post("/api/v10/interactions/{interaction_id}/{interaction_token}/callback")
async def api_v10_interaction_callback(request):
    interaction_id = request.match_info["interaction_id"]
    interaction_token = request.match_info["interaction_token"]

    data = await request.json()
    callback_type = data.get("type", 4)
    response_data = data.get("data", {})

    content = response_data.get("content", "")
    embeds = response_data.get("embeds", [])
    components = response_data.get("components", [])
    flags = response_data.get("flags", 0)

    interaction_ctx = pending_interactions.get(interaction_token)
    
    if interaction_ctx:
        channel_id = interaction_ctx.get("channel_id")
        server_id = interaction_ctx.get("server_id")
        bot_user_id = interaction_ctx.get("bot_user_id")
        user_id = interaction_ctx.get("user_id")

        bot_app = database.query_one("SELECT * FROM applications WHERE bot_user_id = ?", (bot_user_id,))
        bot_name = bot_app.get("name") if bot_app else "Bot"
        bot_avatar = bot_app.get("avatar_url") if bot_app else "/static/bastion-logo.png"

        # If ephemeral flag (64), send only to the interacting user
        is_ephemeral = (flags & 64) == 64

        msg_id = str(uuid.uuid4())
        msg_obj = {
            "id": msg_id,
            "channel_id": channel_id,
            "server_id": server_id,
            "user_id": bot_user_id,
            "username": bot_name,
            "display_name": bot_name,
            "avatar_url": bot_avatar,
            "is_bot": True,
            "is_verified_bot": bool(bot_app.get("is_verified", 0)) if bot_app else False,
            "content": content,
            "embeds": embeds,
            "components": components,
            "flags": flags,
            "is_ephemeral": is_ephemeral,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        if not is_ephemeral:
            database.execute("""
                INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message, embeds, components, flags)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
            """, (msg_id, channel_id, server_id, bot_user_id, content, json_dumps(embeds), json_dumps(components), flags))

            await broadcast_to_channel(channel_id, {
                "type": "NEW_MESSAGE",
                "message": msg_obj
            })
        else:
            await send_to_user(user_id, {
                "type": "EPHEMERAL_MESSAGE",
                "channelId": channel_id,
                "message": msg_obj
            })

    return web.Response(status=204)


# Webhook edit original interaction response (safeReply / editReply)
@routes.patch("/api/v10/webhooks/{application_id}/{interaction_token}/messages/@original")
async def api_v10_webhook_edit_original(request):
    interaction_token = request.match_info["interaction_token"]
    data = await request.json()
    
    interaction_ctx = pending_interactions.get(interaction_token)
    if interaction_ctx:
        channel_id = interaction_ctx.get("channel_id")
        user_id = interaction_ctx.get("user_id")
        content = data.get("content", "")
        embeds = data.get("embeds", [])
        components = data.get("components", [])

        # Send updated message event
        await send_to_user(user_id, {
            "type": "INTERACTION_REPLY_UPDATED",
            "channelId": channel_id,
            "content": content,
            "embeds": embeds,
            "components": components
        })

    return web.json_response({"success": True})


# Guild & Member Information
@routes.get("/api/v10/guilds/{guild_id}")
async def api_v10_get_guild(request):
    guild_id = request.match_info["guild_id"]
    g = database.get_discord_guild(guild_id)
    if not g:
        return web.json_response({"error": "Serveur introuvable"}, status=404)
    return web.json_response(g)


@routes.get("/api/v10/guilds/{guild_id}/members")
async def api_v10_get_guild_members(request):
    guild_id = request.match_info["guild_id"]
    g = database.get_discord_guild(guild_id)
    if not g:
        return web.json_response({"error": "Serveur introuvable"}, status=404)
    return web.json_response(g.get("members", []))


@routes.get("/api/v10/guilds/{guild_id}/members/{user_id}")
async def api_v10_get_guild_member(request):
    guild_id = request.match_info["guild_id"]
    user_id = request.match_info["user_id"]
    mem = database.get_discord_member(guild_id, user_id)
    if not mem:
        return web.json_response({"error": "Membre introuvable"}, status=404)
    return web.json_response(mem)


# Moderation: Kick member
@routes.delete("/api/v10/guilds/{guild_id}/members/{user_id}")
async def api_v10_kick_member(request):
    guild_id = request.match_info["guild_id"]
    user_id = request.match_info["user_id"]
    database.execute("DELETE FROM member_roles WHERE server_id = ? AND user_id = ?", (guild_id, user_id))
    database.execute("DELETE FROM server_members WHERE server_id = ? AND user_id = ?", (guild_id, user_id))
    await broadcast_to_all({"type": "MEMBER_KICKED", "serverId": guild_id, "userId": user_id})
    return web.Response(status=204)


# Moderation: Ban member
@routes.put("/api/v10/guilds/{guild_id}/bans/{user_id}")
async def api_v10_ban_member(request):
    guild_id = request.match_info["guild_id"]
    user_id = request.match_info["user_id"]
    database.execute("DELETE FROM member_roles WHERE server_id = ? AND user_id = ?", (guild_id, user_id))
    database.execute("DELETE FROM server_members WHERE server_id = ? AND user_id = ?", (guild_id, user_id))
    await broadcast_to_all({"type": "MEMBER_KICKED", "serverId": guild_id, "userId": user_id})
    return web.Response(status=204)


# Trigger Interaction from Bastion Frontend (User clicking Button / Menu / Slash command)
@routes.post("/api/interactions/trigger")
async def api_trigger_interaction(request):
    user = get_auth_user(request)
    if not user:
        return web.json_response({"error": "Non authentifié"}, status=401)

    data = await request.json()
    interaction_type = data.get("type", 2)  # 2: SlashCommand, 3: MessageComponent
    channel_id = data.get("channel_id")
    server_id = data.get("server_id")
    custom_id = data.get("custom_id")
    command_name = data.get("command_name")
    values = data.get("values", [])
    component_type = data.get("component_type", 2)  # 2: Button, 3: StringSelect
    target_bot_user_id = data.get("bot_user_id")

    channel = database.query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return web.json_response({"error": "Salon introuvable"}, status=404)

    # Find target bot if not provided
    if not target_bot_user_id:
        if command_name:
            clean_cmd = command_name.strip().lower().lstrip("/")
            apps = database.query("SELECT * FROM applications")
            for a in apps:
                cmds = a.get("slash_commands")
                if isinstance(cmds, str):
                    try:
                        cmds = json.loads(cmds)
                    except Exception:
                        cmds = []
                for c in cmds:
                    if c.get("name", "").lower() == clean_cmd:
                        target_bot_user_id = a["bot_user_id"]
                        break
                if target_bot_user_id:
                    break

    if not target_bot_user_id:
        # Fallback to first bot in server
        first_bot = database.query_one("""
            SELECT u.id FROM users u
            JOIN server_members sm ON u.id = sm.user_id
            WHERE sm.server_id = ? AND u.is_bot = 1 LIMIT 1
        """, (channel["server_id"],))
        if first_bot:
            target_bot_user_id = first_bot["id"]

    if not target_bot_user_id:
        return web.json_response({"error": "Aucun bot disponible pour cette interaction."}, status=404)

    interaction_id = str(uuid.uuid4())
    interaction_token = str(uuid.uuid4()).replace("-", "")

    pending_interactions[interaction_token] = {
        "interaction_id": interaction_id,
        "token": interaction_token,
        "user_id": user["id"],
        "channel_id": channel_id,
        "server_id": channel["server_id"],
        "bot_user_id": target_bot_user_id,
        "created_at": time.time()
    }

    # Clean old interactions (> 15 minutes)
    now = time.time()
    for tok in list(pending_interactions.keys()):
        if now - pending_interactions[tok]["created_at"] > 900:
            pending_interactions.pop(tok, None)

    # Format INTERACTION_CREATE payload
    interaction_payload = {
        "id": interaction_id,
        "token": interaction_token,
        "type": interaction_type,
        "guild_id": str(channel["server_id"]),
        "channel_id": str(channel_id),
        "member": database.get_discord_member(channel["server_id"], user["id"]),
        "user": database.get_discord_user(user["id"]),
        "data": {
            "id": str(uuid.uuid4()),
            "name": command_name,
            "custom_id": custom_id,
            "component_type": component_type,
            "values": values
        }
    }

    # Auto-handling for built-in Protect buttons
    if custom_id == "protect_open_ticket":
        server_id = channel["server_id"]
        ticket_cat = database.query_one("SELECT * FROM channel_categories WHERE server_id = ? AND UPPER(name) = 'TICKETS'", (server_id,))
        if not ticket_cat:
            cat_id = str(uuid.uuid4())
            database.execute("INSERT INTO channel_categories (id, server_id, name, position) VALUES (?, ?, 'TICKETS', 200)", (cat_id, server_id))
            ticket_cat = {"id": cat_id}

        ch_id = str(uuid.uuid4())
        raw_username = re.sub(r'[^a-zA-Z0-9_-]', '', user["username"].lower()) or "membre"
        ch_name = f"ticket-{raw_username[:15]}"
        topic = f"Ticket privé ouvert par @{user['username']} ({user['id']})"

        database.execute("""
            INSERT INTO channels (id, server_id, name, type, topic, is_private, category_id)
            VALUES (?, ?, ?, 'text', ?, 1, ?)
        """, (ch_id, server_id, ch_name, topic, ticket_cat["id"]))

        created_channel = database.query_one("SELECT * FROM channels WHERE id = ?", (ch_id,))

        msg_id = str(uuid.uuid4())
        welcome_ticket = f"Bonjour <@{user['username']}> ! 👋\nMerci d'avoir ouvert un ticket d'assistance. Un membre de l'équipe de modération va prendre en charge votre demande sous peu.\nVeuillez décrire en détail votre question ou votre problème ci-dessous."
        embeds = [{
            "title": f"🎟️ Ticket d'assistance : @{user['username']}",
            "description": welcome_ticket,
            "color": "#5865F2",
            "thumbnail": {"url": "/static/protect-logo.png"},
            "fields": [
                {"name": "Demandeur", "value": f"@{user['username']}", "inline": True},
                {"name": "Date d'ouverture", "value": datetime.now().strftime("%d/%m/%Y %H:%M"), "inline": True}
            ],
            "footer": {"text": "Bastion Guard • Protection & Assistance"}
        }]
        components = [{
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 4,
                    "custom_id": "protect_close_ticket",
                    "label": "🔒 Fermer le ticket",
                    "emoji": "🔒"
                }
            ]
        }]

        database.execute("""
            INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message, embeds, components)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """, (msg_id, ch_id, server_id, database.PROTECT_BOT_USER_ID, "", json_dumps(embeds), json_dumps(components)))

        await broadcast_to_all({"type": "CHANNEL_CREATED", "serverId": server_id, "channel": created_channel})

        return web.json_response({
            "success": True,
            "action": "ticket_created",
            "channel": created_channel
        })

    elif custom_id == "protect_close_ticket":
        server_id = channel["server_id"]
        database.execute("DELETE FROM messages WHERE channel_id = ?", (channel_id,))
        database.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
        await broadcast_to_all({
            "type": "CHANNEL_DELETED",
            "serverId": server_id,
            "channelId": channel_id
        })
        return web.json_response({
            "success": True,
            "action": "ticket_closed"
        })

    print(f"[INTERACTION] ⚡ Déclenchement interaction type {interaction_type} vers bot {target_bot_user_id}...")
    await dispatch_to_bot(target_bot_user_id, "INTERACTION_CREATE", interaction_payload)

    return web.json_response({
        "success": True,
        "interaction_id": interaction_id,
        "token": interaction_token
    })


# ==========================================================
# 7. STATIC FILES & SINGLE PAGE APP
# ==========================================================
static_path = os.path.join(os.path.dirname(__file__), "static")
img_path = os.path.join(os.path.dirname(__file__), "img")
routes.static("/static", static_path)
if os.path.exists(img_path):
    routes.static("/img", img_path)

@routes.get("/")
@routes.get("/landing")
async def landing_handler(request):
    landing_file = os.path.join(static_path, "landing.html")
    target = landing_file if os.path.exists(landing_file) else os.path.join(static_path, "index.html")
    resp = web.FileResponse(target)
    resp.content_type = "text/html"
    resp.charset = "utf-8"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@routes.get("/legal")
@routes.get("/cgu")
@routes.get("/privacy")
@routes.get("/mentions")
async def legal_page_handler(request):
    legal_file = os.path.join(static_path, "legal.html")
    resp = web.FileResponse(legal_file if os.path.exists(legal_file) else os.path.join(static_path, "index.html"))
    resp.content_type = "text/html"
    resp.charset = "utf-8"
    return resp

@routes.get("/app")
@routes.get("/app/{tail:.*}")
@routes.get("/oauth2/authorize")
@routes.get("/oauth2/authorize/{tail:.*}")
@routes.get("/developers")
@routes.get("/developers/{tail:.*}")
@routes.get("/invite/{tail:.*}")
@routes.get("/channels/{tail:.*}")
async def index_handler(request):
    resp = web.FileResponse(os.path.join(static_path, "index.html"))
    resp.content_type = "text/html"
    resp.charset = "utf-8"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@web.middleware
async def cors_middleware(request, handler):
    """Gere les requetes cross-origin (CORS) pour WordPress, Electron et les clients externes."""
    if request.method == "OPTIONS":
        response = web.Response(status=200)
    else:
        try:
            response = await handler(request)
        except web.HTTPException as ex:
            response = ex

    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Accept"
    return response


@web.middleware
async def no_cache_middleware(request, handler):
    """Prevents browsers from caching static and application assets so changes appear immediately without Ctrl+F5."""
    response = await handler(request)
    path = request.path.lower()
    if path.endswith(('.html', '.js', '.css', '.json')) or path in ['/', '/app', '/channels', '/landing'] or path.startswith(('/channels/', '/app/', '/static/')):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


async def background_tasks_ctx(app):
    task = asyncio.create_task(cleanup_attachments_worker())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app():
    app = web.Application(client_max_size=300 * 1024 * 1024, middlewares=[cors_middleware, no_cache_middleware])
    app.cleanup_ctx.append(background_tasks_ctx)
    app.add_routes(routes)
    return app


if __name__ == "__main__":
    port = int(os.getenv("PORT") or os.getenv("SERVER_PORT", 8080))
    host = os.getenv("SERVER_HOST", "0.0.0.0")
    print(f"[BASTION] Demarrage du serveur sur http://0.0.0.0:{port}")
    print(f"[DATABASE] Mode actuel: {database.DB_ENGINE.upper()}")
    web.run_app(create_app(), host=host, port=port)
