import os
import sqlite3
import json
import uuid
import datetime
import random
import pymysql
import pymysql.cursors
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
load_dotenv()

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "devora_discord")

DB_ENGINE = "mysql"  # 'mysql' ou 'sqlite'
SQLITE_PATH = os.path.join(os.path.dirname(__file__), "devora_discord.db")


import time

_shared_mysql_conn = None
_last_mysql_activity = 0

def get_mysql_conn(create_db=False):
    global _shared_mysql_conn, _last_mysql_activity
    try:
        if create_db:
            return pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=5
            )
        
        now = time.time()
        # Fast reusable persistent connection
        if _shared_mysql_conn is not None and getattr(_shared_mysql_conn, 'open', False):
            if now - _last_mysql_activity > 30:
                try:
                    _shared_mysql_conn.ping(reconnect=True)
                    _last_mysql_activity = now
                    return _shared_mysql_conn
                except Exception:
                    _shared_mysql_conn = None
            else:
                _last_mysql_activity = now
                return _shared_mysql_conn

        _shared_mysql_conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
            autocommit=True
        )
        _last_mysql_activity = now
        return _shared_mysql_conn
    except Exception as e:
        return None


def init_db():
    global DB_ENGINE
    try:
        mysql_conn = get_mysql_conn(create_db=True)
        if mysql_conn:
            try:
                with mysql_conn.cursor() as cursor:
                    cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
                mysql_conn.commit()
            except Exception:
                pass
            finally:
                try:
                    mysql_conn.close()
                except Exception:
                    pass

        # Connect directly to the specified database
        conn = get_mysql_conn(create_db=False)
        if conn:
            with conn.cursor() as cursor:
                # 1. Users
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `users` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `username` VARCHAR(50) NOT NULL,
                    `tag` VARCHAR(4) NOT NULL,
                    `email` VARCHAR(150) NOT NULL UNIQUE,
                    `password_hash` VARCHAR(255) NOT NULL,
                    `avatar_url` TEXT NULL,
                    `banner_color` VARCHAR(20) DEFAULT '#5865F2',
                    `banner_url` TEXT NULL,
                    `bio` TEXT NULL,
                    `custom_status` VARCHAR(100) DEFAULT 'En ligne',
                    `presence_status` VARCHAR(20) DEFAULT 'online',
                    `global_badges` JSON NULL,
                    `is_bot` TINYINT(1) DEFAULT 0,
                    `is_verified_bot` TINYINT(1) DEFAULT 0,
                    `bot_app_id` VARCHAR(36) NULL,
                    `orbs_points` INT DEFAULT 0,
                    `ads_watched` INT DEFAULT 0,
                    `last_orbs_daily` VARCHAR(50) NULL,
                    `avatar_decoration` VARCHAR(255) DEFAULT '',
                    `profile_effect` VARCHAR(255) DEFAULT '',
                    `profile_frame` VARCHAR(255) DEFAULT '',
                    `inventory` JSON NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX `idx_username_tag` (`username`, `tag`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                for col_name, col_type in [
                    ("banner_url", "TEXT NULL"),
                    ("display_name", "VARCHAR(50) NULL"),
                    ("is_bot", "TINYINT(1) DEFAULT 0"),
                    ("is_verified_bot", "TINYINT(1) DEFAULT 0"),
                    ("bot_app_id", "VARCHAR(36) NULL"),
                    ("orbs_points", "INT DEFAULT 0"),
                    ("ads_watched", "INT DEFAULT 0"),
                    ("last_orbs_daily", "VARCHAR(50) NULL"),
                    ("avatar_decoration", "VARCHAR(255) DEFAULT ''"),
                    ("profile_effect", "VARCHAR(255) DEFAULT ''"),
                    ("profile_frame", "VARCHAR(255) DEFAULT ''"),
                    ("inventory", "JSON NULL"),
                ]:
                    try:
                        cursor.execute(f"ALTER TABLE `users` ADD COLUMN `{col_name}` {col_type};")
                    except Exception:
                        pass

                # Applications / Bots Table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `applications` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `owner_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(50) NOT NULL,
                    `description` TEXT NULL,
                    `avatar_url` TEXT NULL,
                    `banner_url` TEXT NULL,
                    `token` VARCHAR(128) NOT NULL UNIQUE,
                    `bot_user_id` VARCHAR(36) NOT NULL,
                    `public_bot` TINYINT(1) DEFAULT 1,
                    `is_verified` TINYINT(1) DEFAULT 0,
                    `verification_status` VARCHAR(20) DEFAULT 'unverified',
                    `verification_request_reason` TEXT NULL,
                    `server_count` INT DEFAULT 0,
                    `permissions_default` BIGINT DEFAULT 8,
                    `slash_commands` JSON NULL,
                    `webhook_url` TEXT NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_app_owner` (`owner_id`),
                    INDEX `idx_app_token` (`token`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                try:
                    cursor.execute("ALTER TABLE `servers` ADD COLUMN `description` VARCHAR(255) DEFAULT '' AFTER `icon_url`;")
                except Exception:
                    pass

                try:
                    cursor.execute("ALTER TABLE `servers` ADD COLUMN `banner_url` TEXT NULL AFTER `description`;")
                except Exception:
                    pass

                try:
                    cursor.execute("ALTER TABLE `servers` ADD COLUMN `system_channel_id` VARCHAR(36) NULL AFTER `banner_url`;")
                except Exception:
                    pass

                # Badge & boost columns for servers
                server_badge_cols = [
                    ("banner_color", "VARCHAR(20) DEFAULT '#1e293b'"),
                    ("is_official", "TINYINT(1) DEFAULT 0"),
                    ("is_partner", "TINYINT(1) DEFAULT 0"),
                    ("is_community", "TINYINT(1) DEFAULT 0"),
                    ("boost_level", "INT DEFAULT 0"),
                    ("boost_count", "INT DEFAULT 0"),
                    ("server_badge_type", "VARCHAR(50) DEFAULT ''"),
                    ("protect_config", "TEXT NULL"),
                    ("rules_channel_id", "VARCHAR(36) NULL"),
                    ("announcement_channel_id", "VARCHAR(36) NULL"),
                ]
                for col_name, col_type in server_badge_cols:
                    try:
                        cursor.execute(f"ALTER TABLE `servers` ADD COLUMN `{col_name}` {col_type};")
                    except Exception:
                        pass

                # 2. Servers
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `servers` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `name` VARCHAR(100) NOT NULL,
                    `icon_url` TEXT NULL,
                    `description` VARCHAR(255) DEFAULT '',
                    `owner_id` VARCHAR(36) NOT NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 3. Channels
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `channels` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(100) NOT NULL,
                    `type` VARCHAR(20) DEFAULT 'text',
                    `topic` VARCHAR(255) DEFAULT '',
                    `slowmode` INT DEFAULT 0,
                    `content_visibility` VARCHAR(20) DEFAULT 'default',
                    `is_announcement` TINYINT(1) DEFAULT 0,
                    `is_private` TINYINT(1) DEFAULT 0,
                    `permissions_data` JSON NULL,
                    `position` INT DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                channel_alter_cols = [
                    ("slowmode", "INT DEFAULT 0"),
                    ("content_visibility", "VARCHAR(20) DEFAULT 'default'"),
                    ("is_announcement", "TINYINT(1) DEFAULT 0"),
                    ("is_private", "TINYINT(1) DEFAULT 0"),
                    ("permissions_data", "JSON NULL"),
                    ("category_id", "VARCHAR(36) DEFAULT ''")
                ]
                for col_name, col_type in channel_alter_cols:
                    try:
                        cursor.execute(f"ALTER TABLE `channels` ADD COLUMN `{col_name}` {col_type};")
                    except Exception:
                        pass

                # Channel Categories
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `channel_categories` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(100) NOT NULL,
                    `position` INT DEFAULT 0,
                    `collapsed` TINYINT(1) DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # Threads
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `threads` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `channel_id` VARCHAR(36) NOT NULL,
                    `server_id` VARCHAR(36) NOT NULL,
                    `message_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(100) NOT NULL,
                    `creator_id` VARCHAR(36) NOT NULL,
                    `is_locked` TINYINT(1) DEFAULT 0,
                    `is_archived` TINYINT(1) DEFAULT 0,
                    `message_count` INT DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    `last_message_at` DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # Thread messages
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `thread_messages` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `thread_id` VARCHAR(36) NOT NULL,
                    `user_id` VARCHAR(36) NOT NULL,
                    `content` TEXT NOT NULL,
                    `attachment_url` TEXT,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # Server access & discovery columns
                server_access_cols = [
                    ("access_mode", "VARCHAR(30) DEFAULT 'invite_only'"),
                    ("age_restricted", "TINYINT(1) DEFAULT 0"),
                    ("rules_enabled", "TINYINT(1) DEFAULT 0"),
                    ("rules_list", "JSON NULL"),
                    ("banner_url", "TEXT NULL"),
                    ("discover_description", "TEXT NULL"),
                    ("discover_tags", "VARCHAR(255) DEFAULT '[]'"),
                    ("category", "VARCHAR(50) DEFAULT 'community'"),
                    ("automod_rules", "JSON NULL"),
                    ("welcome_enabled", "TINYINT(1) DEFAULT 0"),
                    ("welcome_message", "TEXT NULL"),
                    ("welcome_channels", "JSON NULL")
                ]
                for col_name, col_type in server_access_cols:
                    try:
                        cursor.execute(f"ALTER TABLE `servers` ADD COLUMN `{col_name}` {col_type};")
                    except Exception:
                        pass

                # 4. Server members
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `server_members` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `user_id` VARCHAR(36) NOT NULL,
                    `nickname` VARCHAR(50) NULL,
                    `server_avatar_url` TEXT NULL,
                    `server_bio` TEXT NULL,
                    `rules_accepted` TINYINT(1) DEFAULT 0,
                    `rules_accepted_at` DATETIME NULL,
                    `joined_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY `unique_member` (`server_id`, `user_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                member_cols = [
                    ("server_avatar_url", "TEXT NULL"),
                    ("server_bio", "TEXT NULL"),
                    ("rules_accepted", "TINYINT(1) DEFAULT 0"),
                    ("rules_accepted_at", "DATETIME NULL")
                ]
                for col_name, col_type in member_cols:
                    try:
                        cursor.execute(f"ALTER TABLE `server_members` ADD COLUMN `{col_name}` {col_type};")
                    except Exception:
                        pass

                # 5. Roles & Badges
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `roles` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(50) NOT NULL,
                    `color` VARCHAR(20) DEFAULT '#99AAB5',
                    `icon` VARCHAR(10) DEFAULT '🛡️',
                    `is_badge` TINYINT(1) DEFAULT 1,
                    `role_style` VARCHAR(30) DEFAULT 'solid',
                    `permissions` JSON NULL,
                    `position` INT DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                try:
                    cursor.execute("ALTER TABLE `roles` ADD COLUMN `role_style` VARCHAR(30) DEFAULT 'solid' AFTER `is_badge`;")
                except Exception:
                    pass

                # 6. Member Roles
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `member_roles` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `user_id` VARCHAR(36) NOT NULL,
                    `role_id` VARCHAR(36) NOT NULL,
                    UNIQUE KEY `unique_member_role` (`server_id`, `user_id`, `role_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 7. Messages
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `messages` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `channel_id` VARCHAR(36) NOT NULL,
                    `server_id` VARCHAR(36) NOT NULL,
                    `user_id` VARCHAR(36) NOT NULL,
                    `content` TEXT NOT NULL,
                    `attachment_url` TEXT NULL,
                    `is_pinned` TINYINT(1) DEFAULT 0,
                    `is_edited` TINYINT(1) DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX `idx_channel_created` (`channel_id`, `created_at`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                try:
                    cursor.execute("ALTER TABLE `messages` ADD COLUMN `is_edited` TINYINT(1) DEFAULT 0;")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE `messages` ADD COLUMN `is_bot_message` TINYINT(1) DEFAULT 0;")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE `messages` ADD COLUMN `embeds` TEXT NULL;")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE `messages` ADD COLUMN `components` TEXT NULL;")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE `messages` ADD COLUMN `poll_data` TEXT NULL;")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE `messages` ADD COLUMN `flags` INT DEFAULT 0;")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE `messages` ADD COLUMN `reply_to_id` VARCHAR(36) NULL;")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE `direct_messages` ADD COLUMN `reply_to_id` VARCHAR(36) NULL;")
                except Exception:
                    pass

                # 8. Reactions
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `reactions` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `message_id` VARCHAR(36) NOT NULL,
                    `user_id` VARCHAR(36) NOT NULL,
                    `emoji` VARCHAR(30) NOT NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY `unique_user_reaction` (`message_id`, `user_id`, `emoji`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 9. Server Invites
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `server_invites` (
                    `code` VARCHAR(20) PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `creator_id` VARCHAR(36) NOT NULL,
                    `uses` INT DEFAULT 0,
                    `max_uses` INT DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 10. Friendships & Friend Requests
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `friendships` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `user_id` VARCHAR(36) NOT NULL,
                    `friend_id` VARCHAR(36) NOT NULL,
                    `status` ENUM('pending', 'accepted', 'blocked') DEFAULT 'pending',
                    `action_user_id` VARCHAR(36) NOT NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY `unique_friendship` (`user_id`, `friend_id`),
                    INDEX `idx_user_friend` (`user_id`, `status`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 11. Direct Messages
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `direct_messages` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `sender_id` VARCHAR(36) NOT NULL,
                    `recipient_id` VARCHAR(36) NOT NULL,
                    `content` TEXT NOT NULL,
                    `attachment_url` TEXT NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_dm_conversation` (`sender_id`, `recipient_id`, `created_at`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 12. Server Emojis
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `emojis` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(50) NOT NULL,
                    `image_url` TEXT NOT NULL,
                    `creator_id` VARCHAR(36) NOT NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_emoji_server` (`server_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 13. Audit Logs
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `audit_logs` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `user_id` VARCHAR(36) NOT NULL,
                    `action_type` VARCHAR(50) NOT NULL,
                    `target_name` VARCHAR(100) NULL,
                    `reason` TEXT NULL,
                    `details` JSON NULL,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_audit_server` (`server_id`, `created_at`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 14. Forum Tags
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `forum_tags` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `channel_id` VARCHAR(36) NOT NULL,
                    `server_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(50) NOT NULL,
                    `emoji` VARCHAR(10) DEFAULT '🏷️',
                    `color` VARCHAR(20) DEFAULT '#5865F2',
                    `position` INT DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_forum_tag_channel` (`channel_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 15. Forum Posts
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `forum_posts` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `channel_id` VARCHAR(36) NOT NULL,
                    `server_id` VARCHAR(36) NOT NULL,
                    `author_id` VARCHAR(36) NOT NULL,
                    `title` VARCHAR(200) NOT NULL,
                    `content` TEXT NOT NULL,
                    `tags` JSON NULL,
                    `is_pinned` TINYINT(1) DEFAULT 0,
                    `is_locked` TINYINT(1) DEFAULT 0,
                    `is_solved` TINYINT(1) DEFAULT 0,
                    `reply_count` INT DEFAULT 0,
                    `last_reply_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_forum_post_channel` (`channel_id`, `created_at`),
                    INDEX `idx_forum_post_author` (`author_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 16. Forum Replies
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `forum_replies` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `post_id` VARCHAR(36) NOT NULL,
                    `author_id` VARCHAR(36) NOT NULL,
                    `content` TEXT NOT NULL,
                    `is_solution` TINYINT(1) DEFAULT 0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_forum_reply_post` (`post_id`, `created_at`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

                # 17. Soundboard Sounds
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `soundboard_sounds` (
                    `id` VARCHAR(36) PRIMARY KEY,
                    `server_id` VARCHAR(36) NOT NULL,
                    `user_id` VARCHAR(36) NOT NULL,
                    `name` VARCHAR(50) NOT NULL,
                    `emoji` VARCHAR(20) DEFAULT '🔊',
                    `audio_url` TEXT NOT NULL,
                    `volume` FLOAT DEFAULT 1.0,
                    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_sound_server` (`server_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """)

            conn.commit()
            DB_ENGINE = "mysql"
            print("[DATABASE] Connecte avec succes a MySQL!")
            return
    except Exception as e:
        print(f"[DATABASE] Erreur d'initialisation MySQL: {e}. Bascule sur SQLite.")

    # Fallback to SQLite
    DB_ENGINE = "sqlite"
    print("[DATABASE] Mode SQLite active (MySQL inaccessible ou non demarre).")
    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        display_name TEXT,
        tag TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        avatar_url TEXT,
        banner_color TEXT DEFAULT '#5865F2',
        banner_url TEXT,
        bio TEXT DEFAULT '',
        custom_status TEXT DEFAULT 'En ligne',
        presence_status TEXT DEFAULT 'online',
        global_badges TEXT DEFAULT '[]',
        avatar_decoration TEXT DEFAULT '',
        profile_effect TEXT DEFAULT '',
        profile_frame TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        icon_url TEXT,
        description TEXT DEFAULT '',
        owner_id TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS channels (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        name TEXT NOT NULL,
        type TEXT DEFAULT 'text',
        topic TEXT DEFAULT '',
        position INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS server_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        nickname TEXT,
        joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (server_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        name TEXT NOT NULL,
        color TEXT DEFAULT '#99AAB5',
        icon TEXT DEFAULT '🛡️',
        is_badge INTEGER DEFAULT 1,
        permissions TEXT DEFAULT '[]',
        position INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS member_roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        UNIQUE (server_id, user_id, role_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        channel_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        content TEXT NOT NULL,
        attachment_url TEXT,
        is_pinned INTEGER DEFAULT 0,
        is_edited INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        emoji TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (message_id, user_id, emoji)
    );

    CREATE TABLE IF NOT EXISTS server_invites (
        code TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        creator_id TEXT NOT NULL,
        uses INTEGER DEFAULT 0,
        max_uses INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        friend_id TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        action_user_id TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (user_id, friend_id)
    );

    CREATE TABLE IF NOT EXISTS direct_messages (
    CREATE TABLE IF NOT EXISTS direct_messages (
        id TEXT PRIMARY KEY,
        sender_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        content TEXT NOT NULL,
        attachment_url TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target_name TEXT,
        reason TEXT,
        details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS applications (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        avatar_url TEXT DEFAULT '',
        banner_url TEXT DEFAULT '',
        token TEXT NOT NULL UNIQUE,
        bot_user_id TEXT NOT NULL,
        public_bot INTEGER DEFAULT 1,
        is_verified INTEGER DEFAULT 0,
        verification_status TEXT DEFAULT 'unverified',
        verification_request_reason TEXT DEFAULT '',
        server_count INTEGER DEFAULT 0,
        permissions_default INTEGER DEFAULT 8,
        slash_commands TEXT DEFAULT '[]',
        webhook_url TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Safe migrations for SQLite
    server_cols = [
        ("banner_url", "TEXT DEFAULT ''"),
        ("banner_color", "TEXT DEFAULT '#1e293b'"),
        ("is_official", "INTEGER DEFAULT 0"),
        ("is_partner", "INTEGER DEFAULT 0"),
        ("is_community", "INTEGER DEFAULT 0"),
        ("boost_level", "INTEGER DEFAULT 0"),
        ("boost_count", "INTEGER DEFAULT 0"),
        ("server_badge_type", "TEXT DEFAULT ''"),
        ("system_channel_id", "TEXT DEFAULT ''"),
        ("protect_config", "TEXT DEFAULT '{}'"),
        ("rules_channel_id", "TEXT DEFAULT ''"),
        ("announcement_channel_id", "TEXT DEFAULT ''"),
    ]
    for col, c_type in server_cols:
        try:
            cursor.execute(f"ALTER TABLE servers ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    user_cols = [
        ("display_name", "TEXT DEFAULT ''"),
        ("banner_url", "TEXT DEFAULT ''"),
        ("banner_color", "TEXT DEFAULT '#5865F2'"),
        ("custom_status", "TEXT DEFAULT 'En ligne'"),
        ("presence_status", "TEXT DEFAULT 'online'"),
        ("global_badges", "TEXT DEFAULT '[]'"),
        ("is_bot", "INTEGER DEFAULT 0"),
        ("is_verified_bot", "INTEGER DEFAULT 0"),
        ("bot_app_id", "TEXT DEFAULT ''"),
        ("orbs_points", "INTEGER DEFAULT 0"),
        ("ads_watched", "INTEGER DEFAULT 0"),
        ("last_orbs_daily", "TEXT DEFAULT ''"),
        ("avatar_decoration", "TEXT DEFAULT ''"),
        ("profile_effect", "TEXT DEFAULT ''"),
        ("profile_frame", "TEXT DEFAULT ''"),
        ("inventory", "TEXT DEFAULT '[]'"),
    ]
    for col, c_type in user_cols:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    message_cols = [
        ("poll_data", "TEXT DEFAULT ''"),
        ("reply_to_id", "TEXT NULL"),
    ]
    for col, c_type in message_cols:
        try:
            cursor.execute(f"ALTER TABLE messages ADD COLUMN {col} {c_type}")
        except Exception:
            pass
    try:
        cursor.execute("ALTER TABLE direct_messages ADD COLUMN reply_to_id TEXT NULL")
    except Exception:
        pass

    channel_cols = [
        ("is_private", "INTEGER DEFAULT 0"),
        ("slowmode", "INTEGER DEFAULT 0"),
        ("content_visibility", "TEXT DEFAULT 'default'"),
        ("is_announcement", "INTEGER DEFAULT 0"),
        ("permissions_data", "TEXT DEFAULT '[]'"),
        ("category_id", "TEXT DEFAULT ''"),
    ]
    for col, c_type in channel_cols:
        try:
            cursor.execute(f"ALTER TABLE channels ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    # Channel Categories table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS channel_categories (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        name TEXT NOT NULL,
        position INTEGER DEFAULT 0,
        collapsed INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Threads table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threads (
        id TEXT PRIMARY KEY,
        channel_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        name TEXT NOT NULL,
        creator_id TEXT NOT NULL,
        is_locked INTEGER DEFAULT 0,
        is_archived INTEGER DEFAULT 0,
        message_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_message_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Thread messages table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS thread_messages (
        id TEXT PRIMARY KEY,
        thread_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        content TEXT NOT NULL,
        attachment_url TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Forum Tags table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS forum_tags (
        id TEXT PRIMARY KEY,
        channel_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        name TEXT NOT NULL,
        emoji TEXT DEFAULT '🏷️',
        color TEXT DEFAULT '#5865F2',
        position INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Forum Posts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS forum_posts (
        id TEXT PRIMARY KEY,
        channel_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        author_id TEXT NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        tags TEXT DEFAULT '[]',
        is_pinned INTEGER DEFAULT 0,
        is_locked INTEGER DEFAULT 0,
        is_solved INTEGER DEFAULT 0,
        reply_count INTEGER DEFAULT 0,
        last_reply_at TEXT DEFAULT CURRENT_TIMESTAMP,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Forum Replies table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soundboard_sounds (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        emoji TEXT DEFAULT '🔊',
        audio_url TEXT NOT NULL,
        volume REAL DEFAULT 1.0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS forum_replies (
        id TEXT PRIMARY KEY,
        post_id TEXT NOT NULL,
        author_id TEXT NOT NULL,
        content TEXT NOT NULL,
        is_solution INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    msg_cols = [
        ("embeds", "TEXT DEFAULT '[]'"),
        ("is_bot_message", "INTEGER DEFAULT 0"),
    ]
    for col, c_type in msg_cols:
        try:
            cursor.execute(f"ALTER TABLE messages ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    role_cols = [
        ("role_style", "TEXT DEFAULT 'solid'"),
    ]
    for col, c_type in role_cols:
        try:
            cursor.execute(f"ALTER TABLE roles ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    server_access_cols = [
        ("access_mode", "TEXT DEFAULT 'invite_only'"),
        ("age_restricted", "INTEGER DEFAULT 0"),
        ("rules_enabled", "INTEGER DEFAULT 0"),
        ("rules_list", "TEXT DEFAULT '[]'"),
        ("automod_rules", "TEXT DEFAULT '[]'"),
        ("welcome_enabled", "INTEGER DEFAULT 0"),
        ("welcome_message", "TEXT DEFAULT ''"),
        ("welcome_channels", "TEXT DEFAULT '[]'"),
    ]
    for col, c_type in server_access_cols:
        try:
            cursor.execute(f"ALTER TABLE servers ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    member_cols = [
        ("server_avatar_url", "TEXT DEFAULT ''"),
        ("server_bio", "TEXT DEFAULT ''"),
        ("rules_accepted", "INTEGER DEFAULT 0"),
        ("rules_accepted_at", "TEXT DEFAULT ''"),
    ]
    for col, c_type in member_cols:
        try:
            cursor.execute(f"ALTER TABLE server_members ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    conn.commit()
    conn.close()


def get_sqlite_conn():
    conn = sqlite3.connect(SQLITE_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA cache_size=10000;")
    return conn


def query(sql, params=None):
    global _shared_mysql_conn
    params = params or ()
    if DB_ENGINE == "mysql":
        conn = get_mysql_conn()
        if not conn:
            return []
        try:
            with conn.cursor() as cursor:
                # Convert sqlite ? style if any
                mysql_sql = sql.replace("?", "%s")
                cursor.execute(mysql_sql, params)
                res = cursor.fetchall()
                # Parse JSON fields and format datetimes
                for row in res:
                    for k, v in list(row.items()):
                        if isinstance(v, (datetime.datetime, datetime.date)):
                            row[k] = v.isoformat()
                        elif k in ('global_badges', 'permissions') and isinstance(v, str):
                            try:
                                row[k] = json.loads(v)
                            except Exception:
                                row[k] = []
                return res
        except Exception:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
            _shared_mysql_conn = None
            raise
    else:
        conn = get_sqlite_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            result = []
            for r in rows:
                d = dict(r)
                for k, v in list(d.items()):
                    if isinstance(v, (datetime.datetime, datetime.date)):
                        d[k] = v.isoformat()
                    elif k in ('global_badges', 'permissions') and isinstance(v, str):
                        try:
                            d[k] = json.loads(v)
                        except Exception:
                            d[k] = []
                result.append(d)
            return result
        finally:
            conn.close()


def query_one(sql, params=None):
    res = query(sql, params)
    return res[0] if res else None


def execute(sql, params=None):
    global _shared_mysql_conn
    params = params or ()
    if DB_ENGINE == "mysql":
        conn = get_mysql_conn()
        if not conn:
            return 0
        try:
            with conn.cursor() as cursor:
                mysql_sql = sql.replace("?", "%s")
                # Format json params
                clean_params = []
                for p in params:
                    if isinstance(p, (dict, list)):
                        clean_params.append(json.dumps(p))
                    else:
                        clean_params.append(p)
                cursor.execute(mysql_sql, tuple(clean_params))
                conn.commit()
                return cursor.lastrowid
        except Exception:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
            _shared_mysql_conn = None
            raise
    else:
        conn = get_sqlite_conn()
        try:
            cursor = conn.cursor()
            clean_params = []
            for p in params:
                if isinstance(p, (dict, list)):
                    clean_params.append(json.dumps(p))
                else:
                    clean_params.append(p)
            cursor.execute(sql, tuple(clean_params))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()


OFFICIAL_SERVER_ID = "devora-official-community"

def ensure_official_server():
    """Crée ou met à jour le serveur officiel de la communauté BASTION"""
    existing = query_one("SELECT * FROM servers WHERE id = ?", (OFFICIAL_SERVER_ID,))
    
    # Trouver le compte du CEO WadeOX
    ceo_user = query_one("SELECT id FROM users WHERE email = 'builder.hugo@gmail.com' OR username = 'WadeOX' LIMIT 1")
    ceo_id = ceo_user["id"] if ceo_user else "3b2b45d7-9268-4e5e-b477-caa75ec65105"

    official_icon = "/static/bastion-logo.png"
    official_banner = "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=1200&q=80"

    if not existing:
        execute("""
            INSERT INTO servers (id, name, icon_url, banner_url, description, owner_id, is_official, is_partner, is_community, boost_level, boost_count)
            VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1, 3, 14)
        """, (
            OFFICIAL_SERVER_ID,
            "BASTION — Officiel",
            official_icon,
            official_banner,
            "Serveur officiel de la communauté BASTION. Annonces, salons d'entraide, événements & discussions !",
            ceo_id
        ))

        # Canaux officiels
        channels = [
            ("bienvenue-et-règles", "text", "📌 Bienvenue sur BASTION ! Prenez connaissance des règles de la communauté."),
            ("annonces-officielles", "text", "📢 Les annonces officielles, nouveautés et informations importantes de BASTION."),
            ("général", "text", "💬 Le salon général pour échanger et faire connaissance avec toute la communauté !"),
            ("mises-à-jour", "text", "🚀 Retrouvez tous les patchs notes, ajouts et évolutions de la plateforme."),
            ("suggestions", "text", "💡 Proposez vos idées et votez pour les fonctionnalités futures de BASTION."),
            ("support-aide", "text", "🛠️ Une question ou un bug ? Notre équipe et la communauté sont là pour vous aider."),
            ("Salon Vocal Général", "voice", "🔊 Venez discuter en vocal avec la communauté."),
            ("Salon Vocal Équipe", "voice", "🔊 Salon réservé à l'équipe et aux modérateurs.")
        ]

        for idx, (c_name, c_type, c_topic) in enumerate(channels):
            cid = f"official-ch-{idx+1}"
            execute("""
                INSERT INTO channels (id, server_id, name, type, topic, position)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cid, OFFICIAL_SERVER_ID, c_name, c_type, c_topic, idx))

        # Rôles officiels
        roles = [
            ("official-role-ceo", "👑 CEO & Fondateur", "#FFB800", "👑", 1, ["ADMINISTRATOR"], 0),
            ("official-role-mod", "🛡️ Équipe Modération", "#10B981", "🛡️", 1, ["MANAGE_MESSAGES"], 1),
            ("official-role-dev", "⚡ Développeur BASTION", "#00F0FF", "⚡", 1, ["MANAGE_CHANNELS"], 2),
            ("official-role-staff", "💜 Staff Officiel", "#A855F7", "💜", 1, ["MANAGE_MESSAGES"], 3),
            ("official-role-vip", "💎 VIP Booster", "#D946EF", "💎", 1, [], 4),
            ("official-role-member", "👥 Membre", "#99AAB5", "👥", 0, [], 5),
        ]

        for r_id, r_name, r_color, r_icon, r_badge, r_perms, r_pos in roles:
            execute("""
                INSERT INTO roles (id, server_id, name, color, icon, is_badge, permissions, position)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (r_id, OFFICIAL_SERVER_ID, r_name, r_color, r_icon, r_badge, r_perms, r_pos))

        # Codes d'invitation permanents
        for code in ["BASTION", "BASTION-OFFICIEL", "DEVORA", "DEVORA-OFFICIEL"]:
            try:
                execute("INSERT INTO server_invites (code, server_id, creator_id) VALUES (?, ?, ?)",
                        (code, OFFICIAL_SERVER_ID, ceo_id))
            except Exception:
                pass
    else:
        execute("""
            UPDATE servers 
            SET name = ?, icon_url = ?, description = ?, is_official = 1, is_partner = 1, is_community = 1, boost_level = 3
            WHERE id = ?
        """, (
            "BASTION — Officiel",
            official_icon,
            "Serveur officiel de la communauté BASTION. Annonces, salons d'entraide, événements & discussions !",
            OFFICIAL_SERVER_ID
        ))

    # Assurer que le CEO a le rôle de fondateur sur le serveur officiel
    if ceo_user:
        add_user_to_official_server(ceo_user["id"])
        try:
            execute("INSERT INTO member_roles (server_id, user_id, role_id) VALUES (?, ?, ?)",
                    (OFFICIAL_SERVER_ID, ceo_user["id"], "official-role-ceo"))
        except Exception:
            pass


def add_user_to_official_server(user_id):
    """Ajoute automatiquement un utilisateur au serveur officiel de la communauté"""
    try:
        existing = query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?",
                             (OFFICIAL_SERVER_ID, user_id))
        if not existing:
            execute("INSERT INTO server_members (server_id, user_id) VALUES (?, ?)",
                    (OFFICIAL_SERVER_ID, user_id))
    except Exception:
        pass


GUARD_BOT_USER_ID = "bastion-guard-official-bot"
GUARD_APP_ID = "bastion-guard-official-app"
PROTECT_BOT_USER_ID = GUARD_BOT_USER_ID
PROTECT_APP_ID = GUARD_APP_ID

def ensure_protect_bot():
    """Crée ou met à jour le bot officiel Bastion Guard et l'associe à l'application officielle"""
    ceo_user = query_one("SELECT id FROM users WHERE email = 'builder.hugo@gmail.com' OR username = 'WadeOX' LIMIT 1")
    ceo_id = ceo_user["id"] if ceo_user else "3b2b45d7-9268-4e5e-b477-caa75ec65105"

    guard_avatar = "/static/protect-logo.png"

    # Nettoyage des anciens enregistrements Protect obsolètes
    try:
        execute("DELETE FROM server_members WHERE user_id IN ('bastion-official-protect-bot', 'fefd6dfb-8ecf-4a56-a398-e7ab62976bea')")
        execute("DELETE FROM messages WHERE user_id IN ('bastion-official-protect-bot', 'fefd6dfb-8ecf-4a56-a398-e7ab62976bea')")
        execute("DELETE FROM applications WHERE id IN ('protect-official-app', 'f2cef19b-a6bc-4bac-9daf-260d7cfdf0ba') OR name = 'Protect'")
        execute("DELETE FROM users WHERE id IN ('bastion-official-protect-bot', 'fefd6dfb-8ecf-4a56-a398-e7ab62976bea') OR username = 'Protect'")
    except Exception:
        pass

    # 1. Bot user in users
    existing_user = query_one("SELECT * FROM users WHERE id = ?", (GUARD_BOT_USER_ID,))
    if not existing_user:
        execute("""
            INSERT INTO users (id, username, display_name, tag, email, password_hash, avatar_url, bio, is_bot, is_verified_bot, bot_app_id, global_badges)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)
        """, (
            GUARD_BOT_USER_ID,
            "BastionGuard",
            "Bastion Guard (Bot Officiel)",
            "0001",
            "guard@bastion.internal",
            "OFFICIAL_BOT_NO_LOGIN",
            guard_avatar,
            "Bastion Guard | Bouclier et gardien officiel de votre serveur. Modération intelligente, protection anti-raid, tickets et accueil 24/7. Développé par Devora Team.",
            GUARD_APP_ID,
            json.dumps(["verified_bot"])
        ))
    else:
        execute("""
            UPDATE users 
            SET username = 'BastionGuard', display_name = 'Bastion Guard (Bot Officiel)', avatar_url = ?, is_bot = 1, is_verified_bot = 1,
                bio = 'Bastion Guard | Bouclier et gardien officiel de votre serveur. Modération intelligente, protection anti-raid, tickets et accueil 24/7. Développé par Devora Team.',
                global_badges = ?
            WHERE id = ?
        """, (guard_avatar, json.dumps(["verified_bot"]), GUARD_BOT_USER_ID))

    # 2. Application in applications
    guard_commands = [
        {"name": "setup", "description": "Configure les fonctionnalités de Bastion Guard (tickets, bienvenue, modération).", "response": "PANEL_SETUP"},
        {"name": "ticket", "description": "Ouvre un ticket d'assistance privé avec l'équipe du serveur.", "response": "CREATE_TICKET"},
        {"name": "mod", "description": "Affiche le statut de sécurité et d'auto-modération Bastion Guard.", "response": "🛡️ **Bastion Guard Modération Active**\n• Anti-Spam : `Activé`\n• Protection Anti-Raid : `Active`\n• Détection de liens malveillants : `Active`\n• Statut infrastructure : `Opérationnel 24/7`"},
        {"name": "help", "description": "Affiche l'aide et les commandes du bot Bastion Guard.", "response": "🛡️ **Bastion Guard (Bot Officiel BASTION)**\n- `/setup` : Assistant interactif de configuration\n- `/ticket` : Ouvrir un ticket de support\n- `/mod` : Vérifier la protection du serveur\n- `/ping` : Latence et état de fonctionnement"},
        {"name": "ping", "description": "Teste la réactivité du bot Bastion Guard.", "response": "🏓 **Pong !** Bastion Guard est en ligne et sécurise votre serveur. Latence : `2ms`."}
    ]
    guard_commands_json = json.dumps(guard_commands)

    existing_app = query_one("SELECT * FROM applications WHERE id = ?", (GUARD_APP_ID,))
    if not existing_app:
        execute("""
            INSERT INTO applications (id, owner_id, name, description, avatar_url, banner_url, token, bot_user_id, public_bot, is_verified, verification_status, server_count, permissions_default, slash_commands)
            VALUES (?, ?, ?, ?, ?, '', ?, ?, 1, 1, 'verified', 1, 8, ?)
        """, (
            GUARD_APP_ID,
            ceo_id,
            "Bastion Guard",
            "Bastion Guard est le bot officiel de modération, sécurité, gestion des tickets et accueil de BASTION. Développé par Devora Team.",
            guard_avatar,
            "BASTION_OFFICIAL_GUARD_TOKEN_DEVORA_2026",
            GUARD_BOT_USER_ID,
            guard_commands_json
        ))
    else:
        execute("""
            UPDATE applications 
            SET name = 'Bastion Guard', description = 'Bastion Guard est le bot officiel de modération, sécurité, gestion des tickets et accueil de BASTION. Développé par Devora Team.',
                avatar_url = ?, is_verified = 1, verification_status = 'verified', public_bot = 1, slash_commands = ?
            WHERE id = ?
        """, (guard_avatar, guard_commands_json, GUARD_APP_ID))

    # 3. Assurer sa présence sur le serveur officiel
    try:
        in_official = query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (OFFICIAL_SERVER_ID, GUARD_BOT_USER_ID))
        if not in_official:
            execute("INSERT INTO server_members (server_id, user_id) VALUES (?, ?)", (OFFICIAL_SERVER_ID, GUARD_BOT_USER_ID))
    except Exception:
        pass


BASTION_SYSTEM_USER_ID = "bastion-official-system-user"

def ensure_bastion_system_user():
    """Crée ou met à jour le compte système officiel BASTION pour diffuser les annonces"""
    existing = query_one("SELECT id FROM users WHERE id = ?", (BASTION_SYSTEM_USER_ID,))
    logo = "/static/bastion-logo.png"
    if not existing:
        execute("""
            INSERT INTO users (id, username, display_name, tag, email, password_hash, avatar_url, bio, is_bot, is_verified_bot, global_badges)
            VALUES (?, 'BASTION', 'BASTION (Officiel)', '0000', 'system@bastion.internal', 'SYSTEM_ACCOUNT_NO_LOGIN', ?, 'Système officiel BASTION. Diffusion des annonces globales et notes de mise à jour.', 1, 1, ?)
        """, (BASTION_SYSTEM_USER_ID, logo, json.dumps(["verified", "developer", "staff"])))
    else:
        execute("""
            UPDATE users 
            SET username = 'BASTION', display_name = 'BASTION (Officiel)', avatar_url = ?, is_bot = 1, is_verified_bot = 1
            WHERE id = ?
        """, (logo, BASTION_SYSTEM_USER_ID))


def get_server_protect_config(server_id: str):
    """Retourne la configuration Protect d'un serveur"""
    s = query_one("SELECT protect_config, system_channel_id, rules_channel_id, announcement_channel_id FROM servers WHERE id = ?", (server_id,))
    if not s:
        return {}
    cfg = s.get("protect_config")
    if isinstance(cfg, str) and cfg.strip():
        try:
            data = json.loads(cfg)
        except Exception:
            data = {}
    elif isinstance(cfg, dict):
        data = cfg
    else:
        data = {}

    data.setdefault("tickets_enabled", True)
    data.setdefault("ticket_channel_id", "")
    data.setdefault("ticket_panel_title", "Support & Assistance")
    data.setdefault("ticket_panel_desc", "Besoin d'aide ou d'une question ? Cliquez sur le bouton ci-dessous pour ouvrir un salon de ticket privé avec l'équipe de modération.")
    data.setdefault("welcome_enabled", True)
    data.setdefault("welcome_channel_id", s.get("system_channel_id") or "")
    data.setdefault("welcome_message", "Bienvenue {user} sur **{server}** ! 🎉 Prends connaissance des règles et passe un excellent moment parmi nous.")
    data.setdefault("automod_enabled", True)
    data.setdefault("anti_spam", True)
    data.setdefault("anti_raid", True)
    data.setdefault("anti_links", False)
    return data


def save_server_protect_config(server_id: str, config: dict):
    """Enregistre la configuration Protect d'un serveur"""
    execute("UPDATE servers SET protect_config = ? WHERE id = ?", (json.dumps(config), server_id))
    return get_server_protect_config(server_id)


def is_protect_in_server(server_id: str) -> bool:
    """Vérifie si Protect est présent sur le serveur"""
    row = query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, PROTECT_BOT_USER_ID))
    return bool(row)


def add_protect_to_server(server_id: str, user_id: str):
    """Ajoute Protect au serveur spécifié et lui attribue un rôle de bot officiel"""
    server = query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return {"success": False, "error": "Serveur introuvable."}

    if server["owner_id"] != user_id:
        member_roles = query("""
            SELECT r.permissions FROM member_roles mr
            JOIN roles r ON mr.role_id = r.id
            WHERE mr.server_id = ? AND mr.user_id = ?
        """, (server_id, user_id))
        is_admin = False
        for r in member_roles:
            perms = r.get("permissions")
            if isinstance(perms, str):
                try: perms = json.loads(perms)
                except Exception: perms = []
            if isinstance(perms, list) and ("ADMINISTRATOR" in perms or "MANAGE_SERVER" in perms):
                is_admin = True
                break
        if not is_admin:
            return {"success": False, "error": "Permissions insuffisantes (Administrateur requis)."}

    existing = query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, PROTECT_BOT_USER_ID))
    if not existing:
        execute("INSERT INTO server_members (server_id, user_id) VALUES (?, ?)", (server_id, PROTECT_BOT_USER_ID))

    protect_role = query_one("SELECT * FROM roles WHERE server_id = ? AND name = ?", (server_id, "🛡️ Protect"))
    if not protect_role:
        role_id = f"protect-role-{server_id[:8]}"
        execute("""
            INSERT INTO roles (id, server_id, name, color, icon, is_badge, permissions, position)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (role_id, server_id, "🛡️ Protect", "#5865F2", "🛡️", 1, json.dumps(["ADMINISTRATOR", "MANAGE_MESSAGES", "MANAGE_CHANNELS"]), 90))
        protect_role = {"id": role_id}

    try:
        execute("INSERT INTO member_roles (server_id, user_id, role_id) VALUES (?, ?, ?)",
                (server_id, PROTECT_BOT_USER_ID, protect_role["id"]))
    except Exception:
        pass

    count_row = query_one("SELECT COUNT(DISTINCT server_id) as count FROM server_members WHERE user_id = ?", (PROTECT_BOT_USER_ID,))
    new_count = count_row["count"] if count_row else 1
    execute("UPDATE applications SET server_count = ? WHERE id = ?", (new_count, PROTECT_APP_ID))

    return {"success": True, "server_name": server["name"]}


def remove_protect_from_server(server_id: str, user_id: str):
    """Retire Protect du serveur"""
    server = query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server or server["owner_id"] != user_id:
        return {"success": False, "error": "Action réservée au propriétaire."}
    execute("DELETE FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, PROTECT_BOT_USER_ID))
    execute("DELETE FROM member_roles WHERE server_id = ? AND user_id = ?", (server_id, PROTECT_BOT_USER_ID))
    return {"success": True}



# ====================================================
# BASTION BOT & DEVELOPER PORTAL ENGINE
# ====================================================

def generate_bot_token(app_id: str) -> str:
    """Génère un token d'authentification bot sécurisé au format Bastion.<app_id>.<random_secret>"""
    secret = os.urandom(24).hex()
    return f"Bastion.{app_id[:8]}.{secret}"


def create_bot_application(owner_id: str, name: str, description: str = "", avatar_url: str = "", public_bot: int = 1):
    """Crée une application développeur et son compte utilisateur Bot associé"""
    app_id = str(uuid.uuid4())
    bot_user_id = str(uuid.uuid4())
    token = generate_bot_token(app_id)
    tag = f"{random.randint(1, 9999):04d}"

    default_avatar = avatar_url or "/static/bastion-logo.png"

    # Créer le compte utilisateur Bot
    execute("""
        INSERT INTO users (id, username, display_name, tag, email, password_hash, avatar_url, bio, is_bot, is_verified_bot, bot_app_id, global_badges)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
    """, (
        bot_user_id,
        name,
        name,
        tag,
        f"bot_{app_id[:8]}@bastion.bot",
        "BOT_NO_LOGIN_PASSWORD_HASH",
        default_avatar,
        description or "Bot officiel propulsé par BASTION Bot Engine.",
        app_id,
        ["developer", "verified"] if False else []
    ))

    # Commandes par défaut
    default_commands = [
        {"name": "help", "description": "Affiche les informations et commandes disponibles du bot.", "response": "🤖 **Commandes disponibles :**\n- `/help` : Affiche ce message d'aide\n- `/ping` : Vérifie la latence du bot\n- `/info` : Informations sur le bot"},
        {"name": "ping", "description": "Teste la réactivité du bot et renvoie Pong !", "response": "🏓 **Pong !** Latence API : `8ms` • Passerelle WebSocket : `100% opérationnelle`."},
        {"name": "info", "description": "Affiche les statistiques et détails du bot BASTION.", "response": f"🏰 **Bot BASTION :** {name}\nCréé avec passion sur le moteur BASTION Bot Framework."}
    ]
    default_commands_json = json.dumps(default_commands)

    # Créer l'application
    execute("""
        INSERT INTO applications (id, owner_id, name, description, avatar_url, banner_url, token, bot_user_id, public_bot, is_verified, verification_status, server_count, permissions_default, slash_commands)
        VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, 0, 'unverified', 0, 8, ?)
    """, (
        app_id,
        owner_id,
        name,
        description,
        default_avatar,
        token,
        bot_user_id,
        public_bot,
        default_commands_json
    ))

    return get_application_by_id(app_id)


def get_user_applications(owner_id: str):
    """Récupère toutes les applications et bots créés par un utilisateur"""
    apps = query("""
        SELECT a.*, u.username as bot_username, u.tag as bot_tag, u.avatar_url as bot_avatar_url, u.is_verified_bot
        FROM applications a
        JOIN users u ON a.bot_user_id = u.id
        WHERE a.owner_id = ?
        ORDER BY a.created_at DESC
    """, (owner_id,))

    for app in apps:
        if isinstance(app.get("slash_commands"), str):
            try:
                app["slash_commands"] = json.loads(app["slash_commands"])
            except Exception:
                app["slash_commands"] = []
    return apps


def get_application_by_id(app_id: str):
    """Récupère une application développeur par son identifiant, client_id ou bot_user_id"""
    if not app_id:
        return None
    app = query_one("""
        SELECT a.*, u.username as bot_username, u.tag as bot_tag, u.avatar_url as bot_avatar_url, u.is_verified_bot
        FROM applications a
        JOIN users u ON a.bot_user_id = u.id
        WHERE a.id = ? OR a.bot_user_id = ?
    """, (str(app_id).strip(), str(app_id).strip()))

    if app:
        if isinstance(app.get("slash_commands"), str):
            try:
                app["slash_commands"] = json.loads(app["slash_commands"])
            except Exception:
                app["slash_commands"] = []
    return app


def get_application_by_token(token: str):
    """Récupère une application et son compte bot via le token d'API"""
    if not token:
        return None
    app = query_one("""
        SELECT a.*, u.username as bot_username, u.tag as bot_tag, u.avatar_url as bot_avatar_url, u.is_verified_bot, u.bio as bot_bio
        FROM applications a
        JOIN users u ON a.bot_user_id = u.id
        WHERE a.token = ?
    """, (token,))
    if app and isinstance(app.get("slash_commands"), str):
        try:
            app["slash_commands"] = json.loads(app["slash_commands"])
        except Exception:
            app["slash_commands"] = []
    return app


def update_application(app_id: str, data: dict):
    """Met à jour les informations d'un bot et de son application"""
    app = get_application_by_id(app_id)
    if not app:
        return None

    name = data.get("name", app["name"]).strip() or app["name"]
    description = data.get("description", app.get("description", ""))
    avatar_url = data.get("avatar_url", app.get("avatar_url", ""))
    banner_url = data.get("banner_url", app.get("banner_url", ""))
    public_bot = 1 if data.get("public_bot", app.get("public_bot", 1)) else 0
    webhook_url = data.get("webhook_url", app.get("webhook_url", ""))
    slash_commands = data.get("slash_commands", app.get("slash_commands", []))

    if isinstance(slash_commands, (list, dict)):
        slash_commands_json = json.dumps(slash_commands)
    else:
        slash_commands_json = str(slash_commands or "[]")

    execute("""
        UPDATE applications
        SET name = ?, description = ?, avatar_url = ?, banner_url = ?, public_bot = ?, webhook_url = ?, slash_commands = ?
        WHERE id = ?
    """, (name, description, avatar_url, banner_url, public_bot, webhook_url, slash_commands_json, app["id"]))

    # Mettre à jour l'utilisateur bot correspondant
    execute("""
        UPDATE users
        SET username = ?, display_name = ?, avatar_url = ?, bio = ?, banner_url = ?
        WHERE id = ?
    """, (name, name, avatar_url or "/static/bastion-logo.png", description, banner_url, app["bot_user_id"]))

    return get_application_by_id(app["id"])


def reset_application_token(app_id: str):
    """Génère un nouveau token secret pour le bot"""
    app = get_application_by_id(app_id)
    if not app:
        return None
    new_token = generate_bot_token(app["id"])
    execute("UPDATE applications SET token = ? WHERE id = ?", (new_token, app["id"]))
    return new_token


def request_bot_verification(app_id: str, reason: str = ""):
    """Traite la demande de vérification officielle d'un bot (auto-certifie si >= 100 serveurs)"""
    app = get_application_by_id(app_id)
    if not app:
        return {"success": False, "error": "Application introuvable"}

    # Recalculer le nombre de serveurs réels
    server_count_row = query_one("""
        SELECT COUNT(DISTINCT server_id) as count
        FROM server_members
        WHERE user_id = ?
    """, (app["bot_user_id"],))
    real_count = server_count_row["count"] if server_count_row else 0

    # Si le bot a au moins 100 serveurs ou est validé par un admin/CEO
    if real_count >= 100:
        execute("""
            UPDATE applications
            SET is_verified = 1, verification_status = 'verified', server_count = ?, verification_request_reason = ?
            WHERE id = ?
        """, (real_count, reason, app["id"]))
        execute("UPDATE users SET is_verified_bot = 1 WHERE id = ?", (app["bot_user_id"],))
        return {
            "success": True,
            "status": "verified",
            "message": f"🎉 Félicitations ! Votre bot a atteint {real_count} serveurs et a reçu le badge officiel de Bot Vérifié !"
        }
    else:
        execute("""
            UPDATE applications
            SET verification_status = 'pending', server_count = ?, verification_request_reason = ?
            WHERE id = ?
        """, (real_count, reason, app["id"]))
        return {
            "success": True,
            "status": "pending",
            "server_count": real_count,
            "message": f"Demande transmise avec succès ({real_count}/100 serveurs). L'équipe BASTION examinera votre bot pour lui attribuer le badge officiel."
        }


def verify_bot_application_admin(app_id: str, is_verified: bool = True):
    """Validation administrative du badge officiel bot vérifié"""
    app = get_application_by_id(app_id)
    if not app:
        return False
    status = 'verified' if is_verified else 'unverified'
    val = 1 if is_verified else 0
    execute("UPDATE applications SET is_verified = ?, verification_status = ? WHERE id = ?", (val, status, app["id"]))
    execute("UPDATE users SET is_verified_bot = ? WHERE id = ?", (val, app["bot_user_id"]))
    return True


def get_all_applications_admin():
    """Récupère toutes les applications et demandes pour le panel CEO/Admin"""
    apps = query("""
        SELECT a.*, u.username as bot_username, u.tag as bot_tag, u.avatar_url as bot_avatar_url, u.is_verified_bot,
               o.username as owner_username, o.tag as owner_tag, o.email as owner_email
        FROM applications a
        JOIN users u ON a.bot_user_id = u.id
        LEFT JOIN users o ON a.owner_id = o.id
        ORDER BY a.created_at DESC
    """)
    for app in apps:
        if isinstance(app.get("slash_commands"), str):
            try:
                app["slash_commands"] = json.loads(app["slash_commands"])
            except Exception:
                app["slash_commands"] = []
    return apps


def delete_application(app_id: str, owner_id: str):
    """Supprime une application et son compte Bot associé"""
    app = query_one("SELECT * FROM applications WHERE id = ? AND owner_id = ?", (app_id, owner_id))
    if not app:
        return False
    bot_uid = app["bot_user_id"]
    execute("DELETE FROM applications WHERE id = ?", (app_id,))
    execute("DELETE FROM users WHERE id = ?", (bot_uid,))
    return True


def get_bot_invite_info(app_id: str):
    """Récupère les informations publiques d'un bot pour l'écran OAuth2 d'invitation"""
    app = get_application_by_id(app_id)
    if not app:
        return None
    
    owner = query_one("SELECT username, tag, avatar_url FROM users WHERE id = ?", (app["owner_id"],))
    return {
        "id": app["id"],
        "name": app["name"],
        "description": app.get("description", ""),
        "avatar_url": app.get("avatar_url") or "/static/bastion-logo.png",
        "bot_user_id": app["bot_user_id"],
        "public_bot": bool(app.get("public_bot", 1)),
        "is_verified": bool(app.get("is_verified", 0)),
        "server_count": app.get("server_count", 0),
        "owner": owner
    }


def add_bot_to_server(app_id: str, server_id: str, user_id: str, permissions: int = 8):
    """Ajoute un bot à un serveur (vérifie les droits d'administration de l'utilisateur)"""
    app = get_application_by_id(app_id)
    if not app:
        return {"success": False, "error": "Bot introuvable"}

    # Vérifier si l'utilisateur a les droits d'administrateur ou est le propriétaire du serveur
    server = query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not server:
        return {"success": False, "error": "Serveur introuvable"}

    is_owner = (server["owner_id"] == user_id)
    is_admin = False
    
    member_roles = query("""
        SELECT r.permissions FROM member_roles mr
        JOIN roles r ON mr.role_id = r.id
        WHERE mr.server_id = ? AND mr.user_id = ?
    """, (server_id, user_id))

    for r in member_roles:
        perms = r.get("permissions")
        if isinstance(perms, str):
            try:
                perms = json.loads(perms)
            except Exception:
                perms = []
        if isinstance(perms, list) and ("ADMINISTRATOR" in perms or "MANAGE_SERVER" in perms or "MANAGE_CHANNELS" in perms):
            is_admin = True
            break

    if not is_owner and not is_admin:
        return {"success": False, "error": "Vous devez être administrateur ou propriétaire du serveur pour ajouter des bots."}

    bot_uid = app["bot_user_id"]

    # Vérifier si le bot est déjà sur le serveur
    existing = query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, bot_uid))
    if existing:
        return {"success": False, "error": f"{app['name']} est déjà présent sur ce serveur."}

    # Ajouter le bot au serveur
    execute("INSERT INTO server_members (server_id, user_id) VALUES (?, ?)", (server_id, bot_uid))

    # Mettre à jour le compteur de serveurs
    count_row = query_one("SELECT COUNT(DISTINCT server_id) as count FROM server_members WHERE user_id = ?", (bot_uid,))
    new_count = count_row["count"] if count_row else 1
    execute("UPDATE applications SET server_count = ? WHERE id = ?", (new_count, app_id))

    # Si le bot atteint 100 serveurs, auto-certification automatique !
    if new_count >= 100 and not app.get("is_verified"):
        execute("UPDATE applications SET is_verified = 1, verification_status = 'verified' WHERE id = ?", (app_id,))
        execute("UPDATE users SET is_verified_bot = 1 WHERE id = ?", (bot_uid,))

    return {
        "success": True,
        "bot_name": app["name"],
        "server_name": server["name"],
        "server_count": new_count,
        "is_verified": bool(app.get("is_verified", 0) or new_count >= 100)
    }


def get_channel_slash_commands(channel_id: str):
    """Retourne toutes les commandes slash disponibles dans un salon (issues de tous les bots présents)"""
    channel = query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        return []

    server_id = channel["server_id"]
    
    # Trouver tous les bots membres du serveur
    bots = query("""
        SELECT a.id as app_id, a.name as bot_name, a.avatar_url as bot_avatar, a.is_verified, a.slash_commands, u.id as bot_user_id, u.username, u.tag
        FROM server_members sm
        JOIN users u ON sm.user_id = u.id
        JOIN applications a ON a.bot_user_id = u.id
        WHERE sm.server_id = ? AND u.is_bot = 1
    """, (server_id,))

    all_commands = []
    for b in bots:
        cmds = b.get("slash_commands")
        if isinstance(cmds, str):
            try:
                cmds = json.loads(cmds)
            except Exception:
                cmds = []
        if isinstance(cmds, list):
            for cmd in cmds:
                all_commands.append({
                    "bot_id": b["app_id"],
                    "bot_user_id": b["bot_user_id"],
                    "bot_name": b["bot_name"],
                    "bot_avatar": b.get("bot_avatar") or "/static/bastion-logo.png",
                    "is_verified": bool(b.get("is_verified", 0)),
                    "name": cmd.get("name", "").strip().lstrip("/"),
                    "description": cmd.get("description", "Commande BASTION Bot"),
                    "response": cmd.get("response", "")
                })

    return all_commands


def execute_bot_command(bot_user_id: str, channel_id: str, server_id: str, cmd_name: str, sender_user_id: str, args_text: str = ""):
    """Exécute une commande de bot et enregistre la réponse dans le salon"""
    bot_user = query_one("SELECT * FROM users WHERE id = ? AND is_bot = 1", (bot_user_id,))
    if not bot_user:
        return None

    app = query_one("SELECT * FROM applications WHERE bot_user_id = ?", (bot_user_id,))
    if not app:
        return None

    cmds = app.get("slash_commands")
    if isinstance(cmds, str):
        try:
            cmds = json.loads(cmds)
        except Exception:
            cmds = []

    target_cmd = None
    clean_cmd = cmd_name.strip().lower().lstrip("/")
    for c in cmds:
        if c.get("name", "").strip().lower().lstrip("/") == clean_cmd:
            target_cmd = c
            break

    sender = query_one("SELECT username, display_name FROM users WHERE id = ?", (sender_user_id,))
    sender_name = sender.get("display_name") or sender.get("username") if sender else "Utilisateur"

    response_text = ""
    embeds = []
    components = []

    if bot_user_id == PROTECT_BOT_USER_ID:
        srv = query_one("SELECT name FROM servers WHERE id = ?", (server_id,))
        srv_name = srv["name"] if srv else "le serveur"

        if clean_cmd == "setup":
            response_text = ""
            embeds = [{
                "title": f"🛡️ Assistant de Configuration Protect",
                "description": f"Bienvenue dans l'assistant Protect pour **{srv_name}**.\n\nConfigurez les fonctionnalités de sécurité et d'animation en quelques clics :",
                "color": "#5865F2",
                "thumbnail": {"url": "/static/protect-logo.png"},
                "fields": [
                    {"name": "🎟️ Système de Tickets", "value": "Créez des salons privés de support en 1 clic pour vos membres.", "inline": False},
                    {"name": "👋 Messages d'Accueil", "value": "Accueillez automatiquement chaque nouvel arrivant avec un message personnalisé.", "inline": False},
                    {"name": "🛡️ Auto-Modération 24/7", "value": "Protégez votre communauté contre les spams, attaques et liens malveillants.", "inline": False}
                ],
                "footer": {"text": "Protect Bot Officiel • Devora Team"}
            }]
            components = [{
                "type": 1,
                "components": [
                    {"type": 2, "style": 1, "custom_id": "protect_setup_tickets", "label": "🎟️ Configurer Tickets", "emoji": "🎟️"},
                    {"type": 2, "style": 1, "custom_id": "protect_setup_welcome", "label": "👋 Configurer Accueil", "emoji": "👋"},
                    {"type": 2, "style": 2, "custom_id": "protect_setup_settings", "label": "⚙️ Intégrations Serveur", "emoji": "⚙️"}
                ]
            }]
        elif clean_cmd == "ticket":
            response_text = ""
            embeds = [{
                "title": "📩 Support & Tickets d'assistance",
                "description": "Besoin d'aide ou d'une question pour l'équipe du serveur ? Cliquez sur le bouton ci-dessous pour ouvrir un ticket privé avec les modérateurs.",
                "color": "#5865F2",
                "thumbnail": {"url": "/static/protect-logo.png"},
                "footer": {"text": "Système de Ticket BASTION • Propulsé par Protect"}
            }]
            components = [{
                "type": 1,
                "components": [
                    {"type": 2, "style": 1, "custom_id": "protect_open_ticket", "label": "📩 Ouvrir un ticket", "emoji": "📩"}
                ]
            }]
        elif clean_cmd == "mod":
            response_text = "🛡️ **Protect Modération Active**\n• Anti-Spam : `Activé`\n• Protection Anti-Raid : `Active`\n• Détection de liens malveillants : `Active`\n• Statut infrastructure : `Opérationnel 24/7`"
        elif clean_cmd == "ping":
            response_text = "🏓 **Pong !** Protect est en ligne et sécurise votre serveur. Latence : `2ms`."
        else:
            response_text = "🛡️ **Protect (Bot Officiel BASTION)**\n- `/setup` : Assistant interactif de configuration\n- `/ticket` : Ouvrir un ticket de support\n- `/mod` : Vérifier la protection du serveur\n- `/ping` : Latence et état de fonctionnement"
    elif target_cmd:
        response_text = target_cmd.get("response", f"Commande `/{clean_cmd}` exécutée avec succès.")
        # Remplacement dynamique de variables
        response_text = response_text.replace("{user}", f"**@{sender_name}**")
        response_text = response_text.replace("{args}", args_text)
    else:
        # Commandes globales intégrées par défaut
        if clean_cmd == "ping":
            response_text = f"🏓 **Pong !** Latence websocket : `11ms` • Bot réactif pour @{sender_name}."
        elif clean_cmd == "help":
            response_text = f"🤖 **Aide de {app['name']} :**\nUtilisez les commandes du bot pour interagir dans ce salon !"
        else:
            response_text = f"⚙️ Commande `/{clean_cmd}` reçue par **{app['name']}**."

    # Créer le message du bot dans la base de données
    msg_id = str(uuid.uuid4())
    execute("""
        INSERT INTO messages (id, channel_id, server_id, user_id, content, is_bot_message, embeds, components)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (msg_id, channel_id, server_id, bot_user_id, response_text, json.dumps(embeds) if embeds else None, json.dumps(components) if components else None))

    return {
        "id": msg_id,
        "channel_id": channel_id,
        "server_id": server_id,
        "user_id": bot_user_id,
        "username": bot_user["username"],
        "display_name": bot_user.get("display_name") or bot_user["username"],
        "tag": bot_user["tag"],
        "avatar_url": bot_user.get("avatar_url") or "/static/bastion-logo.png",
        "banner_color": bot_user.get("banner_color", "#5865F2"),
        "is_bot": 1,
        "is_verified_bot": bot_user.get("is_verified_bot", 0),
        "content": response_text,
        "embeds": embeds,
        "components": components,
        "created_at": datetime.datetime.now().isoformat()
    }


def get_discord_user(user_id):
    u = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not u:
        return None
    return {
        "id": str(u["id"]),
        "username": u["username"],
        "discriminator": str(u.get("tag") or "0000"),
        "global_name": u.get("display_name") or u["username"],
        "avatar": u.get("avatar_url"),
        "bot": bool(u.get("is_bot", 0)),
        "system": False,
        "mfa_enabled": False,
        "banner": u.get("banner_url"),
        "accent_color": None,
        "locale": "fr",
        "verified": True,
        "flags": 0,
        "premium_type": 0,
        "public_flags": 0
    }


def get_discord_channel(channel_id):
    c = query_one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not c:
        return None
    ch_type = 0  # GUILD_TEXT
    if c.get("type") == "voice":
        ch_type = 2  # GUILD_VOICE
    elif c.get("type") == "stage":
        ch_type = 13  # GUILD_STAGE_VOICE
    elif c.get("type") == "announcement":
        ch_type = 5  # GUILD_ANNOUNCEMENT

    return {
        "id": str(c["id"]),
        "type": ch_type,
        "guild_id": str(c["server_id"]),
        "name": c["name"],
        "topic": c.get("topic") or "",
        "position": c.get("position", 0),
        "rate_limit_per_user": c.get("slowmode", 0),
        "nsfw": False,
        "permission_overwrites": []
    }


def get_discord_member(server_id, user_id):
    m = query_one("SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, user_id))
    u = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not u:
        return None
    
    roles_raw = query("SELECT role_id FROM member_roles WHERE server_id = ? AND user_id = ?", (server_id, user_id))
    roles = [str(r["role_id"]) for r in roles_raw]

    joined_at = m["joined_at"].isoformat() if m and m.get("joined_at") and hasattr(m["joined_at"], "isoformat") else datetime.datetime.utcnow().isoformat()

    return {
        "user": get_discord_user(user_id),
        "nick": m.get("nickname") if m else None,
        "avatar": None,
        "roles": roles,
        "joined_at": joined_at,
        "deaf": False,
        "mute": False,
        "flags": 0,
        "pending": False,
        "permissions": "8"
    }


def get_discord_guild(server_id):
    s = query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if not s:
        return None
    
    channels_raw = query("SELECT * FROM channels WHERE server_id = ? ORDER BY position ASC", (server_id,))
    channels = [get_discord_channel(c["id"]) for c in channels_raw if c]

    roles_raw = query("SELECT * FROM roles WHERE server_id = ? ORDER BY position ASC", (server_id,))
    roles = []
    for r in roles_raw:
        roles.append({
            "id": str(r["id"]),
            "name": r["name"],
            "color": int(r.get("color", "#99AAB5").replace("#", ""), 16) if r.get("color", "").startswith("#") else 0,
            "hoist": False,
            "position": r.get("position", 0),
            "permissions": "8",
            "managed": False,
            "mentionable": True
        })

    # Everyone role placeholder
    roles.insert(0, {
        "id": str(server_id),
        "name": "@everyone",
        "color": 0,
        "hoist": False,
        "position": 0,
        "permissions": "1071698660929",
        "managed": False,
        "mentionable": False
    })

    members_raw = query("SELECT user_id FROM server_members WHERE server_id = ?", (server_id,))
    members = [get_discord_member(server_id, m["user_id"]) for m in members_raw if m]

    return {
        "id": str(s["id"]),
        "name": s["name"],
        "icon": s.get("icon_url"),
        "description": s.get("description"),
        "owner_id": str(s["owner_id"]),
        "roles": roles,
        "emojis": [],
        "features": ["COMMUNITY"] if s.get("is_community") else [],
        "channels": channels,
        "members": members,
        "member_count": len(members),
        "system_channel_id": s.get("system_channel_id"),
        "verification_level": 0
    }


def get_bot_guilds_discord(bot_user_id):
    servers = query("""
        SELECT s.* FROM servers s
        JOIN server_members sm ON s.id = sm.server_id
        WHERE sm.user_id = ?
    """, (bot_user_id,))
    return [get_discord_guild(s["id"]) for s in servers if s]


def add_audit_log(server_id, user_id, action_type, target_name=None, reason=None, details=None):
    try:
        details_str = json.dumps(details) if details and not isinstance(details, str) else (details or None)
        execute("""
            INSERT INTO audit_logs (server_id, user_id, action_type, target_name, reason, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """ if DB_ENGINE == "sqlite" else """
            INSERT INTO audit_logs (server_id, user_id, action_type, target_name, reason, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, NOW())
        """, (server_id, user_id, action_type, target_name, reason, details_str))
        return True
    except Exception as e:
        print(f"[AUDIT LOG ERROR] {e}")
        return False


def get_server_audit_logs(server_id, limit=50):
    try:
        logs = query("""
            SELECT al.*, u.username, u.display_name, u.avatar_url, u.tag
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE al.server_id = ?
            ORDER BY al.created_at DESC
            LIMIT ?
        """, (server_id, limit))
        result = []
        for l in logs:
            det = l.get("details")
            if det and isinstance(det, str):
                try:
                    det = json.loads(det)
                except Exception:
                    pass
            result.append({
                "id": l.get("id"),
                "server_id": l.get("server_id"),
                "user_id": l.get("user_id"),
                "username": l.get("username") or "Utilisateur inconnu",
                "display_name": l.get("display_name") or l.get("username") or "Utilisateur",
                "avatar_url": l.get("avatar_url"),
                "tag": l.get("tag") or "0000",
                "action_type": l.get("action_type"),
                "target_name": l.get("target_name"),
                "reason": l.get("reason"),
                "details": det,
                "created_at": str(l.get("created_at") or "")
            })
        return result
    except Exception as e:
        print(f"[GET AUDIT LOGS ERROR] {e}")
        return []


