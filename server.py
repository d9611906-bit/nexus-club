#!/usr/bin/env python3
# NEXUS CLUB — back-end (Python stdlib)
# API регистрации/входа, пароли через PBKDF2, сессии на cookie, SQLite-база.
import base64, hashlib, hmac, json, os, secrets, sqlite3, socket, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "nexus.db"
INDEX_HTML = BASE_DIR / "index.html"
COOKIE = "nexus_session"
SESSION_TTL = 60 * 60 * 24 * 7  # 7 дней
PBKDF2_ITER = 240000

# ---------------- База ----------------
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.execute("CREATE TABLE IF NOT EXISTS users ("
              "id INTEGER PRIMARY KEY AUTOINCREMENT,"
              "login TEXT UNIQUE NOT NULL,"
              "pass TEXT NOT NULL,"
              "name TEXT,"
              "role TEXT DEFAULT 'Игрок',"
              "admin INTEGER DEFAULT 0,"
              "created_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS sessions ("
              "token TEXT PRIMARY KEY,"
              "user_id INTEGER NOT NULL,"
              "expires REAL NOT NULL)")
    # Миграция: добавляем колонку role в уже существующую таблицу
    cols = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
    if "role" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'Игрок'")
    c.execute("CREATE TABLE IF NOT EXISTS scores ("
              "user_id INTEGER NOT NULL,"
              "name TEXT NOT NULL,"
              "score INTEGER NOT NULL,"
              "created_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS presence ("
              "client_id TEXT PRIMARY KEY,"
              "user_id INTEGER,"
              "name TEXT,"
              "last_seen REAL NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS forum_threads ("
              "id INTEGER PRIMARY KEY AUTOINCREMENT,"
              "author_id INTEGER NOT NULL,"
              "author_name TEXT NOT NULL,"
              "title TEXT NOT NULL,"
              "body TEXT NOT NULL,"
              "created_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS forum_posts ("
              "id INTEGER PRIMARY KEY AUTOINCREMENT,"
              "thread_id INTEGER NOT NULL,"
              "author_id INTEGER NOT NULL,"
              "author_name TEXT NOT NULL,"
              "body TEXT NOT NULL,"
              "created_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS profile_meta ("
              "user_id INTEGER PRIMARY KEY,"
              "status TEXT DEFAULT '',"
              "bio TEXT DEFAULT '',"
              "avatar_color TEXT DEFAULT '')")
    c.execute("CREATE TABLE IF NOT EXISTS activity_log ("
              "id INTEGER PRIMARY KEY AUTOINCREMENT,"
              "user_id INTEGER NOT NULL,"
              "action TEXT NOT NULL,"
              "at TEXT NOT NULL)")
    c.commit()
    c.close()

# ---------------- Пароли ----------------
def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()

def verify_password(password, stored):
    try:
        salt_b64, dk_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER, len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# ---------------- Сессии ----------------
def create_session(user_id):
    token = secrets.token_urlsafe(32)
    c = db()
    c.execute("DELETE FROM sessions WHERE user_id=? AND expires < ?", (user_id, __import__("time").time()))
    c.execute("INSERT INTO sessions (token, user_id, expires) VALUES (?,?,?)",
              (token, user_id, __import__("time").time() + SESSION_TTL))
    c.commit()
    c.close()
    return token, SESSION_TTL

def user_from_session(token):
    if not token:
        return None
    c = db()
    row = c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
                    "WHERE s.token=? AND s.expires>?", (token, __import__("time").time())).fetchone()
    c.close()
    return row

ONLINE_WINDOW = 45  # сек: столько «жив» человек после последнего пульса

def now_iso():
    return __import__("datetime").datetime.now().isoformat()

def log_activity(user_id, action):
    c = db()
    c.execute("INSERT INTO activity_log (user_id, action, at) VALUES (?,?,?)",
              (user_id, action, now_iso()))
    c.commit()
    c.close()

def user_achievements(u):
    # Достижения считаются динамически по данным пользователя
    c = db()
    posts = c.execute("SELECT COUNT(*) FROM forum_posts WHERE author_id=?", (u["id"],)).fetchone()[0]
    threads = c.execute("SELECT COUNT(*) FROM forum_threads WHERE author_id=?", (u["id"],)).fetchone()[0]
    score_row = c.execute("SELECT MAX(score) FROM scores WHERE user_id=?", (u["id"],)).fetchone()[0]
    last = c.execute("SELECT at FROM activity_log WHERE user_id=? ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
    c.close()
    now = __import__("time").time()
    ach = []
    def add(code, title, desc, earned):
        if earned:
            ach.append({"code": code, "title": title, "desc": desc, "earned": True})
    add("member", "Член сообщества", "Создали аккаунт на сервере", True)
    add("forum", "Автор", "Написали сообщение на форуме", posts > 0)
    add("thread", "Движок форума", "Создали тему на форуме", threads > 0)
    add("gamer", "Геймер", "Набрали очки в мини-игре", bool(score_row and score_row > 0))
    if score_row:
        add("pro", "Рекордсмен", "Счёт в игре от 100 очков", score_row >= 100)
        add("legend", "Легенда", "Счёт в игре от 300 очков", score_row >= 300)
    return ach

def profile_summary(u):
    c = db()
    meta = c.execute("SELECT * FROM profile_meta WHERE user_id=?", (u["id"],)).fetchone()
    posts = c.execute("SELECT COUNT(*) FROM forum_posts WHERE author_id=?", (u["id"],)).fetchone()[0]
    threads = c.execute("SELECT COUNT(*) FROM forum_threads WHERE author_id=?", (u["id"],)).fetchone()[0]
    best = c.execute("SELECT MAX(score) FROM scores WHERE user_id=?", (u["id"],)).fetchone()[0]
    on = c.execute("SELECT COUNT(*) FROM presence WHERE user_id=? AND last_seen>?",
                   (u["id"], __import__("time").time() - ONLINE_WINDOW)).fetchone()[0] > 0
    c.close()
    return {
        "id": u["id"], "login": u["login"], "name": u["name"],
        "role": u["role"] or "Игрок", "admin": u["admin"],
        "joined": u["created_at"], "status": (meta["status"] if meta else "") or "",
        "bio": (meta["bio"] if meta else "") or "",
        "avatar_color": (meta["avatar_color"] if meta else "") or "",
        "online": on, "posts": posts, "threads": threads, "best_score": best or 0,
        "achievements": user_achievements(u)
    }

# ---------------- HTTP ----------------

PRESENCE_ONLINE_WINDOW = ONLINE_WINDOW

def touch_presence(client_id, user_id, name):
    c = db()
    c.execute("DELETE FROM presence WHERE last_seen < ?",
              (__import__("time").time() - ONLINE_WINDOW * 3,))
    c.execute("INSERT OR REPLACE INTO presence (client_id, user_id, name, last_seen) VALUES (?,?,?,?)",
              (client_id, user_id, name, __import__("time").time()))
    c.commit()
    c.close()

def count_online():
    c = db()
    n = c.execute("SELECT COUNT(*) FROM presence WHERE last_seen > ?",
                  (__import__("time").time() - ONLINE_WINDOW,)).fetchone()[0]
    c.close()
    return n

# ---------------- HTTP ----------------
class Handler(BaseHTTPRequestHandler):
    server_version = "NexusServer/1.0"

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, payload, headers=None):
        self._send(code, json.dumps(payload, ensure_ascii=False), headers=headers)

    def _read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        if n <= 0:
            return {}
        body = self.rfile.read(n).decode("utf-8")
        try:
            return json.loads(body)
        except Exception:
            return {}

    def _cookie_headers(self, token, ttl):
        # Secure флаг включается только при HTTPS (в проде). Включаем его, когда
        # задана переменная PRODUCTION=1 (например, на Render).
        secure = " Secure;" if os.environ.get("PRODUCTION") == "1" else ""
        return {"Set-Cookie": f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax;{secure} Max-Age={ttl}"}

    def log_message(self, *a):
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html", "/index"):
            self._serve_index()
        elif path == "/api/me":
            token = self._cookie()
            u = user_from_session(token)
            if u:
                self._json(200, {"ok": True, "user": {"id": u["id"], "login": u["login"], "name": u["name"], "role": u["role"] or "Игрок", "admin": u["admin"]}})
            else:
                self._json(200, {"ok": False, "user": None})
        elif path == "/api/members":
            token = self._cookie()
            u = user_from_session(token)
            if not u:
                self._json(401, {"ok": False, "error": "Требуется вход"})
                return
            c = db()
            rows = c.execute("SELECT login, name, role FROM users ORDER BY id").fetchall()
            c.close()
            members = [{"name": r["name"] or r["login"], "role": r["role"] or "Игрок", "online": True}
                       for r in rows]
            self._json(200, {"ok": True, "members": members})
        elif path == "/api/stats":
            c = db()
            total = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            c.close()
            on = count_online()
            self._json(200, {"ok": True, "members": total, "online": on})
        elif path == "/api/game/top":
            c = db()
            rows = c.execute("SELECT name, MAX(score) AS best FROM scores "
                             "GROUP BY user_id ORDER BY best DESC LIMIT 10").fetchall()
            c.close()
            top = [{"name": r["name"], "score": r["best"]} for r in rows]
            self._json(200, {"ok": True, "top": top})
        elif path == "/api/forum/threads":
            c = db()
            rows = c.execute("SELECT t.id, t.title, t.author_name, t.created_at, "
                             "(SELECT COUNT(*) FROM forum_posts p WHERE p.thread_id=t.id) AS posts "
                             "FROM forum_threads t ORDER BY t.id DESC").fetchall()
            c.close()
            threads = [{"id": r["id"], "title": r["title"], "author": r["author_name"],
                        "created_at": r["created_at"], "posts": r["posts"]} for r in rows]
            self._json(200, {"ok": True, "threads": threads})
        elif path.startswith("/api/forum/threads/"):
            try:
                tid = int(parsed.path.split("/")[-1])
            except ValueError:
                self._json(400, {"ok": False, "error": "Неверный id"}); return
            c = db()
            t = c.execute("SELECT * FROM forum_threads WHERE id=?", (tid,)).fetchone()
            if not t:
                c.close(); self._json(404, {"ok": False, "error": "Тема не найдена"}); return
            posts = c.execute("SELECT * FROM forum_posts WHERE thread_id=? ORDER BY id", (tid,)).fetchall()
            c.close()
            self._json(200, {"ok": True, "thread":
                {"id": t["id"], "title": t["title"], "body": t["body"], "author": t["author_name"],
                 "created_at": t["created_at"]},
                "posts": [{"id": p["id"], "author": p["author_name"], "body": p["body"],
                           "created_at": p["created_at"]} for p in posts]})
        elif path == "/api/profile":
            token = self._cookie()
            u = user_from_session(token)
            if not u:
                self._json(401, {"ok": False, "error": "Требуется вход"}); return
            self._json(200, {"ok": True, "profile": profile_summary(u)})
        else:
            self._json(404, {"ok": False, "error": "Не найдено"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/register":
            data = self._read_json()
            login = (data.get("login") or "").strip()
            password = data.get("password") or ""
            name = (data.get("name") or "").strip()
            if len(login) < 3:
                self._json(400, {"ok": False, "error": "Логин слишком короткий (минимум 3 символа)"}); return
            if len(password) < 4:
                self._json(400, {"ok": False, "error": "Пароль минимум 4 символа"}); return
            c = db()
            try:
                c.execute("INSERT INTO users (login, pass, name, created_at) VALUES (?,?,?,?)",
                          (login, hash_password(password), name or login,
                           __import__("datetime").datetime.now().isoformat()))
            except sqlite3.IntegrityError:
                c.close()
                self._json(409, {"ok": False, "error": "Такой логин уже занят"}); return
            c.commit()
            uid = c.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone()[0]
            c.close()
            token, ttl = create_session(uid)
            self._json(200, {"ok": True, "user": {"id": uid, "login": login, "name": name or login}},
                       headers=self._cookie_headers(token, ttl))
        elif path == "/api/login":
            data = self._read_json()
            login = (data.get("login") or "").strip()
            password = data.get("password") or ""
            c = db()
            row = c.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
            c.close()
            if not row or not verify_password(password, row["pass"]):
                self._json(401, {"ok": False, "error": "Неверный логин или пароль"}); return
            token, ttl = create_session(row["id"])
            self._json(200, {"ok": True, "user": {"id": row["id"], "login": row["login"], "name": row["name"], "role": row["role"] or "Игрок", "admin": row["admin"]}},
                       headers=self._cookie_headers(token, ttl))
        elif path == "/api/logout":
            token = self._cookie()
            if token:
                c = db(); c.execute("DELETE FROM sessions WHERE token=?", (token,)); c.commit(); c.close()
            self._json(200, {"ok": True}, headers={"Set-Cookie": f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"})
        elif path == "/api/game/score":
            token = self._cookie()
            u = user_from_session(token)
            if not u:
                self._json(401, {"ok": False, "error": "Требуется вход"}); return
            data = self._read_json()
            score = int(data.get("score") or 0)
            if score < 0:
                score = 0
            c = db()
            c.execute("INSERT INTO scores (user_id, name, score, created_at) VALUES (?,?,?,?)",
                      (u["id"], u["name"] or u["login"], score, __import__("datetime").datetime.now().isoformat()))
            c.commit(); c.close()
            self._json(200, {"ok": True, "best": score})
        elif path == "/api/heartbeat":
            data = self._read_json()
            client_id = (data.get("client") or "").strip()[:64]
            if not client_id:
                self._json(400, {"ok": False, "error": "Нет client"}); return
            token = self._cookie()
            u = user_from_session(token)
            touch_presence(client_id, u["id"] if u else None, (u["name"] or u["login"]) if u else None)
            self._json(200, {"ok": True, "online": count_online(), "me": (u["login"] if u else None)})
        elif path == "/api/forum/threads":
            token = self._cookie()
            u = user_from_session(token)
            if not u:
                self._json(401, {"ok": False, "error": "Требуется вход"}); return
            data = self._read_json()
            title = (data.get("title") or "").strip()
            body = (data.get("body") or "").strip()
            if not title or not body:
                self._json(400, {"ok": False, "error": "Заполните заголовок и текст"}); return
            c = db()
            c.execute("INSERT INTO forum_threads (author_id, author_name, title, body, created_at) VALUES (?,?,?,?,?)",
                      (u["id"], u["name"] or u["login"], title, body, now_iso()))
            c.commit(); c.close()
            log_activity(u["id"], "create_thread")
            self._json(200, {"ok": True})
        elif path.startswith("/api/forum/threads/"):
            try:
                tid = int(parsed.path.split("/")[-1])
            except ValueError:
                self._json(400, {"ok": False, "error": "Неверный id"}); return
            token = self._cookie()
            u = user_from_session(token)
            if not u:
                self._json(401, {"ok": False, "error": "Требуется вход"}); return
            data = self._read_json()
            body = (data.get("body") or "").strip()
            if not body:
                self._json(400, {"ok": False, "error": "Пустое сообщение"}); return
            c = db()
            t = c.execute("SELECT id FROM forum_threads WHERE id=?", (tid,)).fetchone()
            if not t:
                c.close(); self._json(404, {"ok": False, "error": "Тема не найдена"}); return
            c.execute("INSERT INTO forum_posts (thread_id, author_id, author_name, body, created_at) VALUES (?,?,?,?,?)",
                      (tid, u["id"], u["name"] or u["login"], body, now_iso()))
            c.commit(); c.close()
            log_activity(u["id"], "forum_post")
            self._json(200, {"ok": True})
        elif path == "/api/profile/save":
            token = self._cookie()
            u = user_from_session(token)
            if not u:
                self._json(401, {"ok": False, "error": "Требуется вход"}); return
            data = self._read_json()
            status = (data.get("status") or "").strip()[:80]
            bio = (data.get("bio") or "").strip()[:300]
            color = (data.get("avatar_color") or "").strip()[:20]
            c = db()
            c.execute("INSERT INTO profile_meta (user_id, status, bio, avatar_color) VALUES (?,?,?,?) "
                      "ON CONFLICT(user_id) DO UPDATE SET status=?, bio=?, avatar_color=?",
                      (u["id"], status, bio, color, status, bio, color))
            c.commit(); c.close()
            log_activity(u["id"], "update_profile")
            self._json(200, {"ok": True})
        else:
            self._json(404, {"ok": False, "error": "Не найдено"})

    def _cookie(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(COOKIE + "="):
                return part[len(COOKIE) + 1:]
        return None

    def _serve_index(self):
        if INDEX_HTML.exists():
            with open(INDEX_HTML, "rb") as f:
                self._send(200, f.read(), ctype="text/html; charset=utf-8")
        else:
            self._json(500, {"ok": False, "error": "index.html не найден"})

def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("Сервер NEXUS CLUB запущен:")
    print(f"  Локально:  http://localhost:{port}")
    print(f"  В сети:    http://{local_ip()}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлен.")