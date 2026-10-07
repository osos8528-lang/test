"""Campus Todo API.
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

Run: python -m uvicorn main:app --reload
The unsafe training conventions are replaced with bound SQL, salted password
hashes, expiring tokens and WAL. Set ADMIN_PASSWORD before starting the app.
"""
from contextlib import asynccontextmanager, contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator

APP_NAME = "Campus Todo API"
APP_VERSION = "0.2.0"
DB_FILE = os.getenv("DB_FILE", str(Path(__file__).with_name("service.db")))
PASSWORD_ITERATIONS = 600_000
SESSION_SECONDS = 3600
BLOCKED_TAGS = frozenset({"spam", "ad", "private", "temp"})
bearer = HTTPBearer(auto_error=False)


def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextmanager
def database():
    conn = get_db_connection()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    with database() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT,
                owner_username TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                is_completed INTEGER NOT NULL DEFAULT 0 CHECK(is_completed IN (0, 1)),
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                tags TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        """)


def hash_credential(raw_secret: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return "$".join(("pbkdf2_sha256", str(PASSWORD_ITERATIONS), salt.hex(), digest.hex()))


def verify_credential(raw_secret: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored_hash.split("$")
        rounds = int(iterations)
        if algorithm != "pbkdf2_sha256" or not 1 <= rounds <= 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", raw_secret.encode("utf-8"), bytes.fromhex(salt), rounds
        ).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    admin_password = os.getenv("ADMIN_PASSWORD")
    application.state.admin_password_hash = hash_credential(admin_password) if admin_password else None
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)


def issue_token(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = time.time()
    with database() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.execute(
            "INSERT INTO sessions (token_hash, username, role, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, username, role, now + SESSION_SECONDS),
        )
    return token


def require_admin(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    x_auth_token: Annotated[str | None, Header()] = None,
) -> dict:
    token = credentials.credentials if credentials else x_auth_token
    if not token:
        raise HTTPException(401, "Administrator token required", headers={"WWW-Authenticate": "Bearer"})
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with database() as conn:
        session = conn.execute(
            "SELECT username, role FROM sessions WHERE token_hash = ? AND expires_at > ?",
            (digest, time.time()),
        ).fetchone()
    if not session:
        raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    if session["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return dict(session)


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserRegisterRequest(InputModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Username cannot be blank")
        return value.strip()


class ItemCreateRequest(InputModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(default="", max_length=10000)

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Title cannot be blank")
        return value.strip()


class TodoCreateRequest(InputModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    is_completed: bool = Field(default=False, strict=True)
    tags: str = Field(default="", max_length=1000)

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        return ItemCreateRequest.validate_title(value)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: str) -> str:
        return ",".join(dict.fromkeys(tag.strip().lower() for tag in value.split(",") if tag.strip()))


class TodoResponse(TodoCreateRequest):
    id: int
    created_at: str


class AdminLoginRequest(InputModel):
    password: str = Field(min_length=1, max_length=1024)


def todo_dict(row: sqlite3.Row) -> dict:
    result = dict(row)
    result["is_completed"] = bool(result["is_completed"])
    return result


def literal_like(keyword: str) -> str:
    # Search %, _ and backslash literally instead of treating them as wildcards.
    escaped = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def deduplicate_records(records: list) -> list:
    seen = set()
    unique_items = []
    for item in records:
        identifier = item.get("id")
        if identifier not in seen:
            seen.add(identifier)
            unique_items.append(item)
    return unique_items


@app.get("/", tags=["Status"])
def health_check():
    return {"status": "healthy", "app": APP_NAME, "version": APP_VERSION}


@app.post("/todos", response_model=TodoResponse, status_code=201, tags=["Todos"])
def create_todo(req: TodoCreateRequest):
    with database() as conn:
        cursor = conn.execute(
            "INSERT INTO todos (title, description, is_completed, tags) VALUES (?, ?, ?, ?)",
            (req.title, req.description, req.is_completed, req.tags),
        )
        row = conn.execute("SELECT * FROM todos WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return todo_dict(row)


@app.get("/todos", response_model=list[TodoResponse], tags=["Todos"])
def list_todos():
    with database() as conn:
        rows = conn.execute("SELECT * FROM todos ORDER BY id").fetchall()
    return [todo_dict(row) for row in rows]


@app.get("/todos/search", response_model=list[TodoResponse], tags=["Todos"])
def search_todos(q: Annotated[str, Query(min_length=1, max_length=200)]):
    if not q.strip():
        raise HTTPException(400, "Search keyword cannot be blank")
    pattern = literal_like(q)
    with database() as conn:
        rows = conn.execute(
            "SELECT * FROM todos WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' ORDER BY id",
            (pattern, pattern),
        ).fetchall()
    return [todo_dict(row) for row in rows]


@app.get("/todos/filtered", response_model=list[TodoResponse], tags=["Todos"])
def filtered_todos():
    return [todo for todo in list_todos() if not BLOCKED_TAGS.intersection(todo["tags"].split(","))]


@app.get("/todos/{todo_id}", response_model=TodoResponse, tags=["Todos"])
def get_todo(todo_id: int):
    with database() as conn:
        row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Todo not found")
    return todo_dict(row)


@app.put("/todos/{todo_id}", response_model=TodoResponse, tags=["Todos"])
def update_todo(todo_id: int, req: TodoCreateRequest):
    """Replace editable fields; id and created_at stay unchanged."""
    with database() as conn:
        cursor = conn.execute(
            "UPDATE todos SET title = ?, description = ?, is_completed = ?, tags = ? WHERE id = ?",
            (req.title, req.description, req.is_completed, req.tags, todo_id),
        )
        if not cursor.rowcount:
            raise HTTPException(404, "Todo not found")
        row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    return todo_dict(row)


@app.post("/admin/login", tags=["Admin"])
def admin_login(req: AdminLoginRequest):
    stored_hash = app.state.admin_password_hash
    if not stored_hash:
        raise HTTPException(503, "Set ADMIN_PASSWORD and restart the server to enable administrator login")
    if not verify_credential(req.password, stored_hash):
        raise HTTPException(401, "Invalid administrator password")
    return {"token": issue_token("admin", "admin"), "token_type": "bearer", "expires_in": SESSION_SECONDS}


@app.delete("/admin/todos/{todo_id}", tags=["Admin"])
def delete_todo(todo_id: int, admin: Annotated[dict, Depends(require_admin)]):
    with database() as conn:
        cursor = conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        if not cursor.rowcount:
            raise HTTPException(404, "Todo not found")
    return {"success": True, "deleted_id": todo_id}


# Retained starter endpoints with bound SQL and separate user/admin roles.
@app.post("/api/auth/register", tags=["Starter API"])
def register_user(req: UserRegisterRequest):
    hashed_pw = hash_credential(req.password)
    try:
        with database() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (req.username, hashed_pw),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username already exists") from None
    return {"success": True, "message": f"User {req.username} registered successfully"}


@app.post("/api/auth/login", tags=["Starter API"])
def login_user(req: UserRegisterRequest):
    with database() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
    if not row or not verify_credential(req.password, row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    # This route never grants administrator privileges.
    user = {"id": row["id"], "username": row["username"], "role": "user"}
    return {"success": True, "token": issue_token(req.username, "user"), "user": user}


@app.get("/api/items", tags=["Starter API"])
def search_items(keyword: Annotated[str | None, Query(max_length=200)] = None):
    with database() as conn:
        if keyword:
            pattern = literal_like(keyword)
            rows = conn.execute(
                "SELECT * FROM items WHERE title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\' ORDER BY id",
                (pattern, pattern),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM items ORDER BY id").fetchall()
    items = deduplicate_records([dict(row) for row in rows])
    return {"total": len(items), "items": items}


@app.post("/api/items", tags=["Starter API"])
def create_item(req: ItemCreateRequest, admin: Annotated[dict, Depends(require_admin)]):
    with database() as conn:
        cursor = conn.execute(
            "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
            (req.title, req.content, admin["username"]),
        )
        item_id = cursor.lastrowid
    return {"success": True, "item_id": item_id, "title": req.title}
