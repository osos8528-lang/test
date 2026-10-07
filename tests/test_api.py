from concurrent.futures import ThreadPoolExecutor
import hashlib
import secrets

from fastapi.testclient import TestClient
import pytest

import main


@pytest.fixture
def configured_app(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "service.db"))
    secret = secrets.token_urlsafe(24)
    monkeypatch.setenv("ADMIN_PASSWORD", secret)
    return secret


@pytest.fixture
def client(configured_app):
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers(client, configured_app):
    response = client.post("/admin/login", json={"password": configured_app})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


def add_todo(client, **overrides):
    body = {"title": "실습 과제", "description": "FastAPI 공부", "tags": "study"}
    body.update(overrides)
    response = client.post("/todos", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_health_and_interactive_docs(client):
    assert client.get("/").json()["status"] == "healthy"
    assert client.get("/docs").status_code == 200
    schema = client.get("/openapi.json").json()
    assert "/todos/search" in schema["paths"]
    assert "HTTPBearer" in schema["components"]["securitySchemes"]


def test_todo_create_list_read_update_delete(client, admin_headers):
    assert client.get("/todos").json() == []
    todo = add_todo(client, title="  공부  ", tags="Study, ,study, Work")
    assert todo["title"] == "공부"
    assert todo["tags"] == "study,work"
    assert todo["is_completed"] is False
    assert todo["created_at"]
    path = f"/todos/{todo['id']}"
    assert client.get(path).json() == todo
    changed = client.put(path, json={"title": "완료", "is_completed": True})
    assert changed.status_code == 200
    assert changed.json()["is_completed"] is True
    assert changed.json()["created_at"] == todo["created_at"]
    assert client.get("/todos").json() == [changed.json()]
    response = client.delete(f"/admin/todos/{todo['id']}", headers=admin_headers)
    assert response.status_code == 200
    assert client.get(path).status_code == 404
    assert client.get("/todos").json() == []


@pytest.mark.parametrize("fields", [
    {"title": ""}, {"title": "   "}, {"title": None}, {"title": "x" * 201},
    {"is_completed": "yes"}, {"tags": ["spam"]}, {"unexpected": True},
])
def test_invalid_todo_payload_is_rejected(client, fields):
    assert client.post("/todos", json={"title": "valid", **fields}).status_code == 422
    assert client.get("/todos").json() == []


def test_search_checks_both_fields(client):
    title_match = add_todo(client, title="회의 준비", description="")
    description_match = add_todo(client, title="업무", description="회의 자료")
    add_todo(client, title="산책", description="공원")
    results = client.get("/todos/search", params={"q": "회의"}).json()
    assert [row["id"] for row in results] == [title_match["id"], description_match["id"]]
    assert client.get("/todos/search", params={"q": "없는단어"}).json() == []


@pytest.mark.parametrize("keyword", ["%", "_", "\\", "' OR 1=1 --"])
def test_search_handles_wildcards_and_injection_as_literal_text(client, keyword):
    expected = add_todo(client, title=f"literal {keyword}")
    add_todo(client, title="ordinary")
    result = client.get("/todos/search", params={"q": keyword})
    assert result.status_code == 200
    assert [row["id"] for row in result.json()] == [expected["id"]]
    assert len(client.get("/todos").json()) == 2


@pytest.mark.parametrize("query,status", [({}, 422), ({"q": ""}, 422), ({"q": "  "}, 400)])
def test_empty_search_is_rejected(client, query, status):
    assert client.get("/todos/search", params=query).status_code == status


def test_filtered_tags_match_whole_tags_case_insensitively(client):
    clean = add_todo(client, tags="study,road")
    untagged = add_todo(client, tags="")
    for tag in (" SPAM ", "ad", "Private", "temp"):
        add_todo(client, tags=f"study,{tag}")
    assert [row["id"] for row in client.get("/todos/filtered").json()] == [clean["id"], untagged["id"]]
    assert len(client.get("/todos").json()) == 6


def test_missing_and_wrong_admin_tokens_cannot_delete(client):
    todo = add_todo(client)
    path = f"/admin/todos/{todo['id']}"
    assert client.delete(path).status_code == 401
    assert client.delete(path, headers={"Authorization": "Bearer not-a-valid-token"}).status_code == 401
    assert client.post("/admin/login", json={"password": "wrong"}).status_code == 401
    assert len(client.get("/todos").json()) == 1


def test_admin_password_missing_disables_login(configured_app, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD")
    with TestClient(main.app) as client:
        assert client.post("/admin/login", json={"password": configured_app}).status_code == 503
        assert client.get("/todos").status_code == 200


def test_admin_sessions_are_random_hashed_and_expire(client, configured_app, monkeypatch):
    first = client.post("/admin/login", json={"password": configured_app}).json()
    second = client.post("/admin/login", json={"password": configured_app}).json()
    assert first["token"] != second["token"]
    assert first["expires_in"] == 3600
    with main.database() as conn:
        hashes = [row["token_hash"] for row in conn.execute("SELECT token_hash FROM sessions")]
        assert first["token"] not in hashes
        assert hashlib.sha256(first["token"].encode()).hexdigest() in hashes
    todo = add_todo(client)
    now = main.time.time()
    monkeypatch.setattr(main.time, "time", lambda: now + 3601)
    assert client.delete(
        f"/admin/todos/{todo['id']}", headers={"Authorization": f"Bearer {first['token']}"}
    ).status_code == 401
    client.post("/admin/login", json={"password": configured_app})
    with main.database() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_missing_ids_and_invalid_ids(client, admin_headers):
    assert client.get("/todos/9999").status_code == 404
    assert client.get("/todos/not-an-id").status_code == 422
    assert client.put("/todos/9999", json={"title": "missing"}).status_code == 404
    assert client.delete("/admin/todos/9999", headers=admin_headers).status_code == 404


def test_registered_user_cannot_escalate_to_admin(client):
    credentials = {"username": "admin", "password": secrets.token_urlsafe(20)}
    assert client.post("/api/auth/register", json=credentials).status_code == 200
    assert client.post("/api/auth/register", json=credentials).status_code == 400
    response = client.post("/api/auth/login", json=credentials)
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["role"] == "user"
    assert "password_hash" not in data["user"]
    assert client.delete("/admin/todos/1", headers={"Authorization": f"Bearer {data['token']}"}).status_code == 403
    assert client.post("/api/auth/login", json={**credentials, "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={**credentials, "username": "' OR 1=1 --"}).status_code == 401
    assert client.post("/api/auth/register", json={**credentials, "role": "admin"}).status_code == 422
    assert client.post("/api/auth/register", json={**credentials, "username": "  "}).status_code == 422


def test_registered_passwords_are_salted_and_not_plaintext(client):
    password = secrets.token_urlsafe(20)
    for username in ("one", "two"):
        assert client.post("/api/auth/register", json={"username": username, "password": password}).status_code == 200
    with main.database() as conn:
        hashes = [row[0] for row in conn.execute("SELECT password_hash FROM users ORDER BY id")]
    assert hashes[0] != hashes[1]
    assert all(password not in hashed and main.verify_credential(password, hashed) for hashed in hashes)


@pytest.mark.parametrize("stored", ["old-md5-value", "unknown$1$aa$bb", "pbkdf2_sha256$0$aa$bb", "pbkdf2_sha256$600000$zz$bb"])
def test_malformed_or_legacy_password_hash_fails_closed(stored):
    assert not main.verify_credential("password", stored)


def test_original_item_endpoints_and_legacy_token_header(client, admin_headers):
    token = admin_headers["Authorization"].split()[1]
    response = client.post(
        "/api/items", json={"title": "O'Reilly 100%", "content": "quoted ' text"},
        headers={"X-Auth-Token": token},
    )
    assert response.status_code == 200
    assert client.get("/api/items").json()["total"] == 1
    assert client.get("/api/items", params={"keyword": "%"}).json()["total"] == 1
    assert client.get("/api/items", params={"keyword": "quoted"}).json()["total"] == 1
    assert client.get("/api/items", params={"keyword": "' OR 1=1 --"}).json()["total"] == 0
    assert client.post("/api/items", json={"title": "no auth"}).status_code == 401


def test_database_is_durable_and_uses_wal(configured_app):
    with TestClient(main.app) as first_client:
        created = add_todo(first_client)
    with TestClient(main.app) as second_client:
        assert second_client.get("/todos").json() == [created]
    with main.database() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_concurrent_writes_do_not_lose_todos(client):
    def create(index):
        return client.post("/todos", json={"title": f"parallel {index}"})
    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(create, range(40)))
    assert all(response.status_code == 201 for response in results)
    rows = client.get("/todos").json()
    assert len(rows) == 40
    assert len({row["id"] for row in rows}) == 40


def test_deduplication_keeps_first_seen_order():
    rows = [{"id": 2, "v": "first"}, {"id": 1}, {"id": 2, "v": "last"}]
    assert main.deduplicate_records(rows) == rows[:2]
