"""SQLite persistence + tamper-evident (hash-chained) audit log + event stream."""
from __future__ import annotations
import hashlib, json, sqlite3, threading
from typing import Any, Optional
from . import config
from .models import now

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None
_db_path = None


def conn() -> sqlite3.Connection:
    global _conn, _db_path
    with _lock:
        if _conn is None or _db_path != str(config.DB_PATH):
            _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _db_path = str(config.DB_PATH)
            _init(_conn)
        return _conn


def use_db(path) -> None:
    """Point the store at another database file (tests)."""
    global _conn, _db_path
    with _lock:
        if _conn:
            _conn.close()
        _conn, _db_path = None, None
        config.DB_PATH = path


def _init(c: sqlite3.Connection):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS objects(kind TEXT, id TEXT, assessment_id TEXT, body TEXT, PRIMARY KEY(kind,id,assessment_id));
    CREATE INDEX IF NOT EXISTS ix_obj ON objects(kind, assessment_id);
    CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT, ts TEXT,
        actor TEXT, action TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
    CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT, ts TEXT, type TEXT, body TEXT);
    """)
    c.commit()


def put(kind: str, obj) -> None:
    body = obj.model_dump_json()
    aid = obj.id if kind == "assessment" else getattr(obj, "assessment_id", "")
    with _lock:
        c = conn()
        c.execute("INSERT OR REPLACE INTO objects(kind,id,assessment_id,body) VALUES(?,?,?,?)", (kind, obj.id, aid, body))
        c.commit()


def get(kind: str, id_: str, model, assessment_id: Optional[str] = None):
    q, args = "SELECT body FROM objects WHERE kind=? AND id=?", [kind, id_]
    if assessment_id:
        q += " AND assessment_id=?"; args.append(assessment_id)
    with _lock:
        r = conn().execute(q, args).fetchone()
    return model(**json.loads(r["body"])) if r else None


def list_(kind: str, model, assessment_id: Optional[str] = None) -> list:
    q, args = "SELECT body FROM objects WHERE kind=?", [kind]
    if assessment_id:
        q += " AND assessment_id=?"; args.append(assessment_id)
    q += " ORDER BY rowid"
    with _lock:
        rows = conn().execute(q, args).fetchall()
    return [model(**json.loads(r["body"])) for r in rows]


def count(kind: str, assessment_id: str) -> int:
    with _lock:
        return conn().execute("SELECT COUNT(*) FROM objects WHERE kind=? AND assessment_id=?", (kind, assessment_id)).fetchone()[0]


def next_id(prefix: str, kind: str, assessment_id: str, width: int = 3) -> str:
    return f"{prefix}-{count(kind, assessment_id) + 1:0{width}d}"


# ---------------- audit log ----------------
def audit(assessment_id: str, actor: str, action: str, detail: Any = None) -> dict:
    detail_s = json.dumps(detail, sort_keys=True, default=str) if detail is not None else ""
    with _lock:
        c = conn()
        last = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else "GENESIS"
        ts = now()
        h = hashlib.sha256(f"{prev}|{assessment_id}|{ts}|{actor}|{action}|{detail_s}".encode()).hexdigest()
        c.execute("INSERT INTO audit(assessment_id,ts,actor,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
                  (assessment_id, ts, actor, action, detail_s, prev, h))
        c.commit()
    return {"ts": ts, "actor": actor, "action": action, "hash": h}


def audit_entries(assessment_id: Optional[str] = None) -> list[dict]:
    with _lock:
        rows = [dict(r) for r in conn().execute("SELECT * FROM audit ORDER BY seq").fetchall()]
    return [r for r in rows if not assessment_id or r["assessment_id"] == assessment_id]


def verify_audit() -> tuple[bool, Optional[int]]:
    """Recompute the full chain. Returns (ok, first_bad_seq)."""
    prev = "GENESIS"
    for r in audit_entries():
        h = hashlib.sha256(f"{prev}|{r['assessment_id']}|{r['ts']}|{r['actor']}|{r['action']}|{r['detail']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h:
            return False, r["seq"]
        prev = h
    return True, None


# ---------------- events (progress stream) ----------------
def event(assessment_id: str, type_: str, body: Any) -> int:
    with _lock:
        c = conn()
        cur = c.execute("INSERT INTO events(assessment_id,ts,type,body) VALUES(?,?,?,?)",
                        (assessment_id, now(), type_, json.dumps(body, default=str)))
        c.commit()
        return cur.lastrowid


def events_since(assessment_id: str, seq: int = 0) -> list[dict]:
    with _lock:
        rows = conn().execute("SELECT * FROM events WHERE assessment_id=? AND seq>? ORDER BY seq", (assessment_id, seq)).fetchall()
    return [{"seq": r["seq"], "ts": r["ts"], "type": r["type"], "body": json.loads(r["body"])} for r in rows]
