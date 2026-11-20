import sqlite3
import json
import secrets
import hashlib
import time
from pathlib import Path

DB_PATH = Path(__file__).with_name("echo.db")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            permissions TEXT NOT NULL,
            contained INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            event TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        """)


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def log_event(agent_id, event, details):
    with db() as con:
        con.execute(
            "INSERT INTO audit(agent_id,event,details,created_at) VALUES(?,?,?,?)",
            (agent_id, event, json.dumps(details), time.time())
        )


def register_agent(name, permissions):
    agent_id = "agent_" + secrets.token_hex(6)
    token = secrets.token_urlsafe(32)

    with db() as con:
        con.execute(
            """INSERT INTO agents
            (agent_id,name,token_hash,permissions,contained,created_at)
            VALUES(?,?,?,?,0,?)""",
            (
                agent_id,
                name,
                hash_token(token),
                json.dumps(permissions),
                time.time()
            )
        )

    log_event(agent_id, "REGISTERED", {
        "name": name,
        "permissions": permissions
    })

    return {
        "agent_id": agent_id,
        "token": token
    }


def get_agent_by_token(token):
    with db() as con:
        row = con.execute(
            "SELECT * FROM agents WHERE token_hash=?",
            (hash_token(token),)
        ).fetchone()

    return dict(row) if row else None


def get_agent(agent_id):
    with db() as con:
        row = con.execute(
            "SELECT * FROM agents WHERE agent_id=?",
            (agent_id,)
        ).fetchone()

    return dict(row) if row else None


def authorize(agent, action, resource):

    if agent["contained"]:
        log_event(
            agent["agent_id"],
            "BLOCKED_CONTAINED",
            {"action": action, "resource": resource}
        )

        return {
            "allowed": False,
            "reason": "Agent is contained"
        }

    permissions = json.loads(agent["permissions"])

    allowed = any(
        permission.get("action") == action
        and permission.get("resource") == resource
        for permission in permissions
    )

    log_event(
        agent["agent_id"],
        "POLICY_CHECK",
        {
            "action": action,
            "resource": resource,
            "allowed": allowed
        }
    )

    return {
        "allowed": allowed,
        "reason": "Permission granted" if allowed else "No matching permission"
    }


def contain_agent(agent_id):

    with db() as con:
        row = con.execute(
            "SELECT agent_id FROM agents WHERE agent_id=?",
            (agent_id,)
        ).fetchone()

        if not row:
            return False

        con.execute(
            "UPDATE agents SET contained=1 WHERE agent_id=?",
            (agent_id,)
        )

    log_event(agent_id, "CONTAINED", {
        "scope": "ECHO authorization layer"
    })

    return True


def recover_agent(agent_id):

    with db() as con:
        row = con.execute(
            "SELECT agent_id FROM agents WHERE agent_id=?",
            (agent_id,)
        ).fetchone()

        if not row:
            return False

        con.execute(
            "UPDATE agents SET contained=0 WHERE agent_id=?",
            (agent_id,)
        )

    log_event(agent_id, "RECOVERED", {
        "approval": "admin"
    })

    return True


def list_agents():

    with db() as con:
        rows = con.execute(
            """SELECT agent_id,name,permissions,contained,created_at
            FROM agents ORDER BY created_at DESC"""
        ).fetchall()

    return [dict(row) for row in rows]


def audit_log(limit=100):

    with db() as con:
        rows = con.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()

    return [dict(row) for row in rows]
