import os

from typing import List, Dict

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field

import echo_core as core


app = FastAPI(
    title="ECHO",
    description="Independent AI authorization and containment prototype",
    version="0.1.0"
)


ADMIN_KEY = os.getenv("ECHO_ADMIN_KEY")

if not ADMIN_KEY:
    raise RuntimeError(
        "Set ECHO_ADMIN_KEY before starting ECHO."
    )


core.init_db()


class RegisterRequest(BaseModel):

    name: str = Field(min_length=1, max_length=80)

    permissions: List[Dict[str, str]] = Field(
        default_factory=list
    )


class CheckRequest(BaseModel):

    action: str

    resource: str


def require_admin(
    x_echo_admin: str = Header(default="")
):

    if x_echo_admin != ADMIN_KEY:

        raise HTTPException(
            status_code=401,
            detail="Invalid admin key"
        )


def current_agent(
    authorization: str = Header(default="")
):

    if not authorization.startswith("Bearer "):

        raise HTTPException(
            status_code=401,
            detail="Provide agent token as Bearer token"
        )

    token = authorization[7:]

    agent = core.get_agent_by_token(token)

    if not agent:

        raise HTTPException(
            status_code=401,
            detail="Invalid agent token"
        )

    return agent


@app.get("/")
def root():

    return {
        "name": "ECHO",
        "version": "0.1",
        "status": "running",
        "notice": "Prototype: enforcement applies only to requests routed through ECHO."
    }


@app.post("/agents", dependencies=[Depends(require_admin)])
def register_agent(req: RegisterRequest):

    result = core.register_agent(
        req.name,
        req.permissions
    )

    return result


@app.post("/authorize")
def check_permission(
    req: CheckRequest,
    agent=Depends(current_agent)
):

    return core.authorize(
        agent,
        req.action,
        req.resource
    )


@app.post(
    "/agents/{agent_id}/contain",
    dependencies=[Depends(require_admin)]
)
def contain_agent(agent_id: str):

    if not core.contain_agent(agent_id):

        raise HTTPException(
            status_code=404,
            detail="Agent not found"
        )

    return {
        "agent_id": agent_id,
        "contained": True,
        "verified": "ECHO authorization layer state updated",
        "scope_warning": "This does not terminate processes or isolate networks."
    }


@app.post(
    "/agents/{agent_id}/recover",
    dependencies=[Depends(require_admin)]
)
def recover_agent(agent_id: str):

    if not core.recover_agent(agent_id):

        raise HTTPException(
            status_code=404,
            detail="Agent not found"
        )

    return {
        "agent_id": agent_id,
        "contained": False,
        "recovery": "admin-approved"
    }


@app.get(
    "/agents",
    dependencies=[Depends(require_admin)]
)
def get_agents():

    return core.list_agents()


@app.get(
    "/audit",
    dependencies=[Depends(require_admin)]
)
def get_audit(limit: int = 100):

    limit = max(1, min(limit, 500))

    return core.audit_log(limit)
