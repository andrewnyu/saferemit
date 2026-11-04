"""FastAPI web app: the OFW's Trusted Surface and the family's bill upload.

    uvicorn loopremit.web.app:app --reload

Two roles, no login (single-household demo): /ofw and /family.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from loopremit.agent import MANILA
from loopremit.config import get_settings
from loopremit.crypto import jws
from loopremit.crypto.jwk import thumbprint
from loopremit.mandates import model as m
from loopremit.services import Services, seed_registry

HERE = Path(__file__).resolve().parent
SAMPLES = HERE.parent.parent / "samples"
MAX_UPLOAD = 8 * 1024 * 1024
STATUS_LABELS = {
    "paid": ("Paid", "ok"), "paying": ("Payout processing", "warn"), "rejected": ("Stopped by gateway", "bad"), "declined": ("Declined by OFW", "bad"),
    "awaiting_ofw": ("Waiting for OFW", "warn"), "needs_review": ("Needs review", "warn"),
    "waiting_for_plan": ("Waiting for a plan", "warn"), "failed": ("Payment failed", "bad"),
    "extracting": ("Reading bill…", "muted"),
}


def peso(minor) -> str:
    return "—" if minor is None else f"₱{int(minor) / 100:,.2f}"


def when(ts) -> str:
    return "—" if not ts else datetime.fromtimestamp(int(ts), MANILA).strftime("%b %d, %Y %I:%M %p")


def create_app(services: Services | None = None) -> FastAPI:
    app = FastAPI(title="Loop Remit", docs_url="/api/docs")
    svc = services or Services(get_settings())
    if not svc.payees():
        seed_registry(svc)
    app.state.services = svc
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters.update(peso=peso, when=when, tojson_pretty=lambda v: json.dumps(v, indent=2, ensure_ascii=False))
    templates.env.globals.update(
        STATUS_LABELS=STATUS_LABELS, settings=svc.settings,
        pending_count=lambda: svc.db.one("SELECT COUNT(*) AS n FROM approvals WHERE status = 'pending'")["n"])
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def render(request: Request, name: str, status_code: int = 200, **ctx):
        ctx.setdefault("paypal_mode", svc.paypal.mode)
        ctx.setdefault("intake_mode", "AI model" if svc.settings.use_ai else "offline fixtures")
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def bills(where: str = "1=1", *args) -> list[dict]:
        rows = svc.db.all(f"SELECT * FROM bills WHERE {where} ORDER BY id DESC", *args)
        out = []
        for r in rows:
            d = dict(r)
            d["extraction"] = json.loads(d["extraction"]) if d["extraction"] else None
            d["checks"] = json.loads(d["checks"]) if d["checks"] else None
            d["closed_content"] = json.loads(d["closed_content"]) if d["closed_content"] else None
            out.append(d)
        return out

    def bill_or_404(bill_id: int) -> dict:
        found = bills("id = ?", bill_id)
        if not found:
            raise HTTPException(404, "no such bill")
        return found[0]

    # ------------------------------------------------------------------ shared

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return render(request, "index.html", plan=svc.active_plan(), device=svc.device_key(), vault=svc.vault(),
                      n_bills=len(bills()))

    @app.post("/demo/reset")
    def reset():
        svc.reset_demo()
        return RedirectResponse("/?reset=1", status_code=303)

    @app.get("/bills/{bill_id}/image")
    def bill_image(bill_id: int):
        b = bill_or_404(bill_id)
        row = svc.db.one("SELECT path, mime FROM gw_evidence WHERE image_sha256 = ?", b["image_sha256"])
        if row is None:
            raise HTTPException(404)
        return FileResponse(row["path"], media_type=row["mime"] or "image/png")

    @app.get("/samples/{name}")
    def sample_file(name: str):
        manifest = json.loads((SAMPLES / "manifest.json").read_text())
        entry = next((e for e in manifest if e["file"] == name), None)
        if entry is None:
            raise HTTPException(404)
        return FileResponse(SAMPLES / entry["file"], media_type="image/png")

    @app.get("/.well-known/loopremit-gateway.json")
    def gateway_keys():
        return {"iss": svc.gateway.audience, "keys": [svc.gateway.jwk],
                "agent_key": {**svc.agent_jwk, "kid": thumbprint(svc.agent_jwk)}}

    @app.get("/api/receipts/{receipt_id}")
    def receipt_json(receipt_id: str):
        r = svc.receipt(receipt_id)
        if r is None:
            raise HTTPException(404)
        return {"receipt_jwt": r["receipt_jwt"], "header": r["header"], "payload": r["payload"], "trace": r["trace"]}

    # ------------------------------------------------------------------ OFW

    @app.get("/ofw", response_class=HTMLResponse)
    def ofw_dashboard(request: Request):
        svc.reconcile_payouts()
        payments = {p["bill_id"]: dict(p) for p in svc.db.all("SELECT * FROM payments")}
        pending = svc.db.one("SELECT COUNT(*) AS n FROM approvals WHERE status = 'pending'")["n"]
        return render(request, "ofw_dashboard.html", bills=bills(), payments=payments, summary=svc.budget_summary(),
                      plan=svc.active_plan(), device=svc.device_key(), vault=svc.vault(), pending=pending)

    @app.get("/ofw/onboarding", response_class=HTMLResponse)
    def ofw_onboarding(request: Request, vault: str | None = None):
        return render(request, "ofw_onboarding.html", device=svc.device_key(), vault=svc.vault(), vault_flash=vault)

    @app.post("/api/ofw/device-key")
    async def register_device_key(request: Request):
        body = await request.json()
        try:
            kid = svc.register_device_key(body["jwk"], body.get("label") or "OFW browser")
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, f"invalid device key: {exc}")
        return {"kid": kid}

    @app.post("/ofw/vault/start")
    def vault_start():
        return RedirectResponse(svc.start_vault(), status_code=303)

    @app.get("/ofw/vault/mock-approve", response_class=HTMLResponse)
    def vault_mock_approve(request: Request, token: str):
        if svc.paypal.mode != "mock":
            raise HTTPException(404)
        return render(request, "mock_approve.html", token=token)

    @app.get("/ofw/vault/return")
    def vault_return(approval_token_id: str | None = None, token: str | None = None):
        try:
            svc.complete_vault(approval_token_id or token)
        except Exception as exc:  # surface PayPal errors on the onboarding page
            return RedirectResponse(f"/ofw/onboarding?vault=error:{str(exc)[:120]}", status_code=303)
        return RedirectResponse("/ofw/onboarding?vault=ok", status_code=303)

    @app.get("/ofw/plan", response_class=HTMLResponse)
    def ofw_plan(request: Request):
        current = svc.active_plan_model()
        default = svc.default_plan()
        return render(request, "ofw_plan.html", plan=default, current=current, payees=svc.payees(),
                      selected={p.id for p in (current or default).payees}, active_plan=svc.active_plan(),
                      categories=m.CATEGORIES)

    @app.post("/api/ofw/plan/draft")
    async def plan_draft(request: Request):
        form = await request.json()
        try:
            plan = _plan_from_form(svc, form)
            plan_id, draft = svc.create_draft(plan, form.get("kid"))
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc))
        return {"plan_id": plan_id, "draft": draft.to_dict()}

    @app.post("/api/ofw/plan/{plan_id}/sign")
    async def plan_sign(plan_id: int, request: Request):
        body = await request.json()
        try:
            mandate_id = svc.activate_plan(plan_id, body["signature"])
        except Exception as exc:
            raise HTTPException(400, f"signature rejected: {exc}")
        return {"mandate_id": mandate_id}

    @app.get("/ofw/approvals", response_class=HTMLResponse)
    def ofw_approvals(request: Request):
        rows = svc.db.all("SELECT * FROM approvals ORDER BY status = 'pending' DESC, id DESC")
        items = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"]) if d["payload"] else None
            d["bill"] = bill_or_404(d["bill_id"])
            items.append(d)
        return render(request, "ofw_approvals.html", approvals=items)

    @app.post("/api/ofw/approvals/{approval_id}")
    async def ofw_decide(approval_id: int, request: Request):
        body = await request.json()
        decision_jws = body["decision_jws"]
        approval = svc.db.one("SELECT * FROM approvals WHERE id = ?", approval_id)
        if approval is None:
            raise HTTPException(404)
        try:
            if approval["kind"] == "step_up":
                result = svc.agent.approve_step_up(approval_id, decision_jws)
                return {"outcome": result.outcome, "error": result.error, "bill_id": approval["bill_id"]}
            if jws.decode_unverified(decision_jws).payload.get("decision") != "decline":
                raise ValueError("a bill the gateway stopped can only be declined; change your plan to allow it")
            svc.agent.decline_escalation(approval_id, decision_jws)
            return {"outcome": "declined", "bill_id": approval["bill_id"]}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/ofw/bills/{bill_id}", response_class=HTMLResponse)
    def ofw_bill(request: Request, bill_id: int):
        svc.reconcile_payouts()
        b = bill_or_404(bill_id)
        payment = svc.db.one("SELECT * FROM payments WHERE bill_id = ?", bill_id)
        history = svc.db.all("SELECT * FROM gw_receipts WHERE bill_id = ? ORDER BY created_at, rowid", bill_id)
        receipts = [svc.receipt(r["id"]) for r in history]
        return render(request, "bill_detail.html", bill=b, payment=dict(payment) if payment else None,
                      receipts=receipts)

    # ------------------------------------------------------------------ family

    @app.get("/family", response_class=HTMLResponse)
    def family(request: Request):
        svc.reconcile_payouts()
        manifest = json.loads((SAMPLES / "manifest.json").read_text())
        return render(request, "family.html", bills=bills(), summary=svc.budget_summary(), samples=manifest,
                      plan=svc.active_plan())

    @app.post("/family/bills")
    async def family_upload(file: UploadFile = File(...), submitted_by: str = Form("Family")):
        data = await file.read()
        if not data or len(data) > MAX_UPLOAD:
            raise HTTPException(400, "upload a bill photo under 8 MB")
        mime = file.content_type if file.content_type in ("image/png", "image/jpeg", "image/webp") else None
        if mime is None:
            raise HTTPException(400, "bills must be PNG, JPEG or WebP photos")
        # Reading a bill takes seconds; don't block the event loop while the model works.
        bill_id = await run_in_threadpool(svc.agent.submit_bill, data, filename=file.filename or "bill", mime=mime,
                                          submitted_by=submitted_by.strip()[:40] or "Family")
        return RedirectResponse(f"/family/bills/{bill_id}", status_code=303)

    @app.post("/family/samples/{key}")
    def family_sample(key: str, submitted_by: str = Form("Mama Rosario")):
        manifest = json.loads((SAMPLES / "manifest.json").read_text())
        entry = next((e for e in manifest if e["key"] == key), None)
        if entry is None:
            raise HTTPException(404)
        bill_id = svc.agent.submit_bill((SAMPLES / entry["file"]).read_bytes(), filename=entry["file"],
                                        mime="image/png", submitted_by=submitted_by.strip()[:40] or "Family")
        return RedirectResponse(f"/family/bills/{bill_id}", status_code=303)

    @app.get("/family/bills/{bill_id}", response_class=HTMLResponse)
    def family_bill(request: Request, bill_id: int):
        svc.reconcile_payouts()
        return render(request, "family_bill.html", bill=bill_or_404(bill_id), summary=svc.budget_summary())

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return render(request, "error.html", status_code=exc.status_code, status=exc.status_code, detail=exc.detail)

    return app


def _plan_from_form(svc: Services, form: dict) -> m.Plan:
    def minor(name: str) -> int:
        value = float(form[name])
        if value < 0:
            raise ValueError(f"{name} must be positive")
        return int(round(value * 100))

    chosen = set(form.get("payees", []))
    payees = [m.Payee(p["id"], p["name"], p["category"], p["account_number"], p["paypal_email"], p.get("website"))
              for p in svc.payees() if p["id"] in chosen]
    if not payees:
        raise ValueError("choose at least one payee")
    caps = []
    for cap in form.get("caps", []):
        if not cap.get("max"):
            continue
        caps.append(m.CategoryCap(
            category=cap["category"], max_minor=int(round(float(cap["max"]) * 100)), period=cap.get("period", "MONTHLY"),
            not_before=cap.get("not_before") or None, not_after=cap.get("not_after") or None, label=cap.get("label") or None))
    if cap_categories := {c.category for c in caps}:
        missing = {p.category for p in payees} - cap_categories
        if missing:
            raise ValueError(f"add a category cap for: {', '.join(sorted(missing))}")
    plan = m.Plan(
        payees=payees, monthly_budget_minor=minor("monthly_budget"),
        max_payments_per_month=int(form["max_payments"]), amount_min_minor=minor("amount_min"),
        amount_max_minor=minor("amount_max"), caps=caps, step_up_over_minor=minor("step_up_over"),
        not_before=form["not_before"], not_after=form["not_after"], valid_days=int(form.get("valid_days", 30)),
        ofw_name=form.get("ofw_name") or "OFW", household=form.get("household") or "Household")
    if plan.not_after < plan.not_before:
        raise ValueError("the execution window ends before it starts")
    if not 1 <= plan.valid_days <= 90:
        raise ValueError("keep the mandate short-lived: 1 to 90 days")
    return plan


def __getattr__(name: str):
    """`uvicorn loopremit.web.app:app` builds the app on first access, so importing
    this module (e.g. in tests) does not touch the default data directory."""
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
