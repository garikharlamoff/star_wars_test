"""
Star Wars Canon Lore — шпаргалка-лэндинг на FastAPI

Запуск:
  uvicorn app:app --reload --host 0.0.0.0 --port 8000
"""

import csv
import hashlib
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict

from fastapi import FastAPI, File, Form, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Star Wars Canon Lore")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

os.makedirs("static/avatars", exist_ok=True)
os.makedirs("static/images", exist_ok=True)

USER_FILE = "users.csv"
DATA_FILE = "data.csv"
LOG_FILE = "logs.txt"

SESSION_TIMEOUT_MINUTES = 5


# ─────────────────────────── Logging ───────────────────────────

def log_action(username: str, action: str, details: str = ""):
    """Append action to logs.txt"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] user={username or 'anonymous'} | {action}"
    if details:
        line += f" | {details}"
    line += "\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


# ─────────────────────────── Users ───────────────────────────

def load_users() -> Dict[str, dict]:
    users = {}
    if os.path.exists(USER_FILE):
        try:
            with open(USER_FILE, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    username = row.get("username")
                    if username:
                        users[username] = row
        except Exception:
            return {}
    return users


def save_users(users: Dict[str, dict]):
    fieldnames = ["username", "password_hash", "avatar", "role"]
    with open(USER_FILE, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for user_data in users.values():
            if "role" not in user_data:
                user_data["role"] = "reader"
            writer.writerow({k: user_data.get(k, "") for k in fieldnames})


def ensure_default_admin():
    users = load_users()
    if not users:
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        users["admin"] = {
            "username": "admin",
            "password_hash": password_hash,
            "avatar": "static/avatars/default.png",
            "role": "admin",
        }
        save_users(users)
        log_action("system", "created_default_admin")
    return users


ensure_default_admin()


# ─────────────────────────── Data (factions) ───────────────────────────

def load_factions() -> List[dict]:
    factions = []
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    factions.append(row)
            factions.sort(key=lambda x: int(x.get("order", 999)))
        except Exception:
            return []
    return factions


def save_factions(factions: List[dict]):
    fieldnames = [
        "id", "name", "symbol", "image", "place",
        "characters", "strengths", "weaknesses", "role", "order"
    ]
    with open(DATA_FILE, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in factions:
            writer.writerow({k: item.get(k, "") for k in fieldnames})


def get_faction_by_id(faction_id: str) -> Optional[dict]:
    for f in load_factions():
        if f.get("id") == faction_id:
            return f
    return None


# ─────────────────────────── Session helpers ───────────────────────────

def get_current_user(request: Request) -> Optional[dict]:
    username = request.cookies.get("session_user")
    session_time_str = request.cookies.get("session_time")

    if not username or not session_time_str:
        return None

    try:
        session_time = datetime.fromisoformat(session_time_str)
        if datetime.now() - session_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            return None  # expired
    except Exception:
        return None

    users = load_users()
    return users.get(username)


def require_role(user: Optional[dict], roles: List[str]) -> bool:
    if not user:
        return False
    return user.get("role") in roles


def set_session_cookies(response: RedirectResponse, username: str):
    now = datetime.now().isoformat()
    response.set_cookie(
        key="session_user",
        value=username,
        httponly=True,
        max_age=SESSION_TIMEOUT_MINUTES * 60,
    )
    response.set_cookie(
        key="session_time",
        value=now,
        httponly=True,
        max_age=SESSION_TIMEOUT_MINUTES * 60,
    )


def refresh_session(response, username: str):
    """Refresh timeout on activity"""
    set_session_cookies(response, username)


# ─────────────────────────── Middleware ───────────────────────────

WHITE_URLS = {"/", "/login", "/register", "/logout"}


@app.middleware("http")
async def auth_and_log_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method

    # Always allow static
    if path.startswith("/static"):
        return await call_next(request)

    user = get_current_user(request)
    username = user["username"] if user else "anonymous"

    # Log every request
    log_action(username, f"{method} {path}")

    # Public pages
    if path in WHITE_URLS:
        response = await call_next(request)
        return response

    # Everything else requires valid session
    if not user:
        log_action("anonymous", "blocked_unauthorized", path)
        return templates.TemplateResponse(
            request=request,
            name="401.html",
            status_code=401,
        )

    response = await call_next(request)

    # Refresh session cookie on successful authenticated request
    if hasattr(response, "set_cookie"):
        try:
            set_session_cookies(response, user["username"])
        except Exception:
            pass

    return response


# ─────────────────────────── Routes ───────────────────────────

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/home", status_code=303)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/home", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={},
    )


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    users = load_users()

    if username not in users:
        log_action(username, "login_failed", "user_not_found")
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Неверный логин или пароль"},
        )

    user_data = users[username]
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if user_data["password_hash"] != password_hash:
        log_action(username, "login_failed", "wrong_password")
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Неверный логин или пароль"},
        )

    log_action(username, "login_success")
    response = RedirectResponse(url="/home", status_code=303)
    set_session_cookies(response, username)
    return response


@app.get("/logout")
def logout(request: Request):
    user = get_current_user(request)
    username = user["username"] if user else "anonymous"
    log_action(username, "logout")
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session_user")
    response.delete_cookie("session_time")
    return response


@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={},
    )


@app.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    avatar: UploadFile = File(None),
):
    users = load_users()

    if username in users:
        log_action(username, "register_failed", "username_taken")
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Пользователь с таким именем уже существует"},
        )

    if len(password) < 4:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Пароль должен быть не короче 4 символов"},
        )

    avatar_path = "static/avatars/default.png"
    if avatar and avatar.filename:
        ext = os.path.splitext(avatar.filename)[1].lower() or ".png"
        if ext not in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
            ext = ".png"
        safe_name = f"{uuid.uuid4().hex}{ext}"
        file_location = f"static/avatars/{safe_name}"
        content = await avatar.read()
        with open(file_location, "wb") as f:
            f.write(content)
        avatar_path = file_location

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    users[username] = {
        "username": username,
        "password_hash": password_hash,
        "avatar": avatar_path,
        "role": "reader",  # всегда reader при регистрации
    }
    save_users(users)
    log_action(username, "register_success")

    return RedirectResponse(url="/login", status_code=303)


@app.get("/home", response_class=HTMLResponse)
def home_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    factions = load_factions()
    can_edit = require_role(user, ["admin"])

    log_action(user["username"], "view_home")

    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={
            "user": user,
            "factions": factions,
            "can_edit": can_edit,
        },
    )


@app.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    log_action(user["username"], "view_profile")

    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={"user": user},
    )


@app.get("/admin/edit", response_class=HTMLResponse)
def admin_edit_get(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if not require_role(user, ["admin"]):
        log_action(user["username"], "access_denied", "/admin/edit")
        return templates.TemplateResponse(
            request=request,
            name="403.html",
            status_code=403,
        )

    factions = load_factions()
    log_action(user["username"], "view_admin_edit")

    return templates.TemplateResponse(
        request=request,
        name="admin_edit.html",
        context={
            "user": user,
            "factions": factions,
        },
    )


@app.post("/admin/edit/add", response_class=HTMLResponse)
async def admin_add_faction(
    request: Request,
    name: str = Form(...),
    symbol: str = Form(""),
    place: str = Form(""),
    characters: str = Form(""),
    strengths: str = Form(""),
    weaknesses: str = Form(""),
    role: str = Form(""),
    order: int = Form(99),
    image: UploadFile = File(None),
):
    user = get_current_user(request)
    if not user or not require_role(user, ["admin"]):
        return templates.TemplateResponse(
            request=request, name="403.html", status_code=403
        )

    factions = load_factions()
    new_id = str(max([int(f.get("id", 0)) for f in factions] + [0]) + 1)

    image_path = ""
    if image and image.filename:
        ext = os.path.splitext(image.filename)[1].lower() or ".jpg"
        safe_name = f"faction_{new_id}{ext}"
        file_location = f"static/images/{safe_name}"
        content = await image.read()
        with open(file_location, "wb") as f:
            f.write(content)
        image_path = file_location

    new_faction = {
        "id": new_id,
        "name": name,
        "symbol": symbol or "⭐",
        "image": image_path,
        "place": place,
        "characters": characters,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "role": role,
        "order": str(order),
    }
    factions.append(new_faction)
    save_factions(factions)

    log_action(user["username"], "add_faction", f"id={new_id} name={name}")

    return RedirectResponse(url="/admin/edit", status_code=303)


@app.post("/admin/edit/update/{faction_id}", response_class=HTMLResponse)
async def admin_update_faction(
    request: Request,
    faction_id: str,
    name: str = Form(...),
    symbol: str = Form(""),
    place: str = Form(""),
    characters: str = Form(""),
    strengths: str = Form(""),
    weaknesses: str = Form(""),
    role: str = Form(""),
    order: int = Form(99),
    image: UploadFile = File(None),
):
    user = get_current_user(request)
    if not user or not require_role(user, ["admin"]):
        return templates.TemplateResponse(
            request=request, name="403.html", status_code=403
        )

    factions = load_factions()
    updated = False
    for f in factions:
        if f.get("id") == faction_id:
            f["name"] = name
            f["symbol"] = symbol or f.get("symbol", "⭐")
            f["place"] = place
            f["characters"] = characters
            f["strengths"] = strengths
            f["weaknesses"] = weaknesses
            f["role"] = role
            f["order"] = str(order)

            if image and image.filename:
                ext = os.path.splitext(image.filename)[1].lower() or ".jpg"
                safe_name = f"faction_{faction_id}{ext}"
                file_location = f"static/images/{safe_name}"
                content = await image.read()
                with open(file_location, "wb") as f_img:
                    f_img.write(content)
                f["image"] = file_location

            updated = True
            break

    if updated:
        save_factions(factions)
        log_action(user["username"], "update_faction", f"id={faction_id}")

    return RedirectResponse(url="/admin/edit", status_code=303)


@app.post("/admin/edit/delete/{faction_id}")
def admin_delete_faction(request: Request, faction_id: str):
    user = get_current_user(request)
    if not user or not require_role(user, ["admin"]):
        return templates.TemplateResponse(
            request=request, name="403.html", status_code=403
        )

    factions = load_factions()
    new_list = [f for f in factions if f.get("id") != faction_id]
    save_factions(new_list)

    log_action(user["username"], "delete_faction", f"id={faction_id}")

    return RedirectResponse(url="/admin/edit", status_code=303)


# ─────────────────────────── Error handlers ───────────────────────────

@app.exception_handler(404)
def custom_404(request: Request, exc):
    user = get_current_user(request)
    username = user["username"] if user else "anonymous"
    log_action(username, "404", request.url.path)
    return templates.TemplateResponse(
        request=request,
        name="404.html",
        status_code=404,
    )


@app.exception_handler(403)
def custom_403(request: Request, exc):
    return templates.TemplateResponse(
        request=request,
        name="403.html",
        status_code=403,
    )
