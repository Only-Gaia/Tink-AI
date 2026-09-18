import os
import sqlite3
import base64
import time
import requests
from urllib.parse import quote
from datetime import datetime

from flask import Flask, request, jsonify, session, render_template, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from google import genai

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cambia-questa-chiave-in-produzione")

DB_PATH = os.path.join(os.path.dirname(__file__), "tink.db")

# Il client legge automaticamente la variabile d'ambiente GEMINI_API_KEY
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

TEXT_MODEL = "gemini-3.6-flash"

# Quante volte riprovare se Google risponde "modello sovraccarico" (503),
# e quanti secondi aspettare tra un tentativo e l'altro (aumenta ogni volta).
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2


def generate_with_retry(**kwargs):
    """Chiama client.models.generate_content ritentando automaticamente
    se il modello risponde 'sovraccarico' (503/UNAVAILABLE) o con un
    errore temporaneo simile (429/RESOURCE_EXHAUSTED)."""
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return client.models.generate_content(**kwargs)
        except Exception as e:
            last_error = e
            error_text = str(e)
            is_temporary = any(
                code in error_text for code in ("503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED")
            )
            if not is_temporary or attempt == MAX_RETRIES:
                raise
            time.sleep(RETRY_DELAY_SECONDS * attempt)
    raise last_error


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT,
            image_base64 TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (conversation_id) REFERENCES conversations (id)
        );
        """
    )
    conn.commit()
    conn.close()


init_db()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Devi effettuare il login"}), 401
        conn = get_db()
        user = conn.execute(
            "SELECT id FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        conn.close()
        if not user:
            session.clear()
            return jsonify({"error": "Sessione scaduta, effettua di nuovo il login"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


# ---------------------------------------------------------------------------
# Gestione errori: qualsiasi eccezione non prevista torna come JSON leggibile
# invece di una pagina HTML di errore (che mandava in crash il fetch() sul
# browser mostrando il generico "Errore di connessione al server").
# ---------------------------------------------------------------------------

@app.errorhandler(Exception)
def handle_any_error(e):
    app.logger.exception("Errore non gestito")
    return jsonify({"error": f"Errore interno del server: {e}"}), 500


# ---------------------------------------------------------------------------
# Pagine
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    if "user_id" not in session:
        return render_template("index.html", logged_in=False)
    return render_template("index.html", logged_in=True, username=session.get("username"))


# ---------------------------------------------------------------------------
# Autenticazione
# ---------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if len(username) < 3:
        return jsonify({"error": "Username minimo 3 caratteri"}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Inserisci un'email valida"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password minimo 4 caratteri"}), 400

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Username o email già registrati"}), 400

    password_hash = generate_password_hash(password)
    cur = conn.execute(
        "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, email, password_hash, datetime.utcnow().isoformat()),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    session["user_id"] = user_id
    session["username"] = username
    return jsonify({"ok": True, "username": username})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Email o password errati"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"ok": True, "username": user["username"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Conversazioni
# ---------------------------------------------------------------------------

@app.route("/api/conversations", methods=["GET"])
@login_required
def list_conversations():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, title, created_at FROM conversations WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/conversations/new", methods=["POST"])
@login_required
def new_conversation():
    # Creare una nuova riga "salva" automaticamente quella precedente,
    # che resta intatta e consultabile nella cronologia.
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO conversations (user_id, title, created_at) VALUES (?, ?, ?)",
        (session["user_id"], None, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conv_id = cur.lastrowid
    conn.close()
    session["conversation_id"] = conv_id
    return jsonify({"conversation_id": conv_id})


@app.route("/api/conversations/<int:conv_id>/messages", methods=["GET"])
@login_required
def get_messages(conv_id):
    conn = get_db()
    conv = conn.execute(
        "SELECT * FROM conversations WHERE id = ? AND user_id = ?", (conv_id, session["user_id"])
    ).fetchone()
    if not conv:
        conn.close()
        return jsonify({"error": "Conversazione non trovata"}), 404

    rows = conn.execute(
        "SELECT role, content, image_base64, created_at FROM messages WHERE conversation_id = ? ORDER BY id ASC",
        (conv_id,),
    ).fetchall()
    conn.close()
    session["conversation_id"] = conv_id
    return jsonify([dict(r) for r in rows])


def _ensure_conversation():
    """Ritorna l'id della conversazione corrente, creandone una se non esiste
    o se il database è stato azzerato (es. dopo un redeploy) e l'id salvato
    nella sessione del browser non corrisponde più a nulla."""
    conv_id = session.get("conversation_id")
    conn = get_db()

    if conv_id:
        row = conn.execute(
            "SELECT id FROM conversations WHERE id = ? AND user_id = ?",
            (conv_id, session["user_id"]),
        ).fetchone()
        if row:
            conn.close()
            return conv_id

    cur = conn.execute(
        "INSERT INTO conversations (user_id, title, created_at) VALUES (?, ?, ?)",
        (session["user_id"], None, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conv_id = cur.lastrowid
    conn.close()
    session["conversation_id"] = conv_id
    return conv_id


def _save_message(conv_id, role, content=None, image_base64=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO messages (conversation_id, role, content, image_base64, created_at) VALUES (?, ?, ?, ?, ?)",
        (conv_id, role, content, image_base64, datetime.utcnow().isoformat()),
    )
    # Se è il primo messaggio utente, usalo come titolo della conversazione
    row = conn.execute(
        "SELECT title FROM conversations WHERE id = ?", (conv_id,)
    ).fetchone()
    if role == "user" and content and not row["title"]:
        title = content[:40] + ("..." if len(content) > 40 else "")
        conn.execute("UPDATE conversations SET title = ? WHERE id = ?", (title, conv_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Chat testuale
# ---------------------------------------------------------------------------

@app.route("/api/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json(force=True)
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "Messaggio vuoto"}), 400

    conv_id = _ensure_conversation()

    # Recupera la cronologia per dare contesto al modello
    conn = get_db()
    history = conn.execute(
        "SELECT role, content FROM messages WHERE conversation_id = ? AND content IS NOT NULL ORDER BY id ASC",
        (conv_id,),
    ).fetchall()
    conn.close()

    contents = []
    for m in history:
        role = "user" if m["role"] == "user" else "model"
        contents.append({"role": role, "parts": [{"text": m["content"]}]})
    contents.append({"role": "user", "parts": [{"text": user_message}]})

    _save_message(conv_id, "user", content=user_message)

    try:
        response = generate_with_retry(model=TEXT_MODEL, contents=contents)
        reply_text = response.text or "(nessuna risposta)"
    except Exception as e:
        reply_text = f"Errore nel contattare l'IA: {e}"

    _save_message(conv_id, "assistant", content=reply_text)

    return jsonify({"reply": reply_text, "conversation_id": conv_id})


# ---------------------------------------------------------------------------
# Generazione immagini
# ---------------------------------------------------------------------------

@app.route("/api/generate-image", methods=["POST"])
@login_required
def generate_image():
    data = request.get_json(force=True)
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "Prompt vuoto"}), 400

    conv_id = _ensure_conversation()
    _save_message(conv_id, "user", content=f"[Immagine] {prompt}")

    try:
        # Pollinations.ai: servizio di generazione immagini gratuito, senza
        # bisogno di chiave API. Limite: circa 1 immagine ogni 15 secondi.
        encoded_prompt = quote(prompt)
        url = f"https://image.pollinations.ai/prompt/{encoded_prompt}?width=1024&height=1024&nologo=true"
        img_response = requests.get(url, timeout=90)
        img_response.raise_for_status()
        image_b64 = base64.b64encode(img_response.content).decode("utf-8")
    except Exception as e:
        return jsonify({"error": f"Errore nella generazione: {e}"}), 500

    _save_message(conv_id, "assistant", image_base64=image_b64)

    return jsonify({"image_base64": image_b64, "conversation_id": conv_id})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
