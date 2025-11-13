# mainBanco.py — Banco (FastAPI) sin llamadas + TTS cache (CBR opcional) + /pagar JSON

# --- 1) Imports ---
import os
import hashlib
import smtplib
from email.message import EmailMessage
import re
import io
import uuid
import glob
import shutil
from typing import Optional
from datetime import datetime, timedelta, timezone

# Seguridad
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# FastAPI y DB
from fastapi import FastAPI, Depends, HTTPException, Header, status, File, UploadFile, Form, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase
from sqlalchemy.exc import IntegrityError

# TTS
from gtts import gTTS
try:
    from pydub import AudioSegment  # opcional; requiere ffmpeg si está disponible
    HAVE_PYDUB = True
except Exception:
    AudioSegment = None
    HAVE_PYDUB = False


# --- 2) Configuración de Seguridad ---
SECRET_KEY = "mi-clave-secreta-del-hackathon-banxico"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# OJO: usar /login/ con slash final para que /docs funcione sin warnings
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")


# --- 3) Configuración de Paths/DB (local, fuera de Docker) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_FOLDER = os.path.join(BASE_DIR, "data_db")
os.makedirs(DB_FOLDER, exist_ok=True)
DB_FILE_PATH = os.path.join(DB_FOLDER, "banco.db")

UPLOAD_FOLDER = os.path.join(BASE_DIR, "data_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

AUDIO_FOLDER = os.path.join(UPLOAD_FOLDER, "tts")
os.makedirs(AUDIO_FOLDER, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_FILE_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass


# --- 4) Modelo de la Tabla (Usuarios) ---
class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    username = Column(String, unique=True, index=True, nullable=False)
    rfc = Column(String, unique=True, index=True, nullable=False)
    curp = Column(String, unique=True, index=True, nullable=False)
    telefono = Column(String, unique=True, index=True, nullable=False)
    correo = Column(String, unique=True, nullable=True)
    hashed_password = Column(String, nullable=True)

    # Flujo sin llamadas:
    # PENDIENTE_REGISTRO -> PENDIENTE_VERIFICACION -> ACTIVO
    status = Column(String, default="PENDIENTE_REGISTRO")

    # Ruta del archivo de identificación (si se sube)
    url_id_simulada = Column(String, nullable=True)

    # Campo antiguo (no se usa, se deja para compatibilidad DB)
    url_llamada_agente = Column(String, nullable=True)

    saldo = Column(Float, default=0.0)

Base.metadata.create_all(bind=engine)


# --- 5) App y CORS ---
app = FastAPI(title="API del Banco (sin llamadas) con TTS cache y /pagar JSON")
origins = [
    "http://localhost", "http://127.0.0.1",
    "http://localhost:80", "http://127.0.0.1:80",
    "http://localhost:8080", "http://127.0.0.1:8080",
    "http://localhost:8000", "http://127.0.0.1:8000",
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:5500", "http://127.0.0.1:5500", 
    "null",  # para cuando abres el HTML como file:// (Origin: null)
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- 6) Modelos / Validaciones ---
RFC_REGEX = r"^[A-Z&Ñ]{3,4}\d{6}[A-Z\d]{3}$"
USERNAME_REGEX = r"^[a-zA-Z0-9_]{5,20}$"

class RegistroUsuario(BaseModel):
    nombre: str
    username: str = Field(..., pattern=USERNAME_REGEX)
    rfc: str = Field(..., pattern=RFC_REGEX)
    curp: str = Field(..., min_length=18, max_length=18)
    telefono: str
    password: str = Field(..., min_length=8, max_length=72)  # max 72 por bcrypt clásico, aquí igual lo limitamos
    correo: Optional[EmailStr] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class Transferencia(BaseModel):
    curp_destino: str = Field(..., description="CURP del receptor")
    monto: float = Field(..., gt=0)

class PagoIn(BaseModel):
    cuenta_id_banco: int = Field(..., gt=0)
    monto: float = Field(..., gt=0)


# --- 7) Helpers de seguridad / sesión ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def sha256_hex(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()

def expected_user_token_for(user: "Usuario") -> str:
    """El 'token' esperado es SHA-256(RFC) en hex (64 chars)."""
    return sha256_hex((user.rfc or "").strip().upper())

HEX64_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise cred_exc
    except JWTError:
        raise cred_exc

    usuario = db.query(Usuario).filter(Usuario.username == username).first()
    if usuario is None:
        raise cred_exc
    if usuario.status != "ACTIVO":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Usuario no está activo. Completa la verificación.")
    return usuario


# Traducciones de ejemplo para /saldo/audio/me
translations = {
    "es": {"user_not_found": "Usuario no encontrado", "balance_is": "Tu saldo actual es de {} pesos"},
    "nah": {"user_not_found": "Matiac amo nesi (Usuario no encontrado)", "balance_is": "Mo saldo axcan de {} pesos (Tu saldo actual es de {} pesos)"},
}
def get_translation(lang: str, key: str, *args):
    if lang not in translations:
        lang = "es"
    return translations[lang].get(key, "???").format(*args)

API_KEY = os.environ.get("BANCO_API_KEY")
async def api_key_security(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="API Key inválida o faltante")


# --- 8) Utils TTS (cache + CBR 96 kbps mono opcional) ---
def tts_file_path(key: str) -> str:
    safe = key.replace("/", "_").replace("\\", "_")
    return os.path.join(AUDIO_FOLDER, f"{safe}.mp3")

def _reencode_voice_stable(in_path: str, out_path: str) -> None:
    """
    Re-encode a MP3 CBR 96 kbps, mono, 22.05 kHz. Mucho más estable para TTS.
    Si no hay pydub/ffmpeg, copia tal cual (fallback).
    """
    if not HAVE_PYDUB:
        shutil.copyfile(in_path, out_path)
        return
    audio = AudioSegment.from_file(in_path)
    # mono + 22050 Hz
    audio = audio.set_channels(1).set_frame_rate(22050)
    audio.export(
        out_path,
        format="mp3",
        bitrate="96k",
        parameters=["-ac", "1"]  # asegura mono
    )

def ensure_tts_file(key: str, text: str, lang: str = "es") -> str:
    final_path = tts_file_path(key)
    if os.path.exists(final_path):
        return final_path

    safe = key.replace("/", "_").replace("\\", "_")     # <= sanitiza SOLO la key
    tmp_raw = os.path.join(AUDIO_FOLDER, f"_{safe}.tmp.mp3")  # <= construye bien el path

    tts = gTTS(text=text, lang=lang)
    tts.save(tmp_raw)
    _reencode_voice_stable(tmp_raw, final_path)
    try: os.remove(tmp_raw)
    except: pass
    return final_path


# --- 9) Endpoints básicos ---
@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.utcnow().isoformat()}

@app.get("/")
def root():
    return {
        "mensaje": "Backend del Banco activo (sin llamadas)",
        "flujo": ["PENDIENTE_REGISTRO", "PENDIENTE_VERIFICACION", "ACTIVO"]
    }

# Registro (sin llamadas)
@app.post("/registrar/")
async def registrar_usuario(
    usuario: RegistroUsuario,
    db: Session = Depends(get_db),
    accesibilidad: bool = False
):
    # Hash password con manejo de error claro
    try:
        hashed_password = get_password_hash(usuario.password)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al hashear password: {e}")

    nuevo = Usuario(
        nombre=usuario.nombre,
        username=usuario.username,
        rfc=usuario.rfc.upper(),
        curp=usuario.curp.upper(),
        telefono=usuario.telefono,
        correo=usuario.correo,
        hashed_password=hashed_password,
        status="PENDIENTE_REGISTRO",
        url_llamada_agente=None,  # no se usa
    )
    try:
        db.add(nuevo)
        db.commit()
        db.refresh(nuevo)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error: Username, RFC, CURP o teléfono ya registrado.")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Fallo inesperado en /registrar: {e}")

    if accesibilidad:
        msg = "Registro inicial completo. Continúa en la app para capturar tu identificación con asistente accesible."
        extra = {"url_mensaje_audio": f"/registrar/audio/{nuevo.id}"}
    else:
        msg = "Registro inicial completo. Siguiente paso: sube tu identificación en la app."
        extra = {}

    return {"mensaje": msg, "id_usuario": nuevo.id, "curp": nuevo.curp, **extra}

# Login
@app.post("/login/", response_model=Token)
async def login_para_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(Usuario.username == form_data.username).first()
    if not usuario or not verify_password(form_data.password, usuario.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # NO bloqueamos por estado aquí; la protección fuerte queda en get_current_user
    access_token = create_access_token(data={"sub": usuario.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/registrar/audio/{usuario_id}")
async def get_audio_confirmacion_registro(usuario_id: int, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    texto = (
        f"Hola {usuario.nombre}. Tu registro inicial está completo. "
        f"Continúa en la aplicación para capturar tu identificación con asistencia accesible si lo necesitas."
    )
    try:
        key = f"registro_{usuario.id}"
        path = ensure_tts_file(key, texto, lang="es")
        return FileResponse(
            path,
            media_type="audio/mpeg",
            filename=os.path.basename(path),
            headers={
                "Cache-Control": "public, max-age=86400",
                "Accept-Ranges": "bytes",
                "Content-Disposition": "inline"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al generar audio: {str(e)}")

# Subir identificación
@app.post("/cargar_id/")
async def cargar_identificacion(
    curp: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    usuario = db.query(Usuario).filter(Usuario.curp == curp.upper()).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if usuario.status != "PENDIENTE_REGISTRO":
        raise HTTPException(status_code=400, detail=f"El usuario no está en estado 'PENDIENTE_REGISTRO'. Estado actual: {usuario.status}")

    try:
        ext = os.path.splitext(file.filename)[1]
        unique_filename = f"{uuid.uuid4()}{ext}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al guardar el archivo: {e}")
    finally:
        file.file.close()

    usuario.url_id_simulada = file_path
    usuario.status = "PENDIENTE_VERIFICACION"
    db.commit()

    return {"mensaje": "Identificación recibida. Quedará en revisión."}

@app.post("/admin/aprobar/")
async def aprobar_usuario(curp: str, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.curp == curp.upper()).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # PERMITIR aprobar desde PENDIENTE_VERIFICACION **y** PENDIENTE_REGISTRO (modo demo)
    if usuario.status not in ["PENDIENTE_VERIFICACION", "PENDIENTE_REGISTRO"]:
        raise HTTPException(status_code=400, detail=f"No se puede aprobar un usuario en estado '{usuario.status}'")

    usuario.status = "ACTIVO"
    usuario.url_id_simulada = None
    usuario.url_llamada_agente = None
    usuario.saldo = (usuario.saldo or 0.0) + 50.00
    db.commit()

    return {"mensaje": f"Usuario {usuario.nombre} APROBADO y ACTIVO. Se abonaron $50 MXN."}

# --- /mis_cuentas (usa el saldo real del usuario ACTIVO) ---
@app.get("/mis_cuentas")
def mis_cuentas(current_user: Usuario = Depends(get_current_user)):
    debito = {
        "tipo": "debito",
        "alias": "Cuenta Nómina",
        "numero": f"**** {current_user.curp[-4:]}",   # máscara estable
        "disponible": float(round(current_user.saldo, 2)),
        "saldo": float(round(current_user.saldo, 2)),
        "moneda": "MXN",
        "tags": ["Principal"]
    }
    credito_demo = {
        "tipo": "credito",
        "alias": "Visa Oro",
        "numero": "**** 7788",
        "disponible": 7800.00,
        "saldo": 1200.00,
        "limite": 9000.00,
        "moneda": "MXN",
        "tags": ["Domiciliado"]
    }
    cuentas = [debito, credito_demo]
    total = float(round(debito["disponible"], 2))
    return {"total_disponible": total, "cuentas": cuentas}

# Saldos
@app.get("/saldo/me")
def consultar_saldo_simple(current_user: Usuario = Depends(get_current_user)):
    return {"saldo": current_user.saldo}

@app.get("/saldo/audio/me")
async def consultar_saldo_propio_en_audio(
    current_user: Usuario = Depends(get_current_user),
    accept_language: Optional[str] = Header("es")
):
    lang = "es"  # gTTS no soporta náhuatl
    texto = get_translation("es", "balance_is", current_user.saldo)
    try:
        key = f"saldo_{current_user.id}_{int(current_user.saldo*100)}"
        path = ensure_tts_file(key, texto, lang="es")
        return FileResponse(
            path,
            media_type="audio/mpeg",
            filename=os.path.basename(path),
            headers={
                "Cache-Control": "public, max-age=300",
                "Accept-Ranges": "bytes",
                "Content-Disposition": "inline"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al generar audio: {str(e)}")

@app.get("/saldo/me/simple")
def consultar_saldo_modo_simple(current_user: Usuario = Depends(get_current_user)):
    u = current_user
    return {
        "usuario_id": u.id,
        "nombre": u.nombre,
        "saldo_actual": u.saldo,
        "moneda": "MXN",
        "explicacion_simple": f"Hola {u.nombre}. Tienes {u.saldo} pesos en tu cuenta.",
        "link_lsm_simulado": f"https://youtube.com/watch?v=lsm-video-sobre-saldo-{u.saldo}",
    }

# Transferencias
@app.post("/transferir/")
async def instruir_pago(
    transferencia: Transferencia,
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_user_token: Optional[str] = Header(None, alias="X-User-Token"),
    x_rfc_hash: Optional[str] = Header(None, alias="X-RFC-Hash"),
):
    # Validación opcional de token (si viene, debe coincidir).
    # El token y el "hash" esperado son SHA-256(RFC) en hex (64 chars).
    expected = expected_user_token_for(current_user)

    if x_user_token:
        if not HEX64_RE.match(x_user_token) or x_user_token.lower() != expected.lower():
            raise HTTPException(status_code=403, detail="Token inválido o no coincide con tu RFC.")
    if x_rfc_hash:
        if not HEX64_RE.match(x_rfc_hash) or x_rfc_hash.lower() != expected.lower():
            raise HTTPException(status_code=403, detail="Hash RFC inválido o no coincide.")

    if current_user.curp.upper() == transferencia.curp_destino.upper():
        raise HTTPException(status_code=400, detail="No puedes transferirte dinero a ti mismo.")
    if current_user.saldo < transferencia.monto:
        raise HTTPException(status_code=400, detail="Saldo insuficiente.")

    destino = db.query(Usuario).filter(Usuario.curp == transferencia.curp_destino.upper()).first()
    if not destino:
        raise HTTPException(status_code=404, detail="La cuenta (CURP) de destino no existe.")
    if destino.status != "ACTIVO":
        raise HTTPException(status_code=400, detail="La cuenta de destino no está activa/verificada.")

    try:
        current_user.saldo -= transferencia.monto
        destino.saldo += transferencia.monto
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error interno durante la transacción: {e}")

    return {
        "mensaje": "Transferencia exitosa",
        "monto_enviado": transferencia.monto,
        "curp_destino": destino.curp,
        "tu_nuevo_saldo": current_user.saldo
    }

# Finanzas abiertas: /pagar (JSON + API Key)
@app.post("/pagar/", dependencies=[Depends(api_key_security)])
async def realizar_pago(
    body: PagoIn,
    db: Session = Depends(get_db)
):
    usuario_banco = db.query(Usuario).filter(Usuario.id == body.cuenta_id_banco).first()
    if not usuario_banco:
        raise HTTPException(status_code=404, detail="La cuenta de banco no existe")
    if usuario_banco.status != "ACTIVO":
        raise HTTPException(status_code=403, detail="La cuenta de banco no está activa/verificada.")
    if usuario_banco.saldo < body.monto:
        raise HTTPException(status_code=400, detail="Saldo insuficiente")

    usuario_banco.saldo -= body.monto
    db.commit()

    return {
        "mensaje": "Pago procesado exitosamente",
        "nuevo_saldo": usuario_banco.saldo,
        "id_transaccion": f"txn_{usuario_banco.id}_{body.monto}"
    }

# --- 10) Endpoints TTS: limpiar caché ---
@app.delete("/tts/cache", tags=["tts"])
def tts_cache_delete_key(key: str = Query(..., description="Clave exacta del TTS a borrar")):
    """
    Borra un archivo TTS por 'key' (la misma usada en ensure_tts_file).
    """
    path = tts_file_path(key)
    if os.path.exists(path):
        os.remove(path)
        return {"ok": True, "borrado": os.path.basename(path)}
    return {"ok": False, "detalle": "No existe esa clave en caché"}

@app.delete("/tts/cache/all", tags=["tts"])
def tts_cache_delete_all():
    """
    Borra todos los MP3 cacheados de TTS.
    """
    files = glob.glob(os.path.join(AUDIO_FOLDER, "*.mp3"))
    count = 0
    for f in files:
        try:
            os.remove(f); count += 1
        except Exception:
            pass
    return {"ok": True, "archivos_borrados": count}

@app.delete("/tts/cache/older-than", tags=["tts"])
def tts_cache_delete_older_than(hours: int = Query(24, ge=1, le=24*30)):
    """
    Borra audios TTS más antiguos que 'hours' (por defecto 24h).
    """
    cutoff = datetime.now().timestamp() - (hours * 3600)
    files = glob.glob(os.path.join(AUDIO_FOLDER, "*.mp3"))
    count = 0
    for f in files:
        try:
            if os.path.getmtime(f) < cutoff:
                os.remove(f); count += 1
        except Exception:
            pass
    return {"ok": True, "archivos_borrados": count, "horas": hours}

# --- 11) SMTP opcional para mandar token por correo (no obligatorio) ---
def _send_token_email_smtp(to_email: str, token: str) -> bool:
    """
    Envío SMTP opcional:
      - SMTP_HOST
      - SMTP_PORT (num)
      - SMTP_USER
      - SMTP_PASS
      - SMTP_FROM (opcional; default = SMTP_USER)
      - SMTP_TLS ("1" para STARTTLS)
    Si falta algo crítico, devolvemos False → el endpoint hará no-op.
    """
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "0") or "0")
    user = os.environ.get("SMTP_USER")
    pwd  = os.environ.get("SMTP_PASS")
    use_tls = os.environ.get("SMTP_TLS", "1") == "1"
    mail_from = os.environ.get("SMTP_FROM") or user

    if not (host and port and user and pwd and mail_from):
        return False

    msg = EmailMessage()
    msg["Subject"] = "Tu token de seguridad (hash RFC)"
    msg["From"] = mail_from
    msg["To"] = to_email
    msg.set_content(f"Este es tu token de seguridad (SHA-256 de tu RFC):\n\n{token}\n\nGuárdalo de forma segura.")

    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            if use_tls:
                s.starttls()
            s.login(user, pwd)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[token_email] Error SMTP: {e}")
        return False

@app.post("/token_email")
async def token_email(payload: dict):
    """
    Espera: { "to": "correo@dominio.com", "token": "hex64" }
    - Si hay SMTP configurado: envía el correo.
    - Si no: hace no-op y devuelve ok (para no romper el flujo del frontend).
    """
    to = (payload or {}).get("to")
    token = (payload or {}).get("token")

    if not to:
        raise HTTPException(status_code=400, detail="Falta 'to'")
    if not token or not HEX64_RE.match(token):
        raise HTTPException(status_code=400, detail="Token inválido (debe ser hex de 64 chars)")

    sent = _send_token_email_smtp(to, token)
    if sent:
        return {"ok": True, "sent": True, "detail": "Correo enviado"}
    else:
        # No-op: registramos en consola y seguimos
        print(f"[token_email] SMTP no configurado. Simulando envío a {to} con token {token[:8]}…")
        return {"ok": True, "sent": False, "detail": "SMTP no configurado; no-op"}


# === NUEVO: /tts genérico (GET/POST) ===
class TTSIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=1200)
    lang: Optional[str] = Field("es", min_length=2, max_length=5)

def _tts_key(text: str, lang: str) -> str:
    h = hashlib.sha256(f"{lang}|{text}".encode("utf-8")).hexdigest()
    return f"tts_{lang}_{h}"

def _tts_response(path: str) -> FileResponse:
    return FileResponse(
        path,
        media_type="audio/mpeg",
        filename=os.path.basename(path),
        headers={
            "Cache-Control": "public, max-age=604800",  # 7 días
            "Accept-Ranges": "bytes",
            "Content-Disposition": "inline"
        }
    )

@app.get("/tts")
async def tts_get(text: str = Query(..., min_length=1, max_length=1200), lang: str = Query("es", min_length=2, max_length=5)):
    try:
        key = _tts_key(text, lang)
        path = ensure_tts_file(key, text, lang=lang)
        return _tts_response(path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error TTS: {e}")

@app.post("/tts")
async def tts_post(body: TTSIn):
    try:
        key = _tts_key(body.text, body.lang or "es")
        path = ensure_tts_file(key, body.text, lang=(body.lang or "es"))
        return _tts_response(path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error TTS: {e}")
