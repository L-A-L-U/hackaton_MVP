# /servicio_banco/mainBanco.py
import os
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, Float
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session

# ========= Settings =========
BANCO_API_KEY = os.environ.get("BANCO_API_KEY", "dev-key")
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:8000,http://localhost:5173")

DB_FOLDER = "/app/data"
os.makedirs(DB_FOLDER, exist_ok=True)
DATABASE_URL = f"sqlite:///{os.path.join(DB_FOLDER, 'banco.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class Base(DeclarativeBase):
    pass

# ========= Modelo mínimo =========
class Cuenta(Base):
    __tablename__ = "cuentas"
    id = Column(Integer, primary_key=True, index=True)
    saldo = Column(Float, default=0.0)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ========= App =========
app = FastAPI(title="Banco Stub", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= Schemas =========
class PagoIn(BaseModel):
    cuenta_id_banco: int = Field(..., gt=0)
    monto: float = Field(..., gt=0)

class PagoOut(BaseModel):
    ok: bool
    transaccion_id: str
    saldo_post: float

# ========= Utils =========
def require_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key is None or x_api_key != BANCO_API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida")

# ========= Seeds (opcional) =========
@app.post("/seed/", tags=["dev"])
def seed(db: Session = Depends(get_db)):
    """Crea una cuenta demo con saldo si no existe (id=1, saldo=10000)."""
    c = db.query(Cuenta).filter(Cuenta.id == 1).first()
    if not c:
        c = Cuenta(id=1, saldo=10000.0)
        db.add(c)
        db.commit()
    return {"ok": True, "cuenta_id": 1, "saldo": c.saldo}

# ========= Health =========
@app.get("/", tags=["health"])
def health():
    return {"mensaje": "Banco operativo", "version": app.version}

# ========= Pagar =========
@app.post("/pagar/", response_model=PagoOut, tags=["pagos"])
def pagar(p: PagoIn, db: Session = Depends(get_db), _auth=Depends(require_api_key)):
    c = db.query(Cuenta).filter(Cuenta.id == p.cuenta_id_banco).first()
    if not c:
        raise HTTPException(status_code=404, detail="Cuenta no encontrada")
    if c.saldo < p.monto:
        raise HTTPException(status_code=402, detail="Saldo insuficiente")

    c.saldo -= p.monto
    db.commit()
    tx_id = f"BNK-{uuid.uuid4().hex[:12].upper()}"
    return PagoOut(ok=True, transaccion_id=tx_id, saldo_post=c.saldo)
