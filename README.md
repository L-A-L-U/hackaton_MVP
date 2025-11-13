# Hackatón MIF - MVP

Este repositorio contiene un MVP de una plataforma de integración bancaria (front + microservicios).

## Estructura

- `front/` → Frontend estático (index.html + assets)
- `servicio_banco/` → Backend FastAPI del banco
- `servicio_seguros/` → Backend FastAPI de seguros
- `docker-compose.yml` → Orquestación de servicios (nginx + backends)

## Cómo correrlo con Docker

```bash
docker compose up --build
Frontend disponible en: http://localhost:8080
 (ejemplo)
Cómo correrlo sin Docker (opcional)
1) Backend banco
cd servicio_banco
source ../venv/bin/activate  # si usas venv
uvicorn main:app --reload --port 8000
