from fastapi import FastAPI

from api.routes import router

app = FastAPI(
    title="VPN-SIGR API",
    description="API REST para la administración del servidor VPN-SIGR.",
    version="1.0.0"
)

app.include_router(router)


@app.get("/")
def root():
    return {
        "message": "VPN-SIGR API funcionando correctamente",
        "documentation": "/docs"
    }