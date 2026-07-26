from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import auth, users, agents, policies, consent, audit, protected

app = FastAPI(title="AI Agent Auth", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://ai-agent-auth-frontend-ch6m-one.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(agents.router)
app.include_router(policies.router)
app.include_router(consent.router)
app.include_router(audit.router)
app.include_router(protected.router)


@app.get("/health")
def health():
    return {"status": "ok"}
