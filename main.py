from fastapi import FastAPI, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.status import HTTP_401_UNAUTHORIZED
from fastapi.responses import JSONResponse
import secrets

app = FastAPI()

security = HTTPBasic()


users = {
    "admin": "secret123",
    "user": "password"
}


def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    correct_password = users.get(credentials.username)
    if not correct_password or not secrets.compare_digest(credentials.password, correct_password):
        return JSONResponse(
            status_code=HTTP_401_UNAUTHORIZED,
            content={"detail": "Invalid credentials"},
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/secure-data")
def read_secure_data(username: str = Depends(get_current_user)):
    return {"message": f"Привіт, {username}! ви авторизовані}

