from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
import datetime

app = FastAPI(title="Hanadora Secure Server 🚀")

# ================= SECURITY =================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "CHANGE_THIS_SECRET_KEY"
ALGORITHM = "HS256"

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)

def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ================= SIMPLE DATABASE =================
users = {}

# ================= MODELS =================
class User(BaseModel):
    username: str
    password: str

# ================= ROUTES =================

@app.get("/")
def home():
    return {"status": "Hanadora server is running 🚀"}

# SIGN UP
@app.post("/signup")
def signup(user: User):
    if user.username in users:
        raise HTTPException(status_code=400, detail="User already exists")

    users[user.username] = hash_password(user.password)

    return {"message": "Account created successfully 🔐"}

# LOGIN
@app.post("/login")
def login(user: User):
    if user.username not in users:
        raise HTTPException(status_code=400, detail="User not found")

    hashed = users[user.username]

    if not verify_password(user.password, hashed):
        raise HTTPException(status_code=400, detail="Wrong password")

    token = create_token({"user": user.username})

    return {
        "message": "Login success 🚀",
        "token": token
    }
