import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from . import models, schemas, crud, auth, twilio_client

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./mindmates.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="MindMates Backend (demo)")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# dependency for DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# token endpoint
@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(get_db)):
    user = crud.get_user_by_email(db, form_data.username)
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")
    token = auth.create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}

# register
@app.post("/users", response_model=schemas.UserOut)
def register_user(user_in: schemas.UserCreate, db=Depends(get_db)):
    existing = crud.get_user_by_email(db, user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = crud.create_user(db, user_in)
    return user

# helper to get current user
from jose import jwt, JWTError
def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        user_id = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# create mood entry
@app.post("/moods", response_model=schemas.MoodCreate)
def add_mood(mood_in: schemas.MoodCreate, current_user = Depends(get_current_user), db=Depends(get_db)):
    entry = crud.create_mood(db, user_id=current_user.id, mood_in=mood_in)
    return {"mood": entry.mood, "note": entry.note}

# assessments
@app.post("/assessments")
def submit_assessment(a: schemas.AssessmentCreate, current_user = Depends(get_current_user), db=Depends(get_db)):
    entry = crud.create_assessment(db, user_id=current_user.id, ass_in=a)
    return {"id": entry.id, "score": entry.score}

# resources
@app.get("/resources", response_model=list[schemas.ResourceOut])
def get_resources(db=Depends(get_db)):
    items = crud.list_resources(db)
    return items

# SOS endpoint (requires confirmation on frontend — backend still verifies auth)
@app.post("/sos")
def sos_trigger(phone_number: str, current_user = Depends(get_current_user)):
    """
    Example flow:
     - Frontend shows confirmation modal “Are you sure?”
     - If confirmed, frontend POSTs to /sos with the user's emergency contact / local helpline number.
     - Backend triggers Twilio SMS/call to that number and/or helpline.
    """
    # Basic safety: ensure phone number sanity check here.
    message = f"SOS triggered by user {current_user.id}. Please contact them immediately."
    try:
        # send SMS (demo)
        res = twilio_client.send_sos_sms(phone_number, message)
        # optionally place a call using a TwiML URL that you host
        # call = twilio_client.place_sos_call(phone_number, "https://example.com/twiml/sos.xml")
        return {"status": "sent", "sid": getattr(res, "sid", None)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    moods = relationship("MoodEntry", back_populates="user")
    assessments = relationship("Assessment", back_populates="user")

class Assessment(Base):
    __tablename__ = "assessments"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    score = Column(Integer)
    data = Column(Text)  # json string of answers (small demo)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="assessments")

class MoodEntry(Base):
    __tablename__ = "mood_entries"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    mood = Column(Integer)         # e.g. scale 1-10
    note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="moods")

class Resource(Base):
    __tablename__ = "resources"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text)
    url = Column(String, nullable=True)
    tag = Column(String, nullable=True)
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str]

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AssessmentCreate(BaseModel):
    score: int
    data: dict

class MoodCreate(BaseModel):
    mood: int
    note: Optional[str] = None

class ResourceOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    url: Optional[str]

    class Config:
        orm_mode = True
from sqlalchemy.orm import Session
from . import models, schemas, auth

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user_in: schemas.UserCreate):
    hashed = auth.hash_password(user_in.password)
    db_user = models.User(email=user_in.email, hashed_password=hashed, full_name=user_in.full_name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_mood(db: Session, user_id: int, mood_in: schemas.MoodCreate):
    entry = models.MoodEntry(user_id=user_id, mood=mood_in.mood, note=mood_in.note)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

def list_resources(db: Session, limit: int = 20):
    return db.query(models.Resource).limit(limit).all()

def create_assessment(db: Session, user_id: int, ass_in: schemas.AssessmentCreate):
    entry = models.Assessment(user_id=user_id, score=ass_in.score, data=str(ass_in.data))
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional

# secret key - put in env
SECRET_KEY = "REPLACE_WITH_SECURE_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
import os
from twilio.rest import Client

TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")  # your Twilio number

client = None
if TWILIO_SID and TWILIO_TOKEN:
    client = Client(TWILIO_SID, TWILIO_TOKEN)

def send_sos_sms(to_number: str, message: str):
    if not client:
        raise RuntimeError("Twilio not configured in env")
    return client.messages.create(to=to_number, from_=TWILIO_FROM, body=message)

def place_sos_call(to_number: str, twiml_url: str):
    if not client:
        raise RuntimeError("Twilio not configured in env")
    return client.calls.create(to=to_number, from_=TWILIO_FROM, url=twiml_url)
