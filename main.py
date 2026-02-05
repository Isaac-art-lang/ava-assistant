import os
import shutil
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Form, Depends
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from ydata_profiling import ProfileReport
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import uvicorn

app = FastAPI(title="AVA Assistant")

# --- 1. SETUP FOLDERS ---
UPLOAD_DIR = "uploads"
REPORT_DIR = "reports"
STATIC_DIR = "static"
# IMPORTANT: 'templates' folder must exist manually or via code logic below
TEMPLATES_DIR = "templates"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
# Ensure templates dir exists to prevent crash, though you should put index.html there manually
os.makedirs(TEMPLATES_DIR, exist_ok=True) 

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- 2. DATABASE SETUP ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    avatar_url = Column(String, default="/static/default.png") 

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- 3. SECURITY & AUTH ---

def get_password_hash(password):
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password, hashed_password):
    plain_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

async def get_current_user(request: Request, db: Session = Depends(get_db)):
    username = request.cookies.get("user_session")
    if not username:
        return None
    user = db.query(User).filter(User.username == username).first()
    return user

@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return JSONResponse(content={"error": "Username already taken"}, status_code=400)
    
    hashed_pw = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return JSONResponse(content={"message": "Account created! Please login."})

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return JSONResponse(content={"error": "Invalid credentials"}, status_code=401)
    
    response = JSONResponse(content={"message": "Login successful", "username": user.username, "avatar": user.avatar_url})
    response.set_cookie(key="user_session", value=user.username)
    return response

@app.post("/logout")
async def logout():
    response = JSONResponse(content={"message": "Logged out"})
    response.delete_cookie("user_session")
    return response

@app.post("/update-avatar")
async def update_avatar(file: UploadFile = File(...), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user: raise HTTPException(status_code=401, detail="Not logged in")
    
    file_ext = file.filename.split(".")[-1]
    filename = f"avatar_{user.username}.{file_ext}"
    file_path = os.path.join(STATIC_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    user.avatar_url = f"/static/{filename}"
    db.commit()
    return JSONResponse(content={"avatar_url": user.avatar_url})

# --- 4. MAIN APP LOGIC ---

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    user = await get_current_user(request, db)
    # NOTE: This looks for index.html inside the 'templates' folder
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

@app.post("/ask")
async def ask_ava(user_input: str = Form(...)):
    # Placeholder for future AI integration
    return JSONResponse(content={"response": f"Ava received: '{user_input}'"})

@app.post("/process")
async def process_file(file: UploadFile = File(...)):
    # 1. Validation
    if not file.filename.endswith('.csv'): 
        return JSONResponse(content={"error": "Only .csv files are allowed"}, status_code=400)
    
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    
    # 2. Save File
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        print(f"SAVE ERROR: {e}")
        return JSONResponse(content={"error": f"Failed to save file: {str(e)}"}, status_code=500)

    try:
        # 3. Load & Clean Data
        df = pd.read_csv(file_path)
        initial = len(df)
        df.drop_duplicates(inplace=True)
        removed = initial - len(df)
        
        filled = 0
        for col in df.columns:
            if df[col].isnull().sum() > 0:
                filled += int(df[col].isnull().sum())
                # Safe fill logic
                if pd.api.types.is_numeric_dtype(df[col]):
                    df[col] = df[col].fillna(df[col].mean())
                else:
                    df[col] = df[col].fillna("Unknown")
        
        # Save cleaned version
        cleaned_name = f"cleaned_{file.filename}"
        df.to_csv(os.path.join(UPLOAD_DIR, cleaned_name), index=False)
        
        # 4. Generate Report (Wrapped in try/except so it doesn't crash the upload)
        report_url = None
        try:
            print("Generating report...")
            profile = ProfileReport(df, title=f"Analysis: {file.filename}", minimal=True)
            rep_name = f"report_{os.path.splitext(file.filename)[0]}.html"
            profile.to_file(os.path.join(REPORT_DIR, rep_name))
            report_url = f"/download-report/{rep_name}"
            print("Report generated successfully.")
        except Exception as report_error:
            print(f"REPORT GENERATION FAILED: {report_error}")
            # We continue even if report fails

        return JSONResponse(content={
            "filename": file.filename, 
            "duplicates_removed": removed, 
            "missing_filled": filled, 
            "report_url": report_url if report_url else "#" 
        })

    except Exception as e:
        print(f"CRITICAL ERROR: {e}") 
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/download-report/{report_name}")
async def download_report(report_name: str):
    path = os.path.join(REPORT_DIR, report_name)
    if os.path.exists(path): return FileResponse(path)
    return HTMLResponse(content="Report not found", status_code=404)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)