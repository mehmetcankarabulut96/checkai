
import httpx, hashlib, os, uuid

from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client


load_dotenv()

app = FastAPI()

# CORS / Cross Origine Resource Sharing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # restrict only for web ip
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sightengine cradentials
SIGHTENGINE_USER = os.getenv("SIGHTENGINE_USER")
SIGHTENGINE_SECRET = os.getenv("SIGHTENGINE_SECRET")
API_URL = os.getenv("API_URL")

# Supabase cradentials
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Token'ı header'dan almak için
security = HTTPBearer()

api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

async def get_client_from_key(api_key: str = Security(api_key_header)):
    if not api_key:
        return None # normal user, JWT kontrolüne pasla
    
    # Gelen key'i hash'le ve DB'de ara
    hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
    result = supabase.table("api_keys").select("*").eq("key_hash", hashed_key).eq("is_active", True).execute()
    
    if not result.data:
        raise HTTPException(status_code=403, detail="Geçersiz API Key")
    
    return result.data[0] # şirket

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Token'ı doğrula ve kullanıcı bilgilerini al
        user_response = supabase.auth.get_user(token)
        return user_response.user
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Unauthorized: {str(e)}")
    
@app.post("/analyze")
async def analyze_image(
    file: UploadFile = File(...),
    business_client = Depends(get_client_from_key), # API Key kontrolü
    normal_client = Depends(get_current_user) # JWT kontrolü
):
    # Eğer api_client varsa şirket isteğidir, yoksa current_user üzerinden devam et
    active_client_id = business_client["user_id"] if business_client else normal_client.id
    
    try:
        content = await file.read()
        
        params = {
            'models': 'genai',
            'api_user': SIGHTENGINE_USER,
            'api_secret': SIGHTENGINE_SECRET
        }
        
        files = {'media': (file.filename, content, file.content_type)}

        async with httpx.AsyncClient() as client:
            response = await client.post(API_URL, data=params, files=files)
            # Hata kodu dönerse (4xx, 5xx) direkt yakalamak için:
            response.raise_for_status() 
            result = response.json()

        if result.get("status") == "success":
            ai_score = result.get("type", {}).get("ai_generated", 0)
            
            # Resmi Storage'a yükle ve URL al, dosya isimlerini unique yap
            file_extension = file.filename.split(".")[-1]
            unique_filename = f"{uuid.uuid4()}.{file_extension}"
            file_path = f"{active_client_id}/{unique_filename}"
            supabase.storage.from_("images").upload(file_path, content, file_options={"content-type": file.content_type})
            image_url = supabase.storage.from_("images").get_public_url(file_path)

            # DB'ye kaydet
            db_data = {
                "user_id": active_client_id,
                "image_url": image_url,
                "confidence_score": ai_score
            }
            supabase.table("analysis_history").insert(db_data).execute()

            return {
                "confidence_score": ai_score,
                "request_id": result.get("request", {}).get("id")
            }
        
        raise HTTPException(status_code=400, detail=f"API Error: {result}")

    except Exception as e:
        print(f"error details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
async def get_history(
    business_client = Depends(get_client_from_key), # API Key kontrolü
    normal_client = Depends(get_current_user) # JWT kontrolü
):
    # Kim gelirse gelsin user_id'sini al
    active_client_id = business_client["user_id"] if business_client else normal_client.id

    try:
        # Sadece giriş yapan kullanıcıya ait verileri çek
        response = supabase.table("analysis_history") \
            .select("*") \
            .eq("user_id", active_client_id) \
            .order("created_at", desc=True) \
            .execute()
        
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/health")
def health_check():
    return {"status": "online"}

class UserRegister(BaseModel):
    email: EmailStr
    password: str

# TODO: profiles tablosu oluştur ve account_type = individual / company olarak ekle
@app.post("/register")
def register(user: UserRegister):
    try:
        # Supabase auth modülü parolayı kendisi şifreler
        response = supabase.auth.sign_up({
            "email": user.email,
            "password": user.password
        })

        if response.user is None:
            raise HTTPException(
                status_code=400,
                detail="User could not be created"
            )

        return {
            "message": "user register success for " + user.email, 
            "user": response.user
        }
    except Exception as e:
        print(f"error details: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
class UserLogin(BaseModel):
    email: EmailStr
    password: str

@app.post("/login")
def login(user: UserLogin):
    try:
        # Supabase kullanıcının parolasını doğrular ve bir session döner
        response = supabase.auth.sign_in_with_password({
            "email": user.email,
            "password": user.password
        })

        # Supabase, JWT'yi otomatik olarak üretir
        return {
            "message": "login success",
            "access_token": response.session.access_token,
            "refresh_token": response.session.refresh_token,
            "token_type": "bearer"
        }
    except Exception as e:
        print(f"error details: {e}")
        raise HTTPException(status_code=500, detail=str(e))