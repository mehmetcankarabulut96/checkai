
import httpx, hashlib, os, uuid, secrets

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
security = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

# jwt veya api-key ile gelen kullanıcıyı doğrular, öncelik x-api-keydir
async def get_auth_user(
    api_key: str = Depends(api_key_header),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    # x-api-key
    if api_key:
        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
        result = supabase.table("api_keys").select("user_id").eq("key_hash", hashed_key).eq("is_active", True).execute()
        
        if result.data:
            return {"id": result.data[0]["user_id"], "type": "company"}
        
    # jwt
    if credentials:
        try:
            user_response = supabase.auth.get_user(credentials.credentials)
            return {"id": user_response.user.id, "type": "individual"}
        except:
            pass

    # unauthorized
    raise HTTPException(status_code=401, detail="unauthorized")
    
# jwt
@app.post("/generate-api-key")
async def generate_api_key(
    current_user = Depends(get_auth_user)
):
    # check if user is a compan
    profile = supabase.table("profiles").select("account_type").eq("id", current_user.id).single().execute()
    
    if not profile.data or profile.data.get("account_type") != "company":
        raise HTTPException(
            status_code=403, 
            detail="Only companies can generate API Key"
        )
    
    # create random key
    raw_key = f"sk_live_{secrets.token_urlsafe(32)}"

    # hash the key and create hint
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_hint = f"{raw_key[:8]}...{raw_key[-4:]}"

    try:
        db_data = {
            "user_id": current_user.id,
            "key_hash": key_hash,
            "key_hint": key_hint
        }
        supabase.table("api_keys").insert(db_data).execute()

        # raw_key only accessed from here
        return {
            "api_key": raw_key,
            "key_hint": key_hint,
            "message": "Save this key with safe. Cannot be read further."
        }
    except Exception as e:
        print(f"Key Error: {e}")
        raise HTTPException(status_code=500, detail="Key generation error")

# jwt + api
@app.post("/analyze")
async def analyze_image(
    file: UploadFile = File(...),
    auth = Depends(get_auth_user)
):
    active_client_id = auth["id"]

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

# jwt + api
@app.get("/history")
async def get_history(
    auth = Depends(get_auth_user)
):
    # Kim gelirse gelsin user_id'sini al
    active_client_id = auth["id"]

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

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    account_type: str

@app.post("/register")
def register(user: UserRegister):
    try:
        # Supabase auth modülü parolayı kendisi şifreler
        response = supabase.auth.sign_up({
            "email": user.email,
            "password": user.password,
            "options": {
                "data": {
                    "account_type": user.account_type
                }
            }
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
        print(f"error details: {repr(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# bu endpointi arayüz üzerinden giriş yapacak bireysel kullanıcılar ve şirket yetkilileri(admin paneli) kullanır
# b2b uygulamalar login olmadan access-token ile istek yaparlar
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