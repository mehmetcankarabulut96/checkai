
import httpx, hashlib, os, uuid, secrets, jwt, os

from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from starlette.requests import Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# security
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"]
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

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

# b2b cradentials (Sadece X-API-KEY varsa dolu döner)
def get_company_id(request: Request):
    api_key = request.headers.get("X-API-KEY")
    if api_key:
        return f"key_{hashlib.md5(api_key.encode()).hexdigest()}"
    return None # Bu limit atlanır

# b2c cradentials (API Key yoksa çalışır)
def get_individual_id(request: Request):
    if request.headers.get("X-API-KEY"):
        return None # Şirketse bu limiti atla
    
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, options={"verify_signature": False})
            return f"user_{payload.get('sub')}"
        except: pass
    return get_remote_address(request)

# get_remote_address -> Eğer özel bir fonksiyon belirtilmezse IP'ye göre limit koyar
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
    # check if user is a company
    response = supabase.table("profiles").select("account_type").eq("id", current_user["id"]).maybe_single().execute()

    if not response or not response.data or response.data.get("account_type") != "company":
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
@limiter.limit("60/minute", key_func=get_company_id)
@limiter.limit("5/minute", key_func=get_individual_id)
async def analyze_image(
    request: Request,
    file: UploadFile = File(...),
    auth = Depends(get_auth_user)
):
    # file extension check
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unallowed file extension! Allowed extensions: {ALLOWED_EXTENSIONS}"
        )
    # mime type check
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unallowed file mime type"
        )
    # file size check
    if file.size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"file is too big: max size is {MAX_FILE_SIZE / (1024*1024)}MB"
        )

    active_client_id = auth["id"]

    # check credits
    user_query = supabase.table("profiles").select("credits").eq("id", active_client_id).single().execute()
    current_credits = user_query.data.get("credits", 0) if user_query.data else 0
    if current_credits <= 0:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Not enough credits, please do payment"
        )
    
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

            # kredi düşme
            new_credits = current_credits - 1
            supabase.table("profiles").update({"credits": new_credits}).eq("id", active_client_id).execute()

            return {
                "confidence_score": ai_score,
                "request_id": result.get("request", {}).get("id"),
                "remaining_credits": new_credits
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