
import httpx, hashlib, os, uuid, secrets, hmac, json, time, cv2, numpy as np, mediapipe as mp, asyncio

from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from starlette.requests import Request
from mediapipe.tasks import python
from mediapipe.tasks.python import vision
from datetime import datetime, timezone

# security
MIN_FILE_SIZE = 50 * 1024 # 50 KB (trash)
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"]
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

# rate limiting
RATE_LIMIT_STORAGE = {} # Rate limit için in-memory storage (MVP için yeterli)
RATE_LIMIT_LOCK = asyncio.Lock()
PACKAGE_LIMITS = { # rate limit / second for packages
    "free": 1,
    "lite": 1,
    "pro": 1
}
PACKAGE_LIMITS_MINUTE = { # rate limit / minute for packages
    "free": 5,
    "lite": 20,
    "pro": 60
}
# monthly limit
MONTHLY_LIMITS = {
    "free": 50,
    "lite": 500,
    "pro": 2000
}
# daily limit
DAILY_LIMITS = {
    "free": 10,
    "lite": 75,
    "pro": 300
}
# business package default limits, theese used if data not fount at database
DEFAULT_BUSINESS_PACKAGE_RATE_LIMIT_SECOND = 5
DEFAULT_BUSINESS_PACKAGE_RATE_LIMIT_MINUTE = 120
DEFAULT_BUSINESS_PACKAGE_DAILY_CREDITS_LIMIT = 500
DEFAULT_BUSINESS_PACKAGE_MONTHLY_CREDITS_LIMIT = 5000

app = FastAPI(title="checkai b2b api", version="1.0.0")

load_dotenv()

# cors
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Sightengine cradentials
SIGHTENGINE_USER = os.getenv("SIGHTENGINE_USER")
SIGHTENGINE_SECRET = os.getenv("SIGHTENGINE_SECRET")
API_URL = os.getenv("API_URL")

# Supabase cradentials
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# authentication (b2b priority)
security = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

# global http client
http_client = httpx.AsyncClient(
    http2=False, # Kararlılık için HTTP/1.1
    limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
    timeout=httpx.Timeout(10.0)
)

# tflite modeli yolu
MODEL_PATH = 'blaze_face_short_range.tflite'

# start the model globally
try:
    base_options = python.BaseOptions(model_asset_path=MODEL_PATH)
    options = vision.FaceDetectorOptions(
        base_options=base_options, 
        min_detection_confidence=0.5
    )
    face_detector = vision.FaceDetector.create_from_options(options)
except Exception as e:
    print(f"tflite model could not be loaded, details: {e}")

async def has_human_face(image_bytes: bytes) -> bool:
    """
        Numpy 2.0+ ve en güncel MediaPipe sürümleriyle uyumlu, 
        'image_ptr' hatasını engelleyen modern implementasyon.
    """
    try:
        # byte verisini Numpy dizisine çevir
        # .copy() eklenmezse MediaPipe '_image_ptr' hatası fırlatır.
        nparr = np.frombuffer(image_bytes, np.uint8).copy()
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return False
            
        # MediaPipe RGB formatı bekler
        img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        # KRİTİK ADIM: Numpy dizisinin hafıza düzenini (memory layout) zorla düzeltiyoruz
        # Bu satır, MediaPipe'ın beklediği C-style hafıza dizilimini garanti eder.
        img_rgb = np.ascontiguousarray(img_rgb)

        # MediaPipe Image objesini oluştur
        mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=img_rgb)
        
        # CPU bloklanmasını önlemek için asenkron thread kullan
        detection_result = await asyncio.to_thread(face_detector.detect, mp_image)
    
        # Sonuçlarda yüz var mı kontrol et
        if len(detection_result.detections) > 0:
            return True
        return False
        
    except Exception as e:
        print(f"Face detection engine failed: {str(e)}")
        raise RuntimeError("Face detection engine failed") from e

# jwt veya api-key ile gelen kullanıcıyı doğrular, öncelik x-api-keydir
async def get_auth_user(
    api_key: str = Depends(api_key_header),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    # x-api-key
    if api_key:
        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
        # supabase sorgusunu ayrı bir thread ile yapıyoruz, böylece saniye bazlı rate limit uygulayabiliriz
        result = await asyncio.to_thread(
            lambda: supabase.table("api_keys").select("user_id").eq("key_hash", hashed_key).eq("is_active", True).execute()
        )
        if result.data:
            return {"id": result.data[0]["user_id"]}
        
    # jwt
    if credentials:
        try:
            user_response = await asyncio.to_thread(
                lambda: supabase.auth.get_user(credentials.credentials)
            )
            return {"id": user_response.user.id}
        except:
            pass

    # unauthorized
    raise HTTPException(status_code=401, detail={"error_code": "UNAUTHORIZED", "message": "unauthorized."})

async def rate_limiter(auth = Depends(get_auth_user)):
    user_id = auth["id"]

    # Kullanıcının planını ve (varsa) özel limitini DB'den al
    profile_res = await asyncio.to_thread(
        lambda: supabase.table("profiles")
        .select("plan_type, custom_rate_limit, custom_rate_limit_min")
        .eq("id", user_id).maybe_single().execute()
    )
    profile = profile_res.data or {}
    plan_type = profile.get("plan_type", "free")
    
    # 1. Limit Belirleme
    if plan_type == "business":
        sec_limit = profile.get("custom_rate_limit") or DEFAULT_BUSINESS_PACKAGE_RATE_LIMIT_SECOND
        minute_limit = profile.get("custom_rate_limit_min") or DEFAULT_BUSINESS_PACKAGE_RATE_LIMIT_MINUTE
    else:
        sec_limit = PACKAGE_LIMITS.get(plan_type, 1)
        minute_limit = PACKAGE_LIMITS_MINUTE.get(plan_type, 5)

    # 2. Limit Kontrolü
    async with RATE_LIMIT_LOCK:
        now = time.time()

        if user_id not in RATE_LIMIT_STORAGE:
            RATE_LIMIT_STORAGE[user_id] = []
        
        # Temizlik: 60 saniyeden eski tüm istekleri bellekten at
        RATE_LIMIT_STORAGE[user_id] = [t for t in RATE_LIMIT_STORAGE[user_id] if now - t < 60.0]
        all_requests = RATE_LIMIT_STORAGE[user_id]

        # A. Saniyelik Kontrol (Son 1 saniye)
        requests_last_sec = [t for t in all_requests if now - t < 1.0]
        if len(requests_last_sec) >= sec_limit:
            raise HTTPException(status_code=429, detail="Rate limit(seconds) exceeded")
        
        # B. Dakikalık Kontrol (Son 60 saniye)
        if len(all_requests) >= minute_limit:
            raise HTTPException(status_code=429, detail=f"Exceeded minute limit: ({minute_limit} req/min).")
            
        # İstek başarılı, zaman damgasını ekle
        RATE_LIMIT_STORAGE[user_id].append(now)

    # Endpoint'in kullanması için auth datayı geri dön
    return auth

async def check_daily_limit(user_id: str, plan_type: str):
    res = await asyncio.to_thread(
        lambda: supabase.table("profiles")
        .select("daily_usage, last_daily_usage_reset, custom_daily_limit")
        .eq("id", user_id).maybe_single().execute()
    )
    profile = res.data or {}
    
    daily_usage = profile.get("daily_usage", 0)
    last_reset_str = profile.get("last_daily_usage_reset")
    if plan_type == "business":
        daily_limit = profile.get("custom_daily_limit") or DEFAULT_BUSINESS_PACKAGE_DAILY_CREDITS_LIMIT
    else:
        daily_limit = DAILY_LIMITS.get(plan_type)

    now = datetime.now(timezone.utc)
    
    # 24 Saat Kontrolü ve Sıfırlama
    if not last_reset_str:
        last_reset_str = now.isoformat()
        
    last_reset = datetime.fromisoformat(last_reset_str.replace('Z', '+00:00'))
    
    if (now - last_reset).total_seconds() >= 86400:
        daily_usage = 0
        await asyncio.to_thread(
            lambda: supabase.table("profiles")
            .update({"daily_usage": 0, "last_daily_usage_reset": now.isoformat()})
            .eq("id", user_id).execute()
        )

    # Limit Aşım Kontrolü
    if daily_usage >= daily_limit:
        raise HTTPException(
            status_code=429, 
            detail=f"Daily usage limit exceeded: max = {daily_limit}."
        )
    
    return daily_usage

# jwt
@app.post("/generate-api-key")
async def generate_api_key(
    current_user = Depends(rate_limiter)
):
    # plan tipini kontrol et
    response = await asyncio.to_thread(
        lambda: supabase.table("profiles").select("plan_type").eq("id", current_user["id"]).maybe_single().execute()
    )
    plan_type = response.data.get("plan_type", "free") if response and response.data else "free"

    # define max key count of plans
    PLAN_LIMITS = {
        "free": 1,
        "lite": 2,
        "pro": 5,
        "business": float('inf') # infinity for enterprises
    }
    max_keys = PLAN_LIMITS.get(plan_type, 1)

    # check key count of user
    keys_query = await asyncio.to_thread(
        lambda: supabase.table("api_keys").select("id", count="exact").eq("user_id", current_user["id"]).execute()
    )
    current_key_count = keys_query.count if keys_query.count is not None else 0

    # check limit
    if current_key_count >= max_keys:
        raise HTTPException(
            status_code=403, 
            detail=f"API Key limit reached for {plan_type} plan. Maximum allowed: {max_keys}. Please delete an existing key to create a new one."
        )
    
    # create random key
    raw_key = f"sk_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_hint = f"{raw_key[:8]}...{raw_key[-4:]}"

    try:
        db_data = {
            "user_id": current_user["id"],
            "key_hash": key_hash,
            "key_hint": key_hint
        }
        await asyncio.to_thread(
            lambda: supabase.table("api_keys").insert(db_data).execute()
        )

        # raw_key only accessed from here
        return {
            "api_key": raw_key,
            "key_hint": key_hint,
            "message": "Save this key with safe. Cannot be read further."
        }
    except Exception as e:
        print(f"Key Error: {e}")
        raise HTTPException(status_code=500, detail="Key generation error")

# decision matrix
ANALYSIS_MAP = {
    "NO_HUMAN_FACE": {
        "label": "NO_HUMAN_FACE",
        "action": "REJECT",
        "risk_level": "LOW",
        "description": "The system could not detect a clear human face in the image.",
        "recommendation": "Please upload a clear profile photo containing a real human face."
    },
    "DEEPFAKE": {
        "label": "DEEPFAKE_DETECTION",
        "action": "REJECT",
        "risk_level": "HIGH",
        "description": "High probability of synthetic face swap or digital identity manipulation detected.",
        "recommendation": "High security risk. Reject the profile photo."
    },
    "SYNTHETIC": {
        "label": "SYNTHETIC_CONTENT",
        "action": "REJECT",
        "risk_level": "HIGH",
        "description": "High probability that the identity or image is entirely generated by artificial intelligence.",
        "recommendation": "High security risk. Reject the profile photo."
    },
    "MODIFIED": {
        "label": "MODIFIED_CONTENT",
        "action": "REVIEW",
        "risk_level": "MEDIUM",
        "description": "Significant digital retouching, heavy filters, or background manipulation detected. The core identity appears intact.",
        "recommendation": "Manual verification is recommended, or prompt the user for an unfiltered photo."
    },
    "INCONCLUSIVE": {
        "label": "INCONCLUSIVE",
        "action": "REVIEW",
        "risk_level": "MEDIUM",
        "description": "Image quality, compression, or file structure is insufficient for a conclusive authenticity analysis.",
        "recommendation": "Request a high-resolution, uncompressed photo taken directly from the device camera."
    },
    "AUTHENTIC": {
        "label": "AUTHENTIC",
        "action": "ACCEPT",
        "risk_level": "LOW",
        "description": "No synthetic face swap or fully AI-generated identity was detected.",
        "recommendation": "Meets identity verification standards. Acceptable."
    }
}

# jwt + api
@app.post("/v1/analyze")
async def analyze_image(
    request: Request,
    file: UploadFile = File(...),
    auth = Depends(rate_limiter)
):
    active_client_id = auth["id"]
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    start_time = time.time()

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
    if file.size < MIN_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"file is too small: min size is {MIN_FILE_SIZE}KB"
        )

    # check credits
    user_query = await asyncio.to_thread(
        lambda: supabase.table("profiles").select("credits, plan_type").eq("id", active_client_id).maybe_single().execute()
    )
    profile_data = user_query.data or {}
    current_credits = profile_data.get("credits", 0)
    plan_type = profile_data.get("plan_type", "free")

    if current_credits <= 0:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Not enough credits, please do payment"
        )
    
    # --- GÜNLÜK LİMİT KONTROLÜ ---
    await check_daily_limit(active_client_id, plan_type)

    try:
        content = await file.read()
        
        try:
            is_human = await has_human_face(content)
        except Exception as face_err:
            raise HTTPException(
                status_code=500, 
                detail={"error": "Face detection service temporarily unavailable. No credits deducted."}
            )

        if not is_human:
            # Yüz yoksa API'ye gitme, sıfır değerleri ata
            decision = ANALYSIS_MAP["NO_HUMAN_FACE"]
            genai_score = 0.0
            deepfake_score = 0.0
            provider_req_id = None
        else:
            # Yüz varsa Sightengine analizini yap
            params = {
                'models': 'genai,deepfake',
                'api_user': SIGHTENGINE_USER,
                'api_secret': SIGHTENGINE_SECRET
            }
            files = {'media': (file.filename, content, file.content_type)}

            response = await http_client.post(API_URL, data=params, files=files)
            response.raise_for_status() 
            result = response.json()

            if result.get("status") != "success":
                raise HTTPException(status_code=400, detail={"request_id": request_id, "error": "Upstream API error"})

            genai_score = result.get("type", {}).get("ai_generated", 0)
            deepfake_score = result.get("type", {}).get("deepfake", 0)
            provider_req_id = result.get("request", {}).get("id")

            # decision
            if deepfake_score >= 0.80: decision = ANALYSIS_MAP["DEEPFAKE"]
            elif genai_score >= 0.85: decision = ANALYSIS_MAP["SYNTHETIC"]
            elif 0.50 <= genai_score < 0.85: decision = ANALYSIS_MAP["MODIFIED"]
            elif 0.30 <= deepfake_score < 0.80 or 0.30 <= genai_score < 0.50: decision = ANALYSIS_MAP["INCONCLUSIVE"]
            else: decision = ANALYSIS_MAP["AUTHENTIC"]

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
            "genai_score": genai_score,
            "deepfake_score": deepfake_score,
            "risk_level": decision["risk_level"],
            "label": decision["label"],
            "action": decision["action"],
            "user_request_id": request_id,
            "provider_request_id": provider_req_id
        }
        db_insert_response = await asyncio.to_thread(
            lambda: supabase.table("analysis_history").insert(db_data).execute()
        )
        history_id = db_insert_response.data[0]['id']

        # güvenli kredi düşme ve günlük sayaç artırma
        try:
            rpc_response = await asyncio.to_thread(
                lambda: supabase.rpc("process_analysis_billing_2", {"user_id": active_client_id}).execute()
            )
            new_credits = rpc_response.data
        except Exception as db_err:
            # İşlem DB seviyesinde reddedildi, eklenen çöp verileri temizle
            await asyncio.to_thread(
                lambda: supabase.table("analysis_history").delete().eq("id", history_id).execute()
            )
            try: supabase.storage.from_("images").remove([file_path])
            except: pass
            raise HTTPException(status_code=500, detail={"request_id": request_id, "error": "Kredi düşülmedi veya günlük sayaç artırılamadı, işlem iptal edildi."})
        
        return {
            "request_id": request_id,
            "status": "success",
            "results": {
                "verdict": {
                    "action": decision["action"],
                    "risk_level": decision["risk_level"],
                    "label": decision["label"]
                },
                "summary": {
                    "description": decision["description"],
                    "recommendation": decision["recommendation"]
                },
                "scores": {
                    "ai_generated": genai_score,
                    "deepfake": deepfake_score
                }
            },
            "meta": {
                "credits_remaining": new_credits,
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }
        }
    except Exception as e:
        print(f"error details: {e}")
        raise HTTPException(status_code=500, detail={"request_id": request_id, "error": str(e)})

# jwt + api
@app.get("/history")
async def get_history(
    auth = Depends(rate_limiter)
):
    # Kim gelirse gelsin user_id'sini al
    active_client_id = auth["id"]

    try:
        # Sadece giriş yapan kullanıcıya ait verileri çek
        response = await asyncio.to_thread(
            lambda: supabase.table("analysis_history") \
                .select("*") \
                .eq("user_id", active_client_id) \
                .order("created_at", desc=True) \
                .execute()
        )
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
    
@app.get("/me")
async def get_me(auth = Depends(rate_limiter)):
    user_id = auth["id"]
    profile = await asyncio.to_thread(
        lambda: supabase.table("profiles").select("*").eq("id", user_id).maybe_single().execute()
    )
    return profile.data or {}

# bir işlemden sonra lemon_squeezy buraya istek atar
@app.post("/webhook/lemonsqueezy", include_in_schema=False)
async def lemon_squeezy_webhook(request: Request):
    secret = os.getenv("LEMON_SQUEEZY_WEBHOOK_SECRET").encode('utf-8')
    signature = request.headers.get("X-Signature")
    
    if not signature:
        raise HTTPException(status_code=400, detail="Missing signature")

    body = await request.body()
    
    # Güvenlik Doğrulaması
    hash_obj = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(hash_obj, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = json.loads(body)
    event_name = payload.get("meta", {}).get("event_name")
    custom_data = payload.get("meta", {}).get("custom_data", {})
    user_id = custom_data.get("user_id")
    attributes = payload.get("data", {}).get("attributes", {})
    variant_id = str(attributes.get("variant_id"))

    # BÖCEK AVI İÇİN BU İKİ SATIRI EKLE:
    print(f"GELEN EVENT: {event_name}")
    print(f"GELEN VARIANT ID: {variant_id}")
    print(f"GELEN USER ID: {user_id}")

    if not user_id:
        return {"status": "ignored", "reason": "user_id not found"}

    attributes = payload.get("data", {}).get("attributes", {})
    variant_id = str(attributes.get("variant_id"))

    # lemon squeezy variants
    LITE_VARIANT_ID = "1490345"
    PRO_VARIANT_ID = "1490323" 
    BUSINESS_VARIANT_ID = "1490341"

    try:
        now_iso = datetime.now(timezone.utc).isoformat()

        # Yeni kayıt, paket yükseltme/düşürme veya aylık yenileme (Krediyi ve Günlük Kullanımı setler)
        if event_name in ['subscription_created', 'subscription_updated', 'subscription_payment_success']:
            plan_type = "free"
            credits = MONTHLY_LIMITS.get(plan_type)
            
            if variant_id == LITE_VARIANT_ID: 
                plan_type = "lite"
                credits = MONTHLY_LIMITS.get(plan_type)
            elif variant_id == PRO_VARIANT_ID: 
                plan_type = "pro"
                credits = MONTHLY_LIMITS.get(plan_type)
            elif variant_id == BUSINESS_VARIANT_ID:
                plan_type = "business"
                credits = int(custom_data.get("custom_credits", DEFAULT_BUSINESS_PACKAGE_MONTHLY_CREDITS_LIMIT))
                
            await asyncio.to_thread(
                lambda: supabase.table("profiles")
                    .update({
                        "plan_type": plan_type,
                        "credits": credits,
                        "daily_usage": 0,                   # Yenilenmede günlük hak sıfırlanır
                        "last_daily_usage_reset": now_iso   # Sayaç an itibariyle baştan başlar
                    }).eq("id", user_id).execute()
            )
            
        # Abonelik süresi tamamen bittiğinde (Free plana düşürür)
        elif event_name == 'subscription_expired':
            await asyncio.to_thread(
                lambda: supabase.table("profiles")
                    .update({
                        "plan_type": "free",
                        "credits": MONTHLY_LIMITS.get("free"),
                        "daily_usage": 0,                   # Plan düştüğünde hakları sıfırdan başlar
                        "last_daily_usage_reset": now_iso
                    }).eq("id", user_id).execute()
            )
        elif event_name in ['order_refunded', 'subscription_cancelled']:
            await asyncio.to_thread(
                lambda: supabase.table("profiles")
                    .update({
                        "plan_type": "free",
                        "credits": 0, # İade yapıldıysa kredisi tamamen sıfırlanmalı
                        "daily_usage": 0,
                        "last_daily_usage_reset": now_iso
                    }).eq("id", user_id).execute()
            )
        return {"status": "success"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))