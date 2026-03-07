from fastapi import FastAPI, File, UploadFile, HTTPException
import httpx

app = FastAPI()

# Sightengine cradentials
SIGHTENGINE_USER = "793268268"
SIGHTENGINE_SECRET = "vCnRhTqQ9K9TmXX4B6my4qPazXY7xR4S"
API_URL = "https://api.sightengine.com/1.0/check.json"


@app.post("/analyze")
async def analyze_image(file: UploadFile = File(...)):
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
            
            return {
                "is_ai": ai_score > 0.5,
                "confidence_score": ai_score,
                "request_id": result.get("request", {}).get("id")
            }
        
        raise HTTPException(status_code=400, detail=f"API Error: {result}")

    except Exception as e:
        print(f"error details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "online"}