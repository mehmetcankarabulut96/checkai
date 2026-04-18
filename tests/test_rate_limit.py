import asyncio, httpx, time, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_IMAGE_PATH = os.path.join(BASE_DIR, "test_photo.jpg")

API_KEY = "sk_live_0W-4SQQ-3RmkjS3tBk2kYlxqID6_AEn0mHtP2IgnDM4"
URL = "http://localhost:8000/v1/analyze"

async def send_request(client, req_id):
    headers = {"X-API-KEY": API_KEY}
    
    # open file with every request
    try:
        with open(TEST_IMAGE_PATH, "rb") as f:
            files = {"file": ("test_photo.jpg", f, "image/jpeg")}
            
            # exponential backoff (yeniden deneme) mantığı eklenebilir
            response = await client.post(URL, headers=headers, files=files)
            
            if response.status_code == 200:
                print(f"✅ [{req_id}] success: {response.json()['request_id']}")
            elif response.status_code == 429:
                print(f"⚠️ [{req_id}] Rate Limit: {response.json()['detail']}")
            else:
                print(f"❌ [{req_id}] error {response.status_code}: {response.text[:50]}")
    except Exception as e:
        print(f"🔥 [{req_id}] connection error: {e}")

async def main():
    # concurrent request count
    request_count = 5
    
    print(f"{request_count} requests sending concurrently...")
    start_time = time.time()
    
    async with httpx.AsyncClient(timeout=10.0, http2=False) as client:
        # create tasks: every request will send at the same time
        tasks = []
        for i in range(1, request_count + 1):
            tasks.append(asyncio.create_task(send_request(client, i)))
        
        # push requests at the same time
        await asyncio.gather(*tasks)
        
    print(f"Task completed. Elapsed time {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    asyncio.run(main())