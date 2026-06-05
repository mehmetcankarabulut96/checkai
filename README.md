# Cludek Backend - Visual Intelligence API

This repository contains the backend for cludek.com. Cludek provides a high-performance, developer-first API designed to detect synthetic media, face-swap deepfakes, and complex semantic or logical anomalies in facial imagery. By combining traditional technical image forensics with state-of-the-art Visual Language Modeling (VLM), Cludek delivers a comprehensive multi-layered authenticity assessment. This allows platforms to secure their identity verification (KYC), trust & safety workflows, and user content pipelines against advanced AI generation and digital spoofing in real-time. 

It is built with **FastAPI**, **Supabase**, and **Lemon Squeezy**. 
The API handles secure image uploads and runs them through a pipeline using **MediaPipe** (Computer Vision Library), **Sightengine** (Moderation API) and **gpt-4o-mini** (OpenAI API) to detect and moderate content. 

API documentation can be found at **cludek.com/docs**.

Swagger documentation can be found at **api.cludek.com/docs**.

---

## 🏗️ Key Features

### 1. Standard API Responses
Every endpoint returns a consistent JSON structure. This makes frontend integration much easier because you always know what format to expect, whether it's a success or an error.

**Success Response:**
```json
{
  "request_id": "9a3f8b1c-7e4d-4c8a-921b-6f3c5a7e1f9b",
  "status": "success",
  "processing_time_ms": 142,
  "data": { "system_status": "operational" },
  "meta": { "timestamp": "2026-06-05T05:46:21Z" }
}
```

**Error Response:**
```json
{
  "request_id": "3c5a7e1f-9b9a-3f8b-1c7e-4d4c8a921b6f",
  "status": "error",
  "processing_time_ms": 18,
  "error": {
    "code": "PROFILE_DATA_FAULT",
    "message": "The user profile session data is corrupted.",
    "recommendation": "Please re-authenticate.",
    "details": null
  }
}
```
### 2. Secure Webhooks (Saga Pattern)
The app integrates with Lemon Squeezy for payments. Webhooks are verified using HMAC-SHA256 signatures. If a user buys credits but the Supabase database update fails, the system rolls back the transaction to prevent broken states.

### 3. Rate Limiting & Performance Tracking
* **Tracing:** Every request gets a unique `request_id` passed through the app using Python's `contextvars` for easy debugging.
* **Rate Limits:** Includes a custom in-memory rate limiter to stop spam. It's designed so it can be easily upgraded to Redis later.

### 4. Strict File Security
Before any AI processing happens, uploaded files are strictly checked:
* Minimum 10KB size limit (to block empty or garbage files).
* Maximum 5MB limit (to prevent server crashes).
* Strict MIME type and magic byte checks.

---

## 🛠️ Tech Stack

* **Backend:** FastAPI, Python, Uvicorn
* **Database & Auth:** Supabase (PostgreSQL)
* **AI & Vision:** MediaPipe, OpenAI GPT-4V, Sightengine
* **Payments:** Lemon Squeezy

---

## ⚙️ How the Pipeline Works

When a user uploads an image, the backend does the following:

1. **Validation:** Checks file size and format.
2. **Pre-Check Layer (MediaPipe):** Analyzes basic image structure. Fails immediately if no human face is found.
3. **Pixel-Level Analysis (Sightengine):** Scans the image to detect AI-generated content and deepfakes using `genai` and `deepfake` models.
4. **Semantic Analysis Layer (OpenAI):** Sends the image to `gpt-4o-mini` for deeper contextual understanding and moderation if needed.
5. **Database:** Updates the user's credit balance and saves the results in Supabase.
6. **Response:** Returns the analysis result in the standard JSON format.
