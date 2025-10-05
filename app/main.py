from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.models import AnalyzeRequest, AnalyzeResponse, HealthResponse
from app.analyzers import ScamAnalyzer
from app.db import init_db, seed_blacklist, check_blacklist
from app.train import train_model
import os

app = FastAPI(
    title="Scam Detection API",
    description="Hybrid scam detection system with heuristics and ML",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analyzer
analyzer = None

@app.on_event("startup")
async def startup_event():
    """Initialize database and model on startup"""
    global analyzer
    
    print("Initializing database...")
    init_db()
    seed_blacklist()
    
    # Check if model exists, if not train one
    if not os.path.exists("app/scam_model.pkl"):
        print("Model not found, training...")
        train_model()
    
    print("Loading analyzer...")
    analyzer = ScamAnalyzer()
    print("Startup complete!")

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    global analyzer
    return {
        "status": "healthy",
        "database": "connected",
        "model_loaded": analyzer is not None and analyzer.model is not None
    }

@app.post("/analyze/phone", response_model=AnalyzeResponse)
async def analyze_phone(request: AnalyzeRequest):
    """Analyze phone number for scam indicators"""
    if not request.phone:
        raise HTTPException(status_code=400, detail="Phone number is required")
    
    if analyzer is None:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    result = analyzer.analyze("phone", request.phone, request.mode)
    return result

@app.post("/analyze/url", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    """Analyze URL for scam indicators"""
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    if analyzer is None:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    result = analyzer.analyze("url", request.url, request.mode)
    return result

@app.post("/analyze/sms", response_model=AnalyzeResponse)
async def analyze_sms(request: AnalyzeRequest):
    """Analyze SMS text for scam indicators"""
    if not request.sms:
        raise HTTPException(status_code=400, detail="SMS text is required")
    
    if analyzer is None:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    result = analyzer.analyze("sms", request.sms, request.mode)
    return result

@app.post("/analyze/file", response_model=AnalyzeResponse)
async def analyze_file(request: AnalyzeRequest):
    """Analyze file hash/name for scam indicators"""
    if not request.file:
        raise HTTPException(status_code=400, detail="File hash or name is required")
    
    if analyzer is None:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    result = analyzer.analyze("file", request.file, request.mode)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
