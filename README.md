# INSAFE - Indian Scam Awareness & Fraud Elimination Platform

A comprehensive cybersecurity platform designed to protect Indian users from online scams and fraud attempts.

## Features

### Core Protection
- **Multi-Scanner Engine**: Scan URLs, SMS messages, QR codes, APK files, and call transcripts
- **Real-Time Threat Intelligence**: Live updates from official data sources
- **AI Pattern Learning**: Continuously improving fraud detection algorithms
- **Smart Report Verification**: Automatic submission to Indian Cyber Crime Portal

### Advanced Capabilities
- **Phone Number Verification**: Real-time lookup against fraud databases
- **Mobile App APIs**: Ready endpoints for Android/iOS development
- **Emergency Reporting**: Direct integration with authorities
- **Community Protection**: Crowd-sourced threat intelligence

## Technology Stack

- **Backend**: Node.js, Express.js, TypeScript
- **Frontend**: React, TypeScript, Tailwind CSS
- **Database**: PostgreSQL with Drizzle ORM
- **AI/ML**: Pattern recognition and threat analysis
- **Real-time**: WebSocket connections for live updates

## Getting Started

### Prerequisites
- Node.js 20+
- PostgreSQL database
- npm or yarn

### Installation
1. Clone the repository
2. Install dependencies: `npm install`
3. Set up environment variables
4. Run database migrations: `npm run db:push`
5. Start development server: `npm run dev`

### Environment Variables
```
DATABASE_URL=your_postgresql_connection_string
NODE_ENV=development
CYBER_CRIME_PORTAL_API_KEY=optional
OPENAI_API_KEY=optional
```

## Deployment

### Render (Recommended)
See [DEPLOY_TO_RENDER.md](./DEPLOY_TO_RENDER.md) for detailed deployment instructions.

### Other Platforms
The application is compatible with:
- Railway
- Heroku
- DigitalOcean App Platform
- AWS/GCP/Azure

## API Endpoints

### Scanning APIs
- `POST /api/scan/url` - URL threat scanning
- `POST /api/scan/sms` - SMS message analysis
- `POST /api/scan/qr` - QR code verification
- `POST /api/scan/apk` - APK file analysis
- `POST /api/scan/call` - Call transcript analysis

### Mobile APIs
- `POST /api/mobile/call-screen` - Real-time call screening
- `POST /api/mobile/sms-filter` - SMS filtering
- `GET /api/mobile/sync/:timestamp` - Threat database sync

### Reporting
- `POST /api/report` - Submit threat reports with AI verification

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License

## Security

For security vulnerabilities, please contact the development team directly.

## Support

For technical support and questions about the INSAFE platform, please refer to the documentation or contact the development team.

---

## Hybrid Scam Detection API (FastAPI Backend)

### New Backend System

A hybrid scam detection system combining heuristic rules, blacklist lookups, and machine learning for accurate classification of potentially fraudulent phone numbers, URLs, SMS messages, and files.

#### FastAPI Endpoints

**Health Check:**
```bash
GET http://localhost:8000/health
```

**Analyze Phone:**
```bash
POST http://localhost:8000/analyze/phone
Content-Type: application/json

{"phone": "+1-900-555-0199", "mode": "balanced"}
```

**Response Format:**
```json
{
  "label": "scam",
  "confidence": 0.89,
  "explain": ["Found in blacklist", "Premium rate number", "ML model prediction: 0.78"],
  "used_methods": ["heuristic", "ml", "lookup"]
}
```

#### Detection Modes
- `heuristic`: Rule-based only
- `ml`: Machine learning only  
- `balanced`: 50/50 fusion (default)
- `hybrid`: Trust-weighted fusion

#### Labels
- `scam`: Confidence ≥ 0.8
- `likely_scam`: Confidence ≥ 0.6
- `suspicious`: Confidence ≥ 0.4
- `benign`: Confidence < 0.4

#### Important Notes
- **ML Model Scope**: Currently, the ML model only applies to phone number analysis. URL, SMS, and file analyzers use heuristic-only detection.
- **Database**: Requires DATABASE_URL environment variable (configured in Replit Secrets).
- **Model Size**: Logistic regression model < 1 MB (optimized for free tier).

#### Quick Start
```bash
# Train model (one-time)
python -m app.train

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Run tests
python -m pytest tests/test_phone_analyzer.py -v
```

#### Example Test
```bash
curl -X POST http://localhost:8000/analyze/phone \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1-900-555-0199", "mode": "balanced"}'
``` 
