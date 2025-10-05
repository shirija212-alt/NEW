# INSAFE - Indian Scam Awareness & Fraud Elimination Platform

## Overview

INSAFE is a comprehensive cybersecurity platform designed to protect Indian users from online scams, fraud attempts, and cyber threats. The platform provides multi-channel threat detection including URL scanning, SMS analysis, phone number verification, QR code scanning, APK analysis, and call transcript analysis. It combines heuristic pattern matching with machine learning models to provide real-time scam detection with high accuracy.

The system features real-time threat intelligence from official Indian government sources, AI-powered pattern learning, smart report verification with automatic submission to authorities, and mobile-ready APIs for native Android/iOS applications.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript for type safety and developer experience
- **Styling**: Tailwind CSS with shadcn/ui component library for consistent, accessible UI
- **Routing**: Wouter for lightweight client-side routing
- **State Management**: TanStack Query (React Query) for server state management and caching
- **Build Tool**: Vite for fast development and optimized production builds

### Backend Architecture
- **Primary Server**: Node.js with Express.js and TypeScript
- **API Design**: RESTful endpoints for scan operations, reporting, analytics, and threat intelligence
- **Hybrid Detection System**: Combines multiple approaches:
  - FastAPI microservice (`/app`) with Python-based ML models for advanced scam detection
  - Heuristic pattern matching using weighted risk factors
  - Machine learning predictions using scikit-learn (Logistic Regression)
  - Real-time blacklist lookups against stored threat data
- **Session Management**: Cookie-based sessions with PostgreSQL session store
- **Middleware**: CORS enabled, JSON body parsing, request/response logging

### Data Storage Solutions
- **Primary Database**: PostgreSQL (Neon serverless) accessed via Drizzle ORM
- **Schema Design**:
  - `users`: Authentication and user management
  - `scans`: Scan history with type, content, verdict, confidence scores, and risk factors
  - `reports`: User-submitted scam reports with verification status
  - `scam_patterns`: Pattern library for detection with categories and weights
  - `blacklist`: Known scam numbers/URLs/entities (Python service)
  - `training_data`: ML model training dataset (Python service)
- **ORM**: Drizzle ORM with TypeScript-first schema definitions and type inference
- **Connection Pooling**: Neon serverless with WebSocket support for efficient connections

### Machine Learning Components
- **Python ML Service** (`/app`):
  - Hybrid classifier combining heuristics and ML
  - Feature extraction for phone numbers (length, patterns, blacklist status, etc.)
  - Logistic Regression model trained on synthetic + real data
  - Model persistence using joblib (< 1MB model file)
  - Multiple detection modes: heuristic-only, ML-only, balanced, and hybrid
- **Training Pipeline**: Automatic synthetic data generation, feature engineering, model training
- **Pattern Learning**: AI-powered continuous learning from scan results and reports

### Authentication & Authorization
- Session-based authentication using express-session
- PostgreSQL session store (connect-pg-simple) for persistence
- User credentials stored with hashed passwords
- IP address tracking for security auditing

### AI & Intelligence Services
- **AI Pattern Learning Service**: Continuously learns from scan data to improve detection
- **Threat Intelligence Service**: Real-time updates from official Indian data sources:
  - India Cyber Crime Portal
  - Telecom Operator Blacklists
  - RBI Fraud Database
  - Community-sourced reports
- **Smart Report System**: AI-powered verification with automatic submission to authorities when confidence thresholds are met

### API Structure
**Scan Endpoints**:
- `POST /api/scan/url` - URL safety analysis
- `POST /api/scan/sms` - SMS scam detection
- `POST /api/scan/qr` - QR code content analysis
- `POST /api/scan/apk` - Android app analysis
- `POST /api/scan/call` - Call transcript analysis
- `POST /api/scan/phone` - Phone number verification

**Analytics & Intelligence**:
- `GET /api/stats` - Platform statistics (total scans, accuracy, blocked threats)
- `GET /api/scans/recent` - Recent scan history
- `GET /api/threat-intelligence/status` - Real-time threat feed status
- `GET /api/ai-learning/status` - AI learning system status

**Reporting**:
- `POST /api/report` - Submit scam reports with AI verification
- `GET /api/reports` - Retrieve verified reports

**Python ML Service** (FastAPI):
- `POST /analyze/phone` - Hybrid phone number analysis
- `POST /analyze/url` - URL analysis with ML
- `POST /analyze/sms` - SMS analysis with ML
- `POST /analyze/file` - File analysis with ML
- `GET /health` - Service health check

## External Dependencies

### Third-Party Services
- **Neon Database**: PostgreSQL serverless database hosting
- **Indian Cyber Crime Portal API**: Official government fraud reporting integration (requires `CYBER_CRIME_PORTAL_API_KEY`)
- **OpenAI API**: Optional enhanced AI features (requires `OPENAI_API_KEY`)
- **Telecom Operator APIs**: Real-time phone number verification (TRAI integration)
- **RBI Fraud Database**: Financial fraud intelligence

### NPM Packages
- **Core Framework**: React, Express, TypeScript, Vite
- **Database**: Drizzle ORM, @neondatabase/serverless, pg
- **UI Components**: Radix UI primitives, Tailwind CSS, shadcn/ui
- **State Management**: @tanstack/react-query
- **Validation**: Zod, drizzle-zod
- **HTTP Client**: Axios
- **Utilities**: date-fns, nanoid, clsx, class-variance-authority

### Python Dependencies (ML Service)
- **ML Framework**: scikit-learn, joblib, numpy
- **API Framework**: FastAPI, uvicorn
- **Phone Number Processing**: phonenumbers
- **Validation**: validators, pydantic
- **Database**: psycopg2 (PostgreSQL driver)

### Development Tools
- **TypeScript**: Type checking and compilation
- **ESBuild**: Production build bundling
- **Drizzle Kit**: Database migrations and schema management
- **cross-env**: Environment variable management across platforms

### Environment Configuration
Required environment variables:
- `DATABASE_URL`: PostgreSQL connection string (Neon)
- `NODE_ENV`: Environment mode (development/production)
- `CYBER_CRIME_PORTAL_API_KEY`: Optional government API integration
- `OPENAI_API_KEY`: Optional AI enhancement features
- `ML_SERVICE_URL`: Optional external ML service endpoint