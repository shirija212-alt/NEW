#!/bin/bash

# Test script for scam detection API
# Make sure the FastAPI server is running on port 8000

echo "=== Scam Detection API Manual Tests ==="
echo ""

# Health check
echo "1. Health Check"
curl -s http://localhost:8000/health | python3 -m json.tool
echo ""

# Test scam phone number
echo "2. Test Scam Phone (Premium 900 number)"
curl -s -X POST http://localhost:8000/analyze/phone \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1-900-555-0199", "mode": "balanced"}' | python3 -m json.tool
echo ""

# Test benign phone
echo "3. Test Benign Phone"
curl -s -X POST http://localhost:8000/analyze/phone \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1-415-555-1234", "mode": "balanced"}' | python3 -m json.tool
echo ""

# Test scam URL
echo "4. Test Scam URL"
curl -s -X POST http://localhost:8000/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://phishing-site.com", "mode": "balanced"}' | python3 -m json.tool
echo ""

# Test benign URL
echo "5. Test Benign URL"
curl -s -X POST http://localhost:8000/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com", "mode": "balanced"}' | python3 -m json.tool
echo ""

# Test scam SMS
echo "6. Test Scam SMS"
curl -s -X POST http://localhost:8000/analyze/sms \
  -H "Content-Type: application/json" \
  -d '{"sms": "URGENT! You have won a prize of 1 lakh rupees! Click http://scam.com to claim now!", "mode": "balanced"}' | python3 -m json.tool
echo ""

# Test benign SMS
echo "7. Test Benign SMS"
curl -s -X POST http://localhost:8000/analyze/sms \
  -H "Content-Type: application/json" \
  -d '{"sms": "Your package will be delivered tomorrow between 2-4 PM.", "mode": "balanced"}' | python3 -m json.tool
echo ""

echo "=== Tests Complete ==="
