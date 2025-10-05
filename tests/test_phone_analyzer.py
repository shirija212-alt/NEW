import pytest
from app.analyzers import ScamAnalyzer
from app.db import init_db, seed_blacklist

@pytest.fixture(scope="module")
def analyzer():
    """Create analyzer instance for testing"""
    init_db()
    seed_blacklist()
    return ScamAnalyzer()

def test_scam_premium_number(analyzer):
    """Test detection of premium rate scam number"""
    result = analyzer.analyze("phone", "+1-900-555-0199", "balanced")
    assert result["label"] in ["scam", "likely_scam"]
    assert result["confidence"] > 0.6
    assert len(result["explain"]) > 0
    assert "heuristic" in result["used_methods"]

def test_repeated_digits_scam(analyzer):
    """Test detection of phone with repeated digits pattern"""
    result = analyzer.analyze("phone", "9999999999", "balanced")
    assert result["label"] in ["scam", "likely_scam", "suspicious"]
    assert "pattern" in " ".join(result["explain"]).lower()

def test_indian_scam_number(analyzer):
    """Test detection of Indian premium number"""
    result = analyzer.analyze("phone", "+91-9000000000", "balanced")
    assert result["confidence"] > 0.5

def test_benign_us_number(analyzer):
    """Test benign US phone number"""
    result = analyzer.analyze("phone", "+1-415-555-1234", "balanced")
    assert result["label"] in ["benign", "suspicious"]
    assert result["confidence"] < 0.7

def test_benign_uk_number(analyzer):
    """Test benign UK phone number"""
    result = analyzer.analyze("phone", "+44-20-7946-0958", "balanced")
    assert result["label"] in ["benign", "suspicious"]
    assert result["confidence"] < 0.7

def test_benign_indian_number(analyzer):
    """Test benign Indian mobile number"""
    result = analyzer.analyze("phone", "+91-9876543210", "balanced")
    assert result["label"] in ["benign", "suspicious"]

def test_invalid_phone_format(analyzer):
    """Test invalid phone number format"""
    result = analyzer.analyze("phone", "notaphone", "balanced")
    assert "used_methods" in result

def test_shortcode_phone(analyzer):
    """Test short code phone number"""
    result = analyzer.analyze("phone", "555-1234", "balanced")
    assert "used_methods" in result

def test_blacklisted_phone(analyzer):
    """Test phone in blacklist"""
    result = analyzer.analyze("phone", "+1-900-555-0199", "heuristic")
    assert "blacklist" in " ".join(result["explain"]).lower()
    assert "lookup" in result["used_methods"]

def test_mode_heuristic_only(analyzer):
    """Test heuristic-only mode"""
    result = analyzer.analyze("phone", "+1-900-555-0199", "heuristic")
    assert "heuristic" in result["used_methods"]
    assert result["confidence"] > 0

def test_mode_balanced(analyzer):
    """Test balanced mode (default)"""
    result = analyzer.analyze("phone", "+1-900-555-0199", "balanced")
    assert result["label"] is not None
    assert 0.0 <= result["confidence"] <= 1.0

def test_response_structure(analyzer):
    """Test that response has all required fields"""
    result = analyzer.analyze("phone", "+1-415-555-1234", "balanced")
    assert "label" in result
    assert "confidence" in result
    assert "explain" in result
    assert "used_methods" in result
    assert isinstance(result["explain"], list)
    assert isinstance(result["used_methods"], list)
    assert result["label"] in ["scam", "likely_scam", "suspicious", "benign"]

def test_confidence_range(analyzer):
    """Test that confidence is always between 0 and 1"""
    test_numbers = [
        "+1-900-555-0199",
        "+1-415-555-1234",
        "9999999999",
        "+91-9876543210"
    ]
    for number in test_numbers:
        result = analyzer.analyze("phone", number, "balanced")
        assert 0.0 <= result["confidence"] <= 1.0
