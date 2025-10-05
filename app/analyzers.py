import re
import os
import joblib
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
import phonenumbers
from phonenumbers import geocoder, carrier
import validators
from app.db import check_blacklist, get_training_data

MODEL_PATH = "app/scam_model.pkl"

class ScamAnalyzer:
    def __init__(self):
        self.model = self._load_model()
        
    def _load_model(self):
        """Load or create ML model"""
        if os.path.exists(MODEL_PATH):
            try:
                return joblib.load(MODEL_PATH)
            except:
                return None
        return None
    
    def analyze(self, input_type: str, input_value: str, mode: str = "balanced") -> Dict[str, Any]:
        """Main analysis function"""
        if input_type == "phone":
            return self._analyze_phone(input_value, mode)
        elif input_type == "url":
            return self._analyze_url(input_value, mode)
        elif input_type == "sms":
            return self._analyze_sms(input_value, mode)
        elif input_type == "file":
            return self._analyze_file(input_value, mode)
        else:
            raise ValueError(f"Unknown input type: {input_type}")
    
    def _analyze_phone(self, phone: str, mode: str) -> Dict[str, Any]:
        """Analyze phone number for scam indicators"""
        features = self._extract_phone_features(phone)
        heuristic_score, heuristic_reasons = self._phone_heuristics(phone, features)
        
        ml_score = 0.5
        ml_reasons = []
        used_methods = ["heuristic"]
        
        if self.model is not None and mode in ["ml", "balanced", "hybrid"]:
            ml_score = self._ml_predict(features)
            ml_reasons.append(f"ML model prediction: {ml_score:.2f}")
            used_methods.append("ml")
        
        if features.get('in_blacklist'):
            used_methods.append("lookup")
        
        final_score = self._fuse_scores(heuristic_score, ml_score, mode, features)
        
        label = self._score_to_label(final_score)
        
        all_reasons = heuristic_reasons + ml_reasons
        
        return {
            "label": label,
            "confidence": round(final_score, 2),
            "explain": all_reasons,
            "used_methods": used_methods
        }
    
    def _analyze_url(self, url: str, mode: str) -> Dict[str, Any]:
        """Analyze URL for scam indicators"""
        features = self._extract_url_features(url)
        heuristic_score, heuristic_reasons = self._url_heuristics(url, features)
        
        ml_score = 0.5
        used_methods = ["heuristic"]
        
        if features.get('in_blacklist'):
            used_methods.append("lookup")
        
        final_score = self._fuse_scores(heuristic_score, ml_score, mode, features)
        label = self._score_to_label(final_score)
        
        return {
            "label": label,
            "confidence": round(final_score, 2),
            "explain": heuristic_reasons,
            "used_methods": used_methods
        }
    
    def _analyze_sms(self, sms: str, mode: str) -> Dict[str, Any]:
        """Analyze SMS text for scam indicators"""
        features = self._extract_sms_features(sms)
        heuristic_score, heuristic_reasons = self._sms_heuristics(sms, features)
        
        ml_score = 0.5
        final_score = self._fuse_scores(heuristic_score, ml_score, mode, features)
        label = self._score_to_label(final_score)
        
        return {
            "label": label,
            "confidence": round(final_score, 2),
            "explain": heuristic_reasons,
            "used_methods": ["heuristic"]
        }
    
    def _analyze_file(self, file_hash: str, mode: str) -> Dict[str, Any]:
        """Analyze file hash for scam indicators"""
        features = self._extract_file_features(file_hash)
        heuristic_score, heuristic_reasons = self._file_heuristics(file_hash, features)
        
        ml_score = 0.5
        used_methods = ["heuristic"]
        
        if features.get('in_blacklist'):
            used_methods.append("lookup")
        
        final_score = self._fuse_scores(heuristic_score, ml_score, mode, features)
        label = self._score_to_label(final_score)
        
        return {
            "label": label,
            "confidence": round(final_score, 2),
            "explain": heuristic_reasons,
            "used_methods": used_methods
        }
    
    def _extract_phone_features(self, phone: str) -> Dict[str, Any]:
        """Extract features from phone number"""
        features = {
            'raw': phone,
            'length': len(re.sub(r'[^0-9]', '', phone)),
            'has_country_code': phone.startswith('+'),
            'in_blacklist': False,
            'blacklist_trust': 0.0,
            'is_premium': False,
            'is_shortcode': False,
            'has_suspicious_pattern': False,
            'country_code': '',
            'area_code': '',
            'repeated_digits': 0
        }
        
        # Check blacklist
        bl_result = check_blacklist('phone', phone)
        if bl_result:
            features['in_blacklist'] = True
            features['blacklist_trust'] = bl_result.get('trust_score', 0.8)
        
        # Parse phone number
        try:
            parsed = phonenumbers.parse(phone, None)
            features['country_code'] = str(parsed.country_code)
            features['is_valid'] = phonenumbers.is_valid_number(parsed)
        except:
            features['is_valid'] = False
        
        # Check for premium numbers (900, 1900 prefixes)
        clean_phone = re.sub(r'[^0-9]', '', phone)
        if clean_phone.startswith('900') or clean_phone.startswith('1900'):
            features['is_premium'] = True
        
        # Check for shortcode (very short numbers)
        if 3 <= features['length'] <= 6:
            features['is_shortcode'] = True
        
        # Pattern analysis - repeated digits
        for digit in '0123456789':
            count = clean_phone.count(digit)
            if count > features['length'] / 2:
                features['repeated_digits'] = count
                features['has_suspicious_pattern'] = True
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extract features from URL"""
        features = {
            'raw': url,
            'length': len(url),
            'in_blacklist': False,
            'blacklist_trust': 0.0,
            'is_valid': validators.url(url) or False,
            'has_ip_address': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
            'has_suspicious_tld': False,
            'is_https': url.startswith('https://'),
            'subdomain_count': 0,
            'has_shortener': False
        }
        
        # Check blacklist
        bl_result = check_blacklist('url', url)
        if bl_result:
            features['in_blacklist'] = True
            features['blacklist_trust'] = bl_result.get('trust_score', 0.8)
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga']
        for tld in suspicious_tlds:
            if url.endswith(tld):
                features['has_suspicious_tld'] = True
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co']
        for shortener in shorteners:
            if shortener in url:
                features['has_shortener'] = True
        
        # Count subdomains
        if '://' in url:
            domain_part = url.split('://')[1].split('/')[0]
            features['subdomain_count'] = domain_part.count('.')
        
        return features
    
    def _extract_sms_features(self, sms: str) -> Dict[str, Any]:
        """Extract features from SMS text"""
        features = {
            'raw': sms,
            'length': len(sms),
            'has_url': bool(re.search(r'http[s]?://|www\.', sms)),
            'has_phone': bool(re.search(r'\+?\d{10,}', sms)),
            'urgency_words': 0,
            'money_words': 0,
            'has_suspicious_keywords': False
        }
        
        sms_lower = sms.lower()
        
        # Urgency indicators
        urgency_keywords = ['urgent', 'immediately', 'now', 'hurry', 'limited time', 'expire', 'act now']
        features['urgency_words'] = sum(1 for kw in urgency_keywords if kw in sms_lower)
        
        # Money/financial keywords
        money_keywords = ['loan', 'credit', 'money', 'cash', 'prize', 'won', 'winner', 'claim', 'reward']
        features['money_words'] = sum(1 for kw in money_keywords if kw in sms_lower)
        
        # Suspicious keywords specific to Indian scams
        suspicious = ['rummy', 'betting', 'casino', 'lottery', 'verify account', 'suspended', 'confirm']
        features['has_suspicious_keywords'] = any(kw in sms_lower for kw in suspicious)
        
        return features
    
    def _extract_file_features(self, file_hash: str) -> Dict[str, Any]:
        """Extract features from file hash/name"""
        features = {
            'raw': file_hash,
            'length': len(file_hash),
            'in_blacklist': False,
            'blacklist_trust': 0.0,
            'is_apk': file_hash.lower().endswith('.apk'),
            'is_executable': file_hash.lower().endswith(('.exe', '.apk', '.dex'))
        }
        
        # Check blacklist
        bl_result = check_blacklist('file', file_hash)
        if bl_result:
            features['in_blacklist'] = True
            features['blacklist_trust'] = bl_result.get('trust_score', 0.8)
        
        return features
    
    def _phone_heuristics(self, phone: str, features: Dict) -> Tuple[float, List[str]]:
        """Apply heuristic rules to phone number"""
        score = 0.5  # neutral starting point
        reasons = []
        
        if features['in_blacklist']:
            score += 0.4
            reasons.append(f"Found in blacklist (trust: {features['blacklist_trust']:.2f})")
        
        if features['is_premium']:
            score += 0.3
            reasons.append("Premium rate number (900/1900 prefix) - high scam risk")
        
        if not features['is_valid']:
            score += 0.2
            reasons.append("Invalid phone number format")
        
        if features['has_suspicious_pattern']:
            score += 0.15
            reasons.append(f"Suspicious pattern detected ({features['repeated_digits']} repeated digits)")
        
        if features['is_shortcode'] and not features['is_valid']:
            score += 0.1
            reasons.append("Unusual short code format")
        
        # Cap score at 1.0
        score = min(1.0, max(0.0, score))
        
        if score < 0.3:
            reasons.append("No major red flags detected")
        
        return score, reasons
    
    def _url_heuristics(self, url: str, features: Dict) -> Tuple[float, List[str]]:
        """Apply heuristic rules to URL"""
        score = 0.5
        reasons = []
        
        if features['in_blacklist']:
            score += 0.4
            reasons.append(f"Found in blacklist (trust: {features['blacklist_trust']:.2f})")
        
        if features['has_ip_address']:
            score += 0.2
            reasons.append("Uses IP address instead of domain name")
        
        if features['has_suspicious_tld']:
            score += 0.2
            reasons.append("Suspicious top-level domain")
        
        if not features['is_https']:
            score += 0.1
            reasons.append("Not using secure HTTPS protocol")
        
        if features['has_shortener']:
            score += 0.15
            reasons.append("URL shortener detected - destination unclear")
        
        if features['subdomain_count'] > 3:
            score += 0.1
            reasons.append("Excessive subdomains detected")
        
        score = min(1.0, max(0.0, score))
        
        if score < 0.3:
            reasons.append("URL appears legitimate")
        
        return score, reasons
    
    def _sms_heuristics(self, sms: str, features: Dict) -> Tuple[float, List[str]]:
        """Apply heuristic rules to SMS"""
        score = 0.5
        reasons = []
        
        if features['has_suspicious_keywords']:
            score += 0.3
            reasons.append("Contains known scam keywords")
        
        if features['urgency_words'] >= 2:
            score += 0.2
            reasons.append(f"High urgency language ({features['urgency_words']} urgency words)")
        
        if features['money_words'] >= 2:
            score += 0.2
            reasons.append(f"Financial/prize language detected ({features['money_words']} money-related words)")
        
        if features['has_url'] and features['urgency_words'] > 0:
            score += 0.15
            reasons.append("Combination of URL and urgency tactics")
        
        score = min(1.0, max(0.0, score))
        
        if score < 0.3:
            reasons.append("Message appears legitimate")
        
        return score, reasons
    
    def _file_heuristics(self, file_hash: str, features: Dict) -> Tuple[float, List[str]]:
        """Apply heuristic rules to file"""
        score = 0.5
        reasons = []
        
        if features['in_blacklist']:
            score += 0.4
            reasons.append(f"File hash found in blacklist (trust: {features['blacklist_trust']:.2f})")
        
        if features['is_apk']:
            score += 0.1
            reasons.append("APK file - verify source before installing")
        
        if features['is_executable']:
            score += 0.1
            reasons.append("Executable file type detected")
        
        score = min(1.0, max(0.0, score))
        
        if score < 0.3:
            reasons.append("No known threats detected")
        
        return score, reasons
    
    def _ml_predict(self, features: Dict) -> float:
        """Use ML model to predict scam probability"""
        if self.model is None:
            return 0.5
        
        # Convert features to numpy array for model
        feature_vector = self._features_to_vector(features)
        
        try:
            # Get probability of scam class
            proba = self.model.predict_proba([feature_vector])[0]
            return proba[1] if len(proba) > 1 else proba[0]
        except:
            return 0.5
    
    def _features_to_vector(self, features: Dict) -> np.ndarray:
        """Convert feature dict to numpy vector for ML model"""
        # Extract numeric features in consistent order
        vector = [
            float(features.get('length', 0)),
            float(features.get('in_blacklist', False)),
            float(features.get('blacklist_trust', 0.0)),
            float(features.get('is_premium', False)),
            float(features.get('is_shortcode', False)),
            float(features.get('has_suspicious_pattern', False)),
            float(features.get('repeated_digits', 0)),
            float(features.get('has_url', False)),
            float(features.get('urgency_words', 0)),
            float(features.get('money_words', 0)),
        ]
        return np.array(vector)
    
    def _fuse_scores(self, heuristic_score: float, ml_score: float, mode: str, features: Dict) -> float:
        """Fuse heuristic and ML scores based on mode"""
        if mode == "heuristic":
            return heuristic_score
        elif mode == "ml":
            return ml_score
        elif mode == "balanced":
            return 0.5 * heuristic_score + 0.5 * ml_score
        elif mode == "hybrid":
            # Weighted by blacklist trust if available
            if features.get('in_blacklist'):
                trust = features.get('blacklist_trust', 0.8)
                return trust * heuristic_score + (1 - trust) * ml_score
            else:
                return 0.5 * heuristic_score + 0.5 * ml_score
        else:
            return 0.5 * heuristic_score + 0.5 * ml_score
    
    def _score_to_label(self, score: float) -> str:
        """Convert numeric score to label"""
        if score >= 0.8:
            return "scam"
        elif score >= 0.6:
            return "likely_scam"
        elif score >= 0.4:
            return "suspicious"
        else:
            return "benign"
