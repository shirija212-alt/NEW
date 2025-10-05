import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from typing import List, Dict, Any
from app.db import get_training_data, add_training_data, init_db, seed_blacklist

MODEL_PATH = "app/scam_model.pkl"

def synthesize_training_data():
    """Create synthetic training examples"""
    print("Synthesizing training data...")
    
    # Scam phone examples
    scam_phones = [
        ("+1-900-555-0199", "scam", {"length": 15, "is_premium": True, "in_blacklist": True}),
        ("+91-9000000000", "scam", {"length": 13, "has_suspicious_pattern": True, "repeated_digits": 10}),
        ("1900555", "scam", {"length": 7, "is_premium": True, "is_shortcode": False}),
        ("+1-888-SCAM-NOW", "likely_scam", {"length": 14, "in_blacklist": True}),
        ("9999999999", "scam", {"length": 10, "has_suspicious_pattern": True, "repeated_digits": 10}),
        ("+1-900-123-4567", "likely_scam", {"length": 15, "is_premium": True}),
    ]
    
    # Benign phone examples
    benign_phones = [
        ("+1-415-555-1234", "benign", {"length": 15, "is_valid": True, "is_premium": False}),
        ("+91-9876543210", "benign", {"length": 13, "is_valid": True, "is_premium": False}),
        ("+44-20-7946-0958", "benign", {"length": 16, "is_valid": True, "is_premium": False}),
        ("555-1234", "benign", {"length": 8, "is_shortcode": True}),
    ]
    
    # Add to database
    for phone, label, features in scam_phones + benign_phones:
        try:
            add_training_data("phone", phone, label, features, is_synthetic=True)
        except:
            pass  # May already exist
    
    print(f"Added {len(scam_phones) + len(benign_phones)} synthetic training examples")

def prepare_features_and_labels(data: List[Dict[str, Any]]) -> tuple:
    """Convert training data to feature vectors and labels"""
    X = []
    y = []
    
    for item in data:
        features = item.get('features', {})
        if isinstance(features, str):
            import json
            features = json.loads(features)
        
        # Convert features to vector (must match _features_to_vector in analyzers.py)
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
        
        X.append(vector)
        
        # Convert label to binary (0 = benign/suspicious, 1 = scam/likely_scam)
        label = item.get('label', 'benign')
        y.append(1 if label in ['scam', 'likely_scam'] else 0)
    
    return np.array(X), np.array(y)

def train_model():
    """Train logistic regression model"""
    print("Training scam detection model...")
    
    # Initialize database and seed data
    init_db()
    seed_blacklist()
    
    # Get training data
    data = get_training_data()
    
    # If insufficient data, synthesize some
    if len(data) < 10:
        print(f"Only {len(data)} training examples found, synthesizing more...")
        synthesize_training_data()
        data = get_training_data()
    
    print(f"Training on {len(data)} examples...")
    
    # Prepare features and labels
    X, y = prepare_features_and_labels(data)
    
    if len(X) < 4:
        print("Insufficient training data even after synthesis!")
        return None
    
    # Train simple logistic regression (small model, fast)
    model = LogisticRegression(
        random_state=42,
        max_iter=1000,
        solver='lbfgs',
        C=1.0
    )
    
    # If enough data, do train/test split
    if len(X) >= 10:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        model.fit(X_train, y_train)
        score = model.score(X_test, y_test)
        print(f"Model accuracy on test set: {score:.2%}")
    else:
        model.fit(X, y)
        print("Trained on all data (small dataset)")
    
    # Save model
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    
    # Print model size
    import os
    model_size = os.path.getsize(MODEL_PATH) / 1024  # KB
    print(f"Model size: {model_size:.2f} KB")
    
    return model

if __name__ == "__main__":
    train_model()
