import os
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from typing import List, Dict, Any, Optional
import json

DATABASE_URL = os.getenv('DATABASE_URL')

if not DATABASE_URL:
    raise EnvironmentError(
        "DATABASE_URL environment variable not set. "
        "Please configure it in Replit Secrets or .env file. "
        "Example: postgresql://user:password@host:port/database"
    )

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def init_db():
    """Initialize database tables"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Create blacklist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id SERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                trust_score REAL DEFAULT 0.8,
                UNIQUE(type, value)
            )
        """)
        
        # Create training_data table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS training_data (
                id SERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                input_raw TEXT NOT NULL,
                label TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                features JSONB,
                is_synthetic BOOLEAN DEFAULT FALSE
            )
        """)
        
        cursor.close()
        
def add_to_blacklist(item_type: str, value: str, trust_score: float = 0.8):
    """Add item to blacklist"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blacklist (type, value, trust_score)
            VALUES (%s, %s, %s)
            ON CONFLICT (type, value) DO UPDATE SET trust_score = EXCLUDED.trust_score
        """, (item_type, value, trust_score))
        cursor.close()

def check_blacklist(item_type: str, value: str) -> Optional[Dict[str, Any]]:
    """Check if value exists in blacklist"""
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT * FROM blacklist WHERE type = %s AND value = %s
        """, (item_type, value))
        result = cursor.fetchone()
        cursor.close()
        return dict(result) if result else None

def get_training_data(item_type: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
    """Get training data from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        if item_type:
            cursor.execute("""
                SELECT * FROM training_data WHERE type = %s ORDER BY created_at DESC LIMIT %s
            """, (item_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM training_data ORDER BY created_at DESC LIMIT %s
            """, (limit,))
        results = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in results]

def add_training_data(item_type: str, input_raw: str, label: str, features: Dict[str, Any], is_synthetic: bool = False):
    """Add training example to database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO training_data (type, input_raw, label, features, is_synthetic)
            VALUES (%s, %s, %s, %s, %s)
        """, (item_type, input_raw, label, json.dumps(features), is_synthetic))
        cursor.close()

def seed_blacklist():
    """Seed database with known scam patterns"""
    scam_phones = [
        ('+1-900-555-0199', 0.9),
        ('+91-9000000000', 0.85),
        ('1900555', 0.9),
        ('+1-888-SCAM-NOW', 0.95),
    ]
    
    scam_urls = [
        ('http://phishing-site.com', 0.95),
        ('https://fake-bank-login.ru', 0.98),
        ('bit.ly/scam123', 0.7),
    ]
    
    for phone, trust in scam_phones:
        add_to_blacklist('phone', phone, trust)
    
    for url, trust in scam_urls:
        add_to_blacklist('url', url, trust)
