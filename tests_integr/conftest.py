# tests_integr/conftest.py
import pytest
import mysql.connector
import os
from fastapi.testclient import TestClient
from fastapi import HTTPException, status

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import app

# Configuration base de données de TEST
TEST_DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Azaz2003@abdellah",
    "database": "test_passworddb",
}

# Credentials de test (tu devras créer cet utilisateur dans ta base de test)
TEST_USER = {
    "email": "abdellahazaz5@gmail.com",
    "password": "azaz",
    "fullname": "abdellahazaziaa",
    "telephone": "0612228430"
}

# Token stocké globalement pour les tests
auth_token = None

@pytest.fixture(scope="session")
def test_database():
    """Crée la base de données de test et les tables nécessaires"""
    
    conn = mysql.connector.connect(
        host=TEST_DB_CONFIG["host"],
        user=TEST_DB_CONFIG["user"],
        password=TEST_DB_CONFIG["password"]
    )
    cursor = conn.cursor()
    
    cursor.execute(f"DROP DATABASE IF EXISTS {TEST_DB_CONFIG['database']}")
    cursor.execute(f"CREATE DATABASE {TEST_DB_CONFIG['database']}")
    cursor.close()
    conn.close()
    
    conn = mysql.connector.connect(**TEST_DB_CONFIG)
    cursor = conn.cursor()
    
    # Table mainuser
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mainuser (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE,
            fullname VARCHAR(255),
            telephone VARCHAR(50),
            is_superadmin BOOLEAN DEFAULT FALSE,
            hashed_password VARCHAR(255)
        )
    """)
    
    # Table user_settings (avec la bonne structure)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_settings (
            email VARCHAR(255) PRIMARY KEY,
            random_password_enabled BOOLEAN DEFAULT TRUE,
            encrypted_result_visible BOOLEAN DEFAULT TRUE,
            scan_history_cleanup_mode VARCHAR(50) DEFAULT 'Jamais',
            use_custom_restore_path BOOLEAN DEFAULT FALSE,
            custom_restore_path TEXT,
            is_ai_analysis_enabled BOOLEAN DEFAULT TRUE,
            is_realtime_analysis_enabled BOOLEAN DEFAULT TRUE,
            require_password_for_delete BOOLEAN DEFAULT TRUE,
            require_password_for_download BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (email) REFERENCES mainuser(email) ON DELETE CASCADE
        )
    """)
    
    conn.commit()
    cursor.close()
    conn.close()
    
    yield TEST_DB_CONFIG
    
    # Nettoyage
    conn = mysql.connector.connect(
        host=TEST_DB_CONFIG["host"],
        user=TEST_DB_CONFIG["user"],
        password=TEST_DB_CONFIG["password"]
    )
    cursor = conn.cursor()
    cursor.execute(f"DROP DATABASE IF EXISTS {TEST_DB_CONFIG['database']}")
    cursor.close()
    conn.close()


@pytest.fixture
def db_connection(test_database):
    """Fournit une connexion DB propre pour chaque test"""
    conn = mysql.connector.connect(**test_database)
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def authenticated_client(test_database):
    """Client avec authentification préalable (session scope pour partager le token)"""
    
    # Configurer la DB
    import main
    main.DB_CONFIG = test_database
    
    with TestClient(app) as test_client:
        # 1. Créer d'abord l'utilisateur dans mainuser
        conn = mysql.connector.connect(**test_database)
        cursor = conn.cursor()
        
        # Vérifier si l'utilisateur existe déjà
        cursor.execute("SELECT email FROM mainuser WHERE email = %s", (TEST_USER["email"],))
        user_exists = cursor.fetchone()
        
        if not user_exists:
            # Créer l'utilisateur de test (simuler un hash de mot de passe)
            # Tu devras adapter selon comment ton API hash les mots de passe
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            hashed_password = pwd_context.hash(TEST_USER["password"])
            
            cursor.execute("""
                INSERT INTO mainuser (email, fullname, telephone, hashed_password, is_superadmin)
                VALUES (%s, %s, %s, %s, %s)
            """, (TEST_USER["email"], TEST_USER["fullname"], TEST_USER["telephone"], hashed_password, False))
            conn.commit()
        
        cursor.close()
        conn.close()
        
        # 2. S'authentifier pour obtenir le token
        login_response = test_client.post("/auth/login", json={
            "email": TEST_USER["email"],
            "password": TEST_USER["password"]
        })
        
        assert login_response.status_code == 200, f"Login failed: {login_response.text}"
        
        token_data = login_response.json()
        access_token = token_data.get("access_token")
        
        assert access_token is not None, "No access token received"
        
        # Stocker le token dans un attribut du client
        test_client.headers.update({
            "Authorization": f"Bearer {access_token}"
        })
        
        yield test_client


@pytest.fixture
def client(authenticated_client):
    """Alias pour authenticated_client (garder la même interface)"""
    return authenticated_client


@pytest.fixture
def clear_settings_table(db_connection):
    """Nettoie la table user_settings avant chaque test"""
    cursor = db_connection.cursor()
    cursor.execute("DELETE FROM user_settings")
    db_connection.commit()
    cursor.close()


@pytest.fixture
def create_test_user(db_connection):
    """Crée un utilisateur de test dans mainuser (déjà fait dans authenticated_client)"""
    # Cette fixture est maintenant redondante car l'utilisateur est créé dans authenticated_client
    # On la garde pour compatibilité mais on ne fait rien
    pass


@pytest.fixture
def setup_existing_settings(db_connection):
    """Insère des settings existants pour tester l'UPDATE"""
    cursor = db_connection.cursor()
    cursor.execute("""
        INSERT INTO user_settings 
        (email, random_password_enabled, encrypted_result_visible, 
         scan_history_cleanup_mode, use_custom_restore_path, custom_restore_path,
         is_ai_analysis_enabled, is_realtime_analysis_enabled,
         require_password_for_delete, require_password_for_download)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE email=email
    """, (
        "existing@example.com",
        False,
        False,
        "manuel",
        False,
        "",
        False,
        False,
        False,
        False
    ))
    db_connection.commit()
    cursor.close()


@pytest.fixture
def sample_user_settings():
    """Fixture avec des paramètres de test valides"""
    return {
        "email": "abdellahazaz5@gmail.com",  # Utiliser l'email de l'utilisateur authentifié
        "random_password_enabled": True,
        "encrypted_result_visible": True,
        "scan_history_cleanup_mode": "Jamais",
        "use_custom_restore_path": False,
        "custom_restore_path": "",
        "is_ai_analysis_enabled": True,
        "is_realtime_analysis_enabled": True,
        "require_password_for_delete": True,
        "require_password_for_download": True
    }