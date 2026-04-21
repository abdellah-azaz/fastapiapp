# tests/test_auth_login.py
import sys
import os
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import jwt
import datetime
from main import JWT_SECRET_KEY, JWT_ALGORITHM


# Ajoute le dossier parent (fastapi/) au path Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app

client = TestClient(app)

# ==================== TESTS POUR /auth/login ====================

@patch('mysql.connector.connect')
def test_login_success(mock_connect):
    """Test: Connexion réussie avec email et mot de passe corrects"""
    # Mock base de données
    mock_cursor = MagicMock()
    mock_connect.return_value.cursor.return_value = mock_cursor
    
    # Simuler utilisateur trouvé
    mock_user = {
        "id": 1,
        "email": "test@example.com",
        "password": "hashed_password123"
    }
    
    # Premier fetchone retourne l'utilisateur, deuxième fetchone (banned) retourne None
    mock_cursor.fetchone.side_effect = [mock_user, None]
    
    # Mock de verify_password (importé dans main.py)
    with patch('main.verify_password', return_value=True):
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "Test123!"
        })
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    assert data["message"] == "Connexion réussie."
    assert "access_token" in data
    assert "refresh_token" in data
    assert "user" in data
    assert "password" not in data["user"]  # Password ne doit pas être envoyé
    assert data["user"]["email"] == "test@example.com"


@patch('mysql.connector.connect')
def test_login_wrong_password(mock_connect):
    """Test: Échec connexion avec mot de passe incorrect"""
    mock_cursor = MagicMock()
    mock_connect.return_value.cursor.return_value = mock_cursor
    
    mock_user = {
        "id": 1,
        "email": "test@example.com",
        "password": "hashed_password123"
    }
    
    mock_cursor.fetchone.side_effect = [mock_user, None]
    
    # Simuler mot de passe incorrect
    with patch('main.verify_password', return_value=False):
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "WrongPassword!"
        })
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == False
    assert data["message"] == "Email ou mot de passe incorrect."
    assert "access_token" not in data


@patch('mysql.connector.connect')
def test_login_user_not_found(mock_connect):
    """Test: Échec connexion avec email inexistant"""
    mock_cursor = MagicMock()
    mock_connect.return_value.cursor.return_value = mock_cursor
    
    # Aucun utilisateur trouvé
    mock_cursor.fetchone.return_value = None
    
    response = client.post("/auth/login", json={
        "email": "nonexistent@example.com",
        "password": "Test123!"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == False
    assert data["message"] == "Email ou mot de passe incorrect."


@patch('mysql.connector.connect')
def test_login_banned_user(mock_connect):
    """Test: Échec connexion pour utilisateur banni"""
    mock_cursor = MagicMock()
    mock_connect.return_value.cursor.return_value = mock_cursor
    
    mock_user = {
        "id": 1,
        "email": "banned@example.com",
        "password": "hashed_password123"
    }
    
    # Premier fetchone = utilisateur, deuxième fetchone = banni avec raison
    mock_cursor.fetchone.side_effect = [
        mock_user,  # utilisateur trouvé
        {"reason": "Comportement inapproprié"}  # utilisateur banni
    ]
    
    response = client.post("/auth/login", json={
        "email": "banned@example.com",
        "password": "Test123!"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == False
    assert data["message"] == "Votre compte a été banni."


@patch('mysql.connector.connect')
def test_login_database_error(mock_connect):
    """Test: Erreur de base de données"""
    import mysql.connector
    mock_connect.side_effect = mysql.connector.Error("Connection failed")
    
    response = client.post("/auth/login", json={
        "email": "test@example.com",
        "password": "Test123!"
    })
    
    assert response.status_code == 500
    assert "Erreur BD" in response.json()["detail"]


# ==================== TESTS POUR /auth/refresh ====================

def test_refresh_token_success():
    """Test: Rafraîchissement du token avec refresh token valide"""
    import jwt
    import datetime
    
    # Créer un refresh token valide
    refresh_expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    refresh_payload = {
        "sub": "test@example.com", 
        "exp": refresh_expire, 
        "type": "refresh"
    }
    
    # Note: Vous devez avoir JWT_REFRESH_SECRET_KEY dans votre environnement
    from main import JWT_REFRESH_SECRET_KEY, JWT_ALGORITHM
    valid_refresh_token = jwt.encode(refresh_payload, JWT_REFRESH_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    response = client.post("/auth/refresh", json={
        "refresh_token": valid_refresh_token
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    assert "access_token" in data


def test_refresh_token_expired():
    """Test: Refresh token expiré"""
    import jwt
    import datetime
    
    # Créer un refresh token expiré
    refresh_expire = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    refresh_payload = {
        "sub": "test@example.com", 
        "exp": refresh_expire, 
        "type": "refresh"
    }
    
    from main import JWT_REFRESH_SECRET_KEY, JWT_ALGORITHM
    expired_token = jwt.encode(refresh_payload, JWT_REFRESH_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    response = client.post("/auth/refresh", json={
        "refresh_token": expired_token
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == False
    assert data["message"] == "Refresh token expiré"


def test_refresh_token_invalid():
    """Test: Refresh token invalide"""
    response = client.post("/auth/refresh", json={
        "refresh_token": "invalid.token.string"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == False
    assert data["message"] == "Refresh token invalide"




# ==================== TESTS DE VALIDATION DES DONNÉES ====================

# tests/test_auth_login.py

@patch('mysql.connector.connect')
def test_update_profile_success(mock_connect):
    """Test: Mise à jour du profil avec succès"""
    # Mock base de données
    mock_cursor = MagicMock()
    mock_connect.return_value.cursor.return_value = mock_cursor
    
    # Simuler qu'une ligne a été modifiée (utilisateur trouvé et mis à jour)
    mock_cursor.rowcount = 1
    
    # Simuler l'utilisateur après mise à jour
    updated_user = {
        "id": 1,
        "fullname": "Jean Dupont",
        "email": "jean@example.com",
        "telephone": "0612345678",
        "is_superadmin": 0
    }
    
    # IMPORTANT: fetchone est appelé UNE SEULE FOIS après le SELECT
    # Pas besoin de side_effect avec None
    mock_cursor.fetchone.return_value = updated_user
    
    # Envoyer la requête de mise à jour
    response = client.post("/auth/update-profile", json={
        "email": "jean@example.com",
        "fullname": "Jean Dupont",
        "telephone": "0612345678"
    })
    
    # Vérifications
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    assert data["message"] == "Profil mis à jour avec succès."
    assert "user" in data
    assert data["user"]["fullname"] == "Jean Dupont"
    assert data["user"]["telephone"] == "0612345678"
    assert data["user"]["email"] == "jean@example.com"
    assert data["user"]["id"] == 1

    ##3######2222###############################################

# tests/test_auth_login.py

@patch('mysql.connector.connect')
def test_vault_list_success(mock_connect):
    """Test: Récupération de la liste des fichiers chiffrés avec succès"""
    
    # 1. CRÉER UN TOKEN JWT VALIDE POUR L'AUTHENTIFICATION
    
    # Créer un token d'accès valide (24 heures)
    access_expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    access_payload = {
        "sub": "test@example.com",  # Email de l'utilisateur
        "exp": access_expire,
        "type": "access"
    }
    valid_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    # 2. MOCK DE LA BASE DE DONNÉES
    mock_cursor = MagicMock()
    mock_connect.return_value.cursor.return_value = mock_cursor
    
    # Simuler la liste des fichiers retournés
    mock_files = [
        {
            "file_id": 1,
            "filename": "document_secret.pdf",
            "created_at": "2024-01-15 10:30:00"
        },
        {
            "file_id": 2,
            "filename": "photo_chiffree.jpg",
            "created_at": "2024-01-14 15:20:00"
        }
    ]
    
    mock_cursor.fetchall.return_value = mock_files
    
    # 3. ENVOYER LA REQUÊTE AVEC LE TOKEN
    response = client.get(
        "/vault/list/test@example.com",
        headers={"Authorization": f"Bearer {valid_token}"}  # ← AJOUTER LE TOKEN ICI
    )
    
    # 4. VÉRIFICATIONS
    assert response.status_code == 200
    data = response.json()
    
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["file_id"] == 1
    assert data[0]["filename"] == "document_secret.pdf"
    
    # Vérifier la requête SQL
    mock_cursor.execute.assert_called_once_with(
        "SELECT file_id, filename, created_at FROM vault_files WHERE owner_email = %s ORDER BY created_at DESC",
        ("test@example.com",)
    )


    #######################################################3333#33####

@patch('modules.ssh_scanner.run_remote_vulnerability_scan')
def test_ssh_scan_success(mock_ssh_scan):
    """Test: Scan SSH réussi"""
    
    token = jwt.encode(
        {
            "sub": "admin@example.com",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24),
            "type": "access"
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )
    
    # Mocker le scan
    mock_ssh_scan.return_value = {
        "success": True,
        "data": {
            "host": "192.168.1.100",
            "port": 22,
            "vulnerabilities": [
                {"name": "Test vuln", "severity": "HIGH", "description": "Test"}
            ],
            "scan_duration": 1.0,
            "recommendations": ["Fix it"]
        }
    }
    
    # Requête avec token
    response = client.post(
        "/ssh/scan",
        json={"host": "192.168.1.100", "port": 22, "username": "admin", "password": "pass"},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    assert response.json()["host"] == "192.168.1.100"

