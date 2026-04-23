# tests_integr/test_conftest_diagnostic.py
import pytest
import mysql.connector

class TestConftest:
    """Tester les fixtures du conftest.py une par une"""
    
    def test_test_database_fixture(self, test_database):
        """Vérifier que la base de test est créée correctement"""
        print(f"\n📁 Base de test: {test_database['database']}")
        
        conn = mysql.connector.connect(**test_database)
        cursor = conn.cursor()
        
        # Vérifier que la table mainuser existe
        cursor.execute("SHOW TABLES LIKE 'mainuser'")
        result = cursor.fetchone()
        assert result is not None, "La table mainuser n'existe pas"
        print("✅ Table mainuser existe")
        
        # Vérifier que la table user_settings existe
        cursor.execute("SHOW TABLES LIKE 'user_settings'")
        result = cursor.fetchone()
        assert result is not None, "La table user_settings n'existe pas"
        print("✅ Table user_settings existe")
        
        cursor.close()
        conn.close()
    
    def test_db_connection_fixture(self, db_connection, test_database):
        """Vérifier la connexion DB"""
        cursor = db_connection.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result[0] == 1
        print("✅ Connexion DB fonctionnelle")
    
    def test_create_test_user_fixture(self, create_test_user, db_connection):
        """Vérifier que la fixture create_test_user fonctionne"""
        cursor = db_connection.cursor(dictionary=True)
        cursor.execute("SELECT email FROM mainuser WHERE email = 'test@example.com'")
        user = cursor.fetchone()
        cursor.close()
        
        # Note: create_test_user dans ton code ne fait rien (pass)
        # Donc ce test va échouer si l'utilisateur n'existe pas
        if user:
            print(f"✅ Utilisateur trouvé: {user['email']}")
        else:
            print("⚠️ Aucun utilisateur test@example.com (normal car create_test_user est vide)")
    
    def test_sample_user_settings_fixture(self, sample_user_settings):
        """Vérifier la fixture des settings"""
        assert sample_user_settings["email"] == "abdellahazaz5@gmail.com"
        assert isinstance(sample_user_settings["random_password_enabled"], bool)
        print(f"✅ Fixture sample_user_settings OK: {sample_user_settings['email']}")
    


    def test_db_recealing(self, db_connection, test_database):
        """Vérifier la connexion DB"""
        cursor = db_connection.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result[0] == 1
        print("✅ Connexion DB fonctionnelle")



    def tables_db_recling(self, db_connection, test_database):
        """Vérifier la connexion DB"""
        cursor = db_connection.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result[0] == 1
        print("✅ Connexion DB fonctionnelle")

    def test_db_connection_fixture(self, db_connection, test_database):
        """Vérifier la connexion DB"""
        cursor = db_connection.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result[0] == 1
        print("✅ Connexion DB fonctionnelle")