# tests_integr/test_settings.py
import pytest
import mysql.connector
from mysql.connector import Error as MySQLError

class TestSaveSettings:
    """Tests d'intégration pour POST /settings"""
    
    def test_create_new_settings_success(self, client, clear_settings_table, sample_user_settings):
        """Test 1: Créer des nouveaux settings pour l'utilisateur authentifié"""
        
        response = None
        db_conn = None
        db_cursor = None
        
        try:
            # 1. Exécuter la requête POST
            response = client.post("/settings", json=sample_user_settings)
            
            # 2. Vérifier le code de statut HTTP
            assert response.status_code == 200, \
                f"❌ Erreur HTTP: attendu 200, reçu {response.status_code}\n" \
                f"Réponse: {response.text}"
            
            # 3. Vérifier la structure de la réponse JSON
            try:
                data = response.json()
            except Exception as json_err:
                pytest.fail(f"❌ La réponse n'est pas du JSON valide: {json_err}\nTexte: {response.text}")
            
            # 4. Vérifier le contenu de la réponse
            assert data.get("success") == True, \
                f"❌ 'success' devrait être True, reçu: {data.get('success')}\n" \
                f"Message: {data.get('message')}"
            
            assert "Settings saved successfully" in data.get("message", ""), \
                f"❌ Message inattendu: {data.get('message')}"
            
            # 5. Vérification en base de données
            try:
                import main
                db_conn = mysql.connector.connect(**main.DB_CONFIG)
                db_cursor = db_conn.cursor(dictionary=True)
                
                db_cursor.execute(
                    "SELECT * FROM user_settings WHERE email = %s", 
                    (sample_user_settings["email"],)
                )
                db_settings = db_cursor.fetchone()
                
            except MySQLError as db_err:
                pytest.fail(f"❌ Erreur de connexion à la base de test: {db_err}")
            
            # 6. Vérifier que les settings ont été créés
            assert db_settings is not None, \
                f"❌ Aucun settings trouvé en DB pour l'email: {sample_user_settings['email']}"
            
            # 7. Vérifier chaque champ individuellement avec des messages clairs
            expected = sample_user_settings
            actual = db_settings
            
            # Convertir les booléens MySQL (0/1) en booléens Python
            bool_fields = [
                "random_password_enabled",
                "encrypted_result_visible",
                "use_custom_restore_path",
                "is_ai_analysis_enabled",
                "is_realtime_analysis_enabled",
                "require_password_for_delete",
                "require_password_for_download"
            ]
            
            for field in bool_fields:
                actual_value = bool(actual.get(field))
                expected_value = expected.get(field)
                assert actual_value == expected_value, \
                    f"❌ Champ '{field}': attendu {expected_value}, reçu {actual_value}"
            
            # Vérifier les champs texte
            assert actual.get("scan_history_cleanup_mode") == expected.get("scan_history_cleanup_mode"), \
                f"❌ scan_history_cleanup_mode: attendu '{expected.get('scan_history_cleanup_mode')}', " \
                f"reçu '{actual.get('scan_history_cleanup_mode')}'"
            
            assert actual.get("custom_restore_path") == expected.get("custom_restore_path"), \
                f"❌ custom_restore_path: attendu '{expected.get('custom_restore_path')}', " \
                f"reçu '{actual.get('custom_restore_path')}'"
            
            # 8. Test réussi
            print(f"\n✅ Test réussi! Settings créés pour {sample_user_settings['email']}")
            
        except AssertionError as e:
            # Propager les erreurs d'assertion avec leur message
            raise e
        except Exception as e:
            # Capturer toute autre exception inattendue
            pytest.fail(f"❌ Exception inattendue dans le test: {type(e).__name__}: {e}")
        finally:
            # 9. Nettoyage des ressources
            if db_cursor:
                db_cursor.close()
            if db_conn and db_conn.is_connected():
                db_conn.close()