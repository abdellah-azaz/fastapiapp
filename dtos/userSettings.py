from pydantic import BaseModel

class UserSettings(BaseModel):
    email: str
    random_password_enabled: bool = True
    encrypted_result_visible: bool = True
    scan_history_cleanup_mode: str = "Jamais"
    use_custom_restore_path: bool = False
    custom_restore_path: str = ""
    is_ai_analysis_enabled: bool = True
    is_realtime_analysis_enabled: bool = True
    require_password_for_delete: bool = True
    require_password_for_download: bool = True
