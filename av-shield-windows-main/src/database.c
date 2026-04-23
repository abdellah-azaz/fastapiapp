#include "../include/database.h"
#include "../include/logger.h"
#include <time.h>

/* ============================================
   OBTENIR L'HEURE ACTUELLE
   ============================================ */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* ============================================
   INITIALISATION BASE DE DONNÉES
   ============================================ */
int database_init(Database *db) {
    int rc = sqlite3_open(DATABASE_PATH, &db->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Impossible d'ouvrir la base: %s\n",
                sqlite3_errmsg(db->db));
        return -1;
    }

    strncpy(db->db_path, DATABASE_PATH, MAX_PATH_LEN - 1);
    db->initialized = 1;

    /* Créer les tables */
    if (database_create_tables(db) != 0) {
        return -1;
    }

    logger_write(LOG_INFO, "Base de données initialisée");
    return 0;
}

/* ============================================
   CRÉATION DES TABLES
   ============================================ */
int database_create_tables(Database *db) {
    char *err_msg = NULL;
    int rc;

    /* Table scans */
    const char *sql_scans =
        "CREATE TABLE IF NOT EXISTS scans ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "scan_id TEXT NOT NULL,"
        "target_path TEXT NOT NULL,"
        "total_files INTEGER DEFAULT 0,"
        "clean_files INTEGER DEFAULT 0,"
        "suspicious_files INTEGER DEFAULT 0,"
        "malware_files INTEGER DEFAULT 0,"
        "scan_duration REAL DEFAULT 0,"
        "scan_date TEXT NOT NULL"
        ");";

    rc = sqlite3_exec(db->db, sql_scans, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Table scans: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* Table threats */
    const char *sql_threats =
        "CREATE TABLE IF NOT EXISTS threats ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "scan_id TEXT NOT NULL,"
        "filepath TEXT NOT NULL,"
        "filename TEXT NOT NULL,"
        "sha256 TEXT NOT NULL,"
        "threat_name TEXT NOT NULL,"
        "threat_type TEXT NOT NULL,"
        "heuristic_score INTEGER DEFAULT 0,"
        "entropy_value REAL DEFAULT 0,"
        "detection_date TEXT NOT NULL,"
        "quarantined INTEGER DEFAULT 0"
        ");";

    rc = sqlite3_exec(db->db, sql_threats, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Table threats: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* Table quarantine */
    const char *sql_quarantine =
        "CREATE TABLE IF NOT EXISTS quarantine ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "original_path TEXT NOT NULL,"
        "quarantine_path TEXT NOT NULL,"
        "original_name TEXT NOT NULL,"
        "quarantine_name TEXT NOT NULL,"
        "sha256 TEXT NOT NULL,"
        "threat_name TEXT NOT NULL,"
        "quarantine_date TEXT NOT NULL,"
        "filesize INTEGER DEFAULT 0,"
        "restored INTEGER DEFAULT 0"
        ");";

    rc = sqlite3_exec(db->db, sql_quarantine, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Table quarantine: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* Table audit_logs */
    const char *sql_audit =
        "CREATE TABLE IF NOT EXISTS audit_logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "action TEXT NOT NULL,"
        "target TEXT NOT NULL,"
        "user TEXT NOT NULL,"
        "timestamp TEXT NOT NULL"
        ");";

    rc = sqlite3_exec(db->db, sql_audit, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Table audit_logs: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    logger_write(LOG_INFO, "Tables SQLite créées avec succès");
    return 0;
}

/* ============================================
   FERMETURE BASE DE DONNÉES
   ============================================ */
void database_close(Database *db) {
    if (db && db->db) {
        sqlite3_close(db->db);
        db->db          = NULL;
        db->initialized = 0;
        logger_write(LOG_INFO, "Base de données fermée");
    }
}

/* ============================================
   SAUVEGARDER UN SCAN
   ============================================ */
int database_save_scan(Database *db, const ScanReport *report) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *sql =
        "INSERT INTO scans "
        "(scan_id, target_path, total_files, clean_files, "
        "suspicious_files, malware_files, scan_duration, scan_date) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, report->scan_id,     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, report->target_path, -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 3, report->total_files);
    sqlite3_bind_int (stmt, 4, report->clean_files);
    sqlite3_bind_int (stmt, 5, report->suspicious_files);
    sqlite3_bind_int (stmt, 6, report->malware_files);
    sqlite3_bind_double(stmt, 7, report->scan_duration);
    sqlite3_bind_text(stmt, 8, timestamp, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;

    logger_write(LOG_INFO, "Scan sauvegardé en base de données");
    return 0;
}

/* ============================================
   SAUVEGARDER UNE MENACE
   ============================================ */
int database_save_threat(Database *db, const FileReport *report,
                          const char *scan_id) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *threat_type =
        (report->final_result == RESULT_MALWARE) ? "MALWARE" : "SUSPICIOUS";

    const char *sql =
        "INSERT INTO threats "
        "(scan_id, filepath, filename, sha256, threat_name, "
        "threat_type, heuristic_score, entropy_value, "
        "detection_date, quarantined) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text  (stmt, 1,  scan_id,             -1, SQLITE_STATIC);
    sqlite3_bind_text  (stmt, 2,  report->filepath,    -1, SQLITE_STATIC);
    sqlite3_bind_text  (stmt, 3,  report->filename,    -1, SQLITE_STATIC);
    sqlite3_bind_text  (stmt, 4,  report->sha256,      -1, SQLITE_STATIC);
    sqlite3_bind_text  (stmt, 5,  report->threat_name, -1, SQLITE_STATIC);
    sqlite3_bind_text  (stmt, 6,  threat_type,         -1, SQLITE_STATIC);
    sqlite3_bind_int   (stmt, 7,  report->heuristic_score);
    sqlite3_bind_double(stmt, 8,  report->entropy);
    sqlite3_bind_text  (stmt, 9,  timestamp,           -1, SQLITE_STATIC);
    sqlite3_bind_int   (stmt, 10, report->quarantined);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;

    logger_write(LOG_THREAT, "Menace sauvegardée en base de données");
    return 0;
}

/* ============================================
   SAUVEGARDER EN QUARANTAINE
   ============================================ */
int database_save_quarantine(Database *db, const FileReport *report) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *sql =
        "INSERT INTO quarantine "
        "(original_path, quarantine_path, original_name, "
        "quarantine_name, sha256, threat_name, "
        "quarantine_date, filesize, restored) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0);";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, report->filepath,        -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, report->quarantine_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, report->filename,        -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, report->quarantine_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, report->sha256,          -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, report->threat_name,     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, timestamp,               -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 8, (int)report->filesize);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;

    logger_write(LOG_AUDIT, "Fichier enregistré en quarantaine");
    return 0;
}

/* ============================================
   RECHERCHER UN HASH
   ============================================ */
int database_search_hash(Database *db, const char *sha256,
                          ThreatRecord *result) {
    const char *sql =
        "SELECT filename, sha256, threat_name, threat_type "
        "FROM threats WHERE sha256 = ? LIMIT 1;";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, sha256, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        strncpy(result->filename,
                (const char*)sqlite3_column_text(stmt, 0),
                MAX_FILENAME_LEN - 1);
        strncpy(result->sha256,
                (const char*)sqlite3_column_text(stmt, 1),
                MAX_HASH_LEN - 1);
        strncpy(result->threat_name,
                (const char*)sqlite3_column_text(stmt, 2),
                MAX_THREAT_NAME - 1);
        sqlite3_finalize(stmt);
        return 1; /* Trouvé ! */
    }

    sqlite3_finalize(stmt);
    return 0; /* Pas trouvé */
}

/* ============================================
   MISE À JOUR RESTAURATION QUARANTAINE
   ============================================ */
int database_update_quarantine_restored(Database *db, const char *sha256) {
    const char *sql =
        "UPDATE quarantine SET restored = 1 WHERE sha256 = ?;";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, sha256, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    logger_write(LOG_AUDIT, "Fichier restauré depuis quarantaine");
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ============================================
   STATISTIQUES GLOBALES
   ============================================ */
void database_print_stats(Database *db) {
    int scans = 0, threats = 0, quarantine = 0;

    /* Compter les scans */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db,
        "SELECT COUNT(*) FROM scans;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            scans = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }

    /* Compter les menaces */
    if (sqlite3_prepare_v2(db->db,
        "SELECT COUNT(*) FROM threats;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            threats = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }

    /* Compter la quarantaine */
    if (sqlite3_prepare_v2(db->db,
        "SELECT COUNT(*) FROM quarantine WHERE restored=0;",
        -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            quarantine = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }

    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_CYAN "║      AV-SHIELD  STATISTIQUES     ║\n" COLOR_RESET);
    printf(COLOR_CYAN "╠══════════════════════════════════╣\n" COLOR_RESET);
    printf(COLOR_CYAN "║ " COLOR_RESET "Total scans      : " COLOR_GREEN "%-14d" COLOR_RESET COLOR_CYAN " ║\n" COLOR_RESET, scans);
    printf(COLOR_CYAN "║ " COLOR_RESET "Menaces détectées: " COLOR_RED   "%-14d" COLOR_RESET COLOR_CYAN " ║\n" COLOR_RESET, threats);
    printf(COLOR_CYAN "║ " COLOR_RESET "En quarantaine   : " COLOR_YELLOW "%-14d" COLOR_RESET COLOR_CYAN " ║\n" COLOR_RESET, quarantine);
    printf(COLOR_CYAN "╚══════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
}

/* ============================================
   AUDIT TRAIL
   ============================================ */
int database_save_audit(Database *db, const char *action,
                         const char *target, const char *user) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *sql =
        "INSERT INTO audit_logs (action, target, user, timestamp) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, action,    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, target,    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user,      -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, timestamp, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ============================================
   COMPTER LES MENACES
   ============================================ */
int database_get_threat_count(Database *db) {
    sqlite3_stmt *stmt;
    int count = 0;

    if (sqlite3_prepare_v2(db->db,
        "SELECT COUNT(*) FROM threats;",
        -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    return count;
}

/* ============================================
   COMPTER LES FICHIERS EN QUARANTAINE
   ============================================ */
int database_get_quarantine_count(Database *db) {
    sqlite3_stmt *stmt;
    int count = 0;

    if (sqlite3_prepare_v2(db->db,
        "SELECT COUNT(*) FROM quarantine WHERE restored=0;",
        -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    return count;
}

/* ============================================
   COMPTER LES SCANS
   ============================================ */
int database_get_scan_count(Database *db) {
    sqlite3_stmt *stmt;
    int count = 0;

    if (sqlite3_prepare_v2(db->db,
        "SELECT COUNT(*) FROM scans;",
        -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    return count;
}
/* ============================================
   HISTORIQUE DES SCANS
   ============================================ */
int database_get_scan_history(Database *db,
                               ScanHistory *history,
                               int max) {
    const char *sql =
        "SELECT scan_id, target_path, total_files, "
        "clean_files, suspicious_files, malware_files, "
        "scan_duration, scan_date "
        "FROM scans ORDER BY id DESC LIMIT ?;";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, max);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW &&
           count < max) {
        strncpy(history[count].scan_id,
                (const char*)sqlite3_column_text(stmt, 0),
                63);
        strncpy(history[count].target_path,
                (const char*)sqlite3_column_text(stmt, 1),
                MAX_PATH_LEN - 1);
        history[count].total_files      = sqlite3_column_int(stmt, 2);
        history[count].clean_files      = sqlite3_column_int(stmt, 3);
        history[count].suspicious_files = sqlite3_column_int(stmt, 4);
        history[count].malware_files    = sqlite3_column_int(stmt, 5);
        history[count].scan_duration    = sqlite3_column_double(stmt, 6);
        strncpy(history[count].scan_date,
                (const char*)sqlite3_column_text(stmt, 7),
                63);
        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}
