#ifndef DATABASE_H
#define DATABASE_H

#include "common.h"
#include <sqlite3.h>

/* ============================================
   STRUCTURE CONNEXION BASE DE DONNÉES
   ============================================ */
typedef struct {
    sqlite3 *db;
    char db_path[MAX_PATH_LEN];
    int initialized;
} Database;

/* ============================================
   STRUCTURE HISTORIQUE SCAN
   ============================================ */
typedef struct {
    int id;
    char scan_id[64];
    char target_path[MAX_PATH_LEN];
    int total_files;
    int clean_files;
    int suspicious_files;
    int malware_files;
    double scan_duration;
    char scan_date[64];
} ScanHistory;

/* ============================================
   STRUCTURE MENACE DÉTECTÉE
   ============================================ */
typedef struct {
    int id;
    char scan_id[64];
    char filepath[MAX_PATH_LEN];
    char filename[MAX_FILENAME_LEN];
    char sha256[MAX_HASH_LEN];
    char threat_name[MAX_THREAT_NAME];
    char threat_type[64];
    int heuristic_score;
    double entropy_value;
    char detection_date[64];
    int quarantined;
} ThreatRecord;

/* ============================================
   FONCTIONS BASE DE DONNÉES
   ============================================ */

/* Initialisation */
int  database_init(Database *db);
int  database_create_tables(Database *db);
void database_close(Database *db);

/* Scans */
int  database_save_scan(Database *db, const ScanReport *report);
int  database_get_scan_history(Database *db, ScanHistory *history, int max);
int  database_get_scan_count(Database *db);

/* Menaces */
int  database_save_threat(Database *db, const FileReport *report, const char *scan_id);
int  database_get_threats(Database *db, ThreatRecord *threats, int max);
int  database_get_threat_count(Database *db);
int  database_search_hash(Database *db, const char *sha256, ThreatRecord *result);

/* Quarantaine */
int  database_save_quarantine(Database *db, const FileReport *report);
int  database_update_quarantine_restored(Database *db, const char *sha256);
int  database_get_quarantine_count(Database *db);

/* Audit */
int  database_save_audit(Database *db, const char *action, const char *target, const char *user);
void database_print_stats(Database *db);

#endif
