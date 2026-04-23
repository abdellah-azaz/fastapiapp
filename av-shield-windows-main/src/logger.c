#include "../include/logger.h"
#include <time.h>

/* Fichiers de log globaux */
static FILE *scan_log  = NULL;
static FILE *error_log = NULL;

/* ============================================
   INITIALISATION DU LOGGER
   ============================================ */
int logger_init(void) {
    /* Ouvre le fichier scan.log en mode append */
    scan_log = fopen(LOG_SCAN, "a");
    if (!scan_log) {
        fprintf(stderr, "[ERROR] Impossible d'ouvrir %s\n", LOG_SCAN);
        return -1;
    }

    /* Ouvre le fichier error.log en mode append */
    error_log = fopen(LOG_ERROR, "a");
    if (!error_log) {
        fprintf(stderr, "[ERROR] Impossible d'ouvrir %s\n", LOG_ERROR);
        fclose(scan_log);
        return -1;
    }

    logger_write(LOG_INFO, "=== AV-Shield Logger initialisé ===");
    return 0;
}

/* ============================================
   OBTENIR L'HEURE ACTUELLE
   ============================================ */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* ============================================
   ÉCRIRE UN MESSAGE DANS LES LOGS
   ============================================ */
void logger_write(LogLevel level, const char *message) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    /* Préfixe selon le niveau */
    const char *level_str;
    FILE *target_file;

    switch (level) {
        case LOG_INFO:
            level_str  = "INFO   ";
            target_file = scan_log;
            break;
        case LOG_WARNING:
            level_str  = "WARNING";
            target_file = scan_log;
            break;
        case LOG_THREAT:
            level_str  = "THREAT ";
            target_file = scan_log;
            break;
        case LOG_ERR:
            level_str  = "ERROR  ";
            target_file = error_log;
            break;
        case LOG_AUDIT:
            level_str  = "AUDIT  ";
            target_file = scan_log;
            break;
        default:
            level_str  = "UNKNOWN";
            target_file = scan_log;
    }

    /* Écriture dans le fichier */
    if (target_file) {
        fprintf(target_file, "[%s] [%s] %s\n",
                timestamp, level_str, message);
        fflush(target_file);
    }
}

/* ============================================
   LOGGER LE RÉSULTAT D'UN FICHIER SCANNÉ
   ============================================ */
void logger_scan_result(const FileReport *report) {
    char message[MAX_LOG_LEN];
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    /* Choisir le niveau selon le résultat */
    LogLevel level;
    const char *result_str;

    switch (report->final_result) {
        case RESULT_CLEAN:
            level      = LOG_INFO;
            result_str = "CLEAN";
            break;
        case RESULT_SUSPICIOUS:
            level      = LOG_WARNING;
            result_str = "SUSPICIOUS";
            break;
        case RESULT_MALWARE:
            level      = LOG_THREAT;
            result_str = "MALWARE";
            break;
        default:
            level      = LOG_ERR;
            result_str = "ERROR";
    }

    /* Format du message */
    snprintf(message, sizeof(message),
             "FILE: %-40s | RESULT: %-10s | SHA256: %.16s... | SIZE: %ld bytes",
             report->filename,
             result_str,
             report->sha256,
             report->filesize);

    logger_write(level, message);

    /* Log supplémentaire si menace */
    if (report->final_result == RESULT_MALWARE) {
        snprintf(message, sizeof(message),
                 "THREAT DETECTED: %.100s | FILE: %.200s",
                 report->threat_name,
                 report->filepath);
        logger_write(LOG_THREAT, message);
    }
}

/* ============================================
   LOGGER UNE ACTION UTILISATEUR (AUDIT)
   ============================================ */
void logger_audit(const char *action, const char *target) {
    char message[MAX_LOG_LEN];
    snprintf(message, sizeof(message),
             "ACTION: %-15s | TARGET: %s",
             action, target);
    logger_write(LOG_AUDIT, message);
}

/* ============================================
   FERMETURE DU LOGGER
   ============================================ */
void logger_close(void) {
    logger_write(LOG_INFO, "=== AV-Shield Logger fermé ===");

    if (scan_log)  { fclose(scan_log);  scan_log  = NULL; }
    if (error_log) { fclose(error_log); error_log = NULL; }
}
