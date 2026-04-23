#ifndef COMMON_H
#define COMMON_H

/* ============================================
   AV-SHIELD v1.0.0 — Définitions communes
   Auteur: Fatima
   Description: Structures et constantes partagées
   ============================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

/* ============================================
   CONSTANTES GLOBALES
   ============================================ */
#define AV_VERSION           "1.0.0"
#define AV_NAME              "AV-Shield"
#define AV_AUTHOR            "Fatima"

#define MAX_PATH_LEN         4096
#define MAX_FILENAME_LEN     256
#define MAX_HASH_LEN         65
#define MAX_THREAT_NAME      256
#define MAX_LOG_LEN          1024
#define FILE_CHUNK_SIZE      8192
#define MAX_FILE_SIZE        104857600   

/* Seuils de détection */
#define ENTROPY_THRESHOLD    7.0         
#define HEURISTIC_THRESHOLD  40          

/* Chemins */
#define QUARANTINE_DIR       "quarantine/"
#define REPORTS_DIR          "reports/"
#define LOG_SCAN             "logs/scan.log"
#define LOG_ERROR            "logs/error.log"
#define DATABASE_PATH        "database/avshield.db"

/* ============================================
   TYPES DE RÉSULTATS
   ============================================ */
typedef enum {
    RESULT_CLEAN      = 0,   
    RESULT_SUSPICIOUS = 1, 
    RESULT_MALWARE    = 2,   
    RESULT_ERROR      = 3 
} ScanResult;

/* ============================================
   STRUCTURE D'UN FICHIER SCANNÉ
   ============================================ */
typedef struct {
    char filepath[MAX_PATH_LEN];
    char filename[MAX_FILENAME_LEN];
    long filesize;
    char sha256[MAX_HASH_LEN];
    ScanResult clamav_result;
    char threat_name[MAX_THREAT_NAME];
    ScanResult heuristic_result;
    int heuristic_score;
    double entropy;
    ScanResult final_result;
    char scan_time[64];
    int quarantined;
    int quarantine_auto;
    char quarantine_path[MAX_PATH_LEN];
} FileReport;

/* ============================================
   STRUCTURE D'UN RAPPORT COMPLET
   ============================================ */
typedef struct {
    char scan_id[64];
    char target_path[MAX_PATH_LEN];
    int total_files;
    int clean_files;
    int suspicious_files;
    int malware_files;
    int error_files;
    double scan_duration;
    char start_time[64];
    char end_time[64];
    FileReport *files;
} ScanReport;

/* ============================================
   COULEURS TERMINAL
   ============================================ */
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_WHITE   "\033[1;37m"
#define COLOR_RESET   "\033[0m"

/* ============================================
   MACROS D'AFFICHAGE
   ============================================ */
#define PRINT_INFO(msg)   printf(COLOR_CYAN    "[INFO]   " COLOR_RESET "%s\n", msg)
#define PRINT_OK(msg)     printf(COLOR_GREEN   "[CLEAN]  " COLOR_RESET "%s\n", msg)
#define PRINT_WARN(msg)   printf(COLOR_YELLOW  "[WARN]   " COLOR_RESET "%s\n", msg)
#define PRINT_ERROR(msg)  printf(COLOR_RED     "[ERROR]  " COLOR_RESET "%s\n", msg)
#define PRINT_THREAT(msg) printf(COLOR_RED     "[THREAT] " COLOR_RESET "%s\n", msg)
#define PRINT_SUSPECT(msg)printf(COLOR_YELLOW  "[SUSPECT]" COLOR_RESET "%s\n", msg)

#endif
