#include "../include/scanner.h"
#include "../include/hash.h"
#include "../include/heuristic.h"
#include "../include/clamav_engine.h"
#include "../include/correlation.h"
#include "../include/quarantine.h"
#include "../include/database.h"
#include "../include/logger.h"
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define S_ISLNK(m) 0
#define lstat stat
#endif


/* Variables globales du scanner */
static ScannerConfig  g_config;
static ScannerStats   g_stats;
static ClamavEngine   g_clamav;
static Database       g_db;

/* ============================================
   INITIALISATION DU SCANNER
   ============================================ */
int scanner_init(ScannerConfig *config) {
    /* Copier la configuration */
    memcpy(&g_config, config, sizeof(ScannerConfig));

    /* Réinitialiser les stats */
    memset(&g_stats, 0, sizeof(ScannerStats));

    /* Initialiser la base de données */
    if (database_init(&g_db) != 0) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Impossible d'initialiser la base\n");
        return -1;
    }

    /* Initialiser ClamAV */
    if (clamav_init(&g_clamav) != 0) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Impossible d'initialiser ClamAV\n");
        return -1;
    }

    /* Initialiser la quarantaine */
    if (quarantine_init() != 0) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Impossible d'initialiser la quarantaine\n");
        return -1;
    }

    /* Initialiser l'heuristique */
    heuristic_init();

    logger_write(LOG_INFO, "Scanner initialisé");
    return 0;
}

/* ============================================
   VÉRIFIER SI UN FICHIER EST VALIDE
   ============================================ */
int scanner_is_valid_file(const char *filepath) {
    struct stat st;

    /* Vérifier que le fichier existe */
    if (stat(filepath, &st) != 0) return 0;

    /* Ignorer les fichiers quarantaine */
    if (strstr(filepath, "/quarantine/") != NULL) return 0;
    if (strstr(filepath, "/reports/") != NULL) return 0;
    if (strstr(filepath, "/logs/") != NULL) return 0;
    if (strstr(filepath, "/obj/") != NULL) return 0;
    if (strstr(filepath, ".quar") != NULL) return 0;
    /* Ignorer les dossiers */
    if (S_ISDIR(st.st_mode)) return 0;

    /* Ignorer les liens symboliques si configuré */
    if (!g_config.follow_symlinks && S_ISLNK(st.st_mode)) return 0;

    /* Vérifier la taille max */
    if (st.st_size > g_config.max_file_size) {
        g_stats.files_skipped++;
        char msg[MAX_LOG_LEN];
        snprintf(msg, sizeof(msg),
                 "Fichier ignoré (trop grand): %s (%ld bytes)",
                 filepath, (long)st.st_size);
        logger_write(LOG_WARNING, msg);
        return 0;
    }

    /* Ignorer les fichiers cachés si configuré */
    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;
    if (!g_config.scan_hidden && basename[0] == '.') return 0;

    /* Ignorer Makefile et notre propre binaire */
    if (strcmp(basename, "Makefile") == 0) return 0;
    if (strcmp(basename, "avshield") == 0) return 0;

    /* Extensions ignorées */
    const char *ext = strrchr(filepath, '.');
    if (ext) {
        if (strcmp(ext, ".o")   == 0 ||
            strcmp(ext, ".log") == 0 ||
            strcmp(ext, ".db")  == 0 ||
            strcmp(ext, ".c")   == 0 ||
            strcmp(ext, ".h")   == 0 ||
            strcmp(ext, ".cfg") == 0 ||
            strcmp(ext, ".md")  == 0) {
            return 0;
        }
    }
    return 1;
}
/* ============================================
   SCANNER UN SEUL FICHIER
   ============================================ */
int scanner_scan_file(const char *filepath, FileReport *report) {
    struct stat st;

    /* Initialiser le rapport */
    memset(report, 0, sizeof(FileReport));

    /* Remplir les infos de base */
    strncpy(report->filepath, filepath, MAX_PATH_LEN - 1);

    /* Extraire le nom du fichier */
    const char *basename = strrchr(filepath, '/');
    strncpy(report->filename,
            basename ? basename + 1 : filepath,
            MAX_FILENAME_LEN - 1);

    /* Obtenir la taille */
    if (stat(filepath, &st) == 0) {
        report->filesize = st.st_size;
    }

    /* Heure du scan */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(report->scan_time, sizeof(report->scan_time),
             "%Y-%m-%d %H:%M:%S", tm_info);

    /* ---- ÉTAPE 1: Vérifier dans la base (hash connu) ---- */
    char sha256[MAX_HASH_LEN];
    ThreatRecord known;
    if (hash_sha256_file(filepath, sha256) == 0) {
        strncpy(report->sha256, sha256, MAX_HASH_LEN - 1);

        /* Chercher dans l'historique */
        if (database_search_hash(&g_db, sha256, &known) == 1) {
            printf(COLOR_RED "[KNOWN]  " COLOR_RESET
                   "Menace connue détectée: %s\n",
                   known.threat_name);
            report->clamav_result = RESULT_MALWARE;
            report->final_result  = RESULT_MALWARE;
            strncpy(report->threat_name, known.threat_name,
                    MAX_THREAT_NAME - 1);
            /* Quarantaine seulement si auto activé */
            if (g_config.quarantine_auto) {
                quarantine_add(report);
                database_save_quarantine(&g_db, report);
                report->quarantined = 1;
            }
            goto scan_done;
        }
    }

    /* ---- ÉTAPE 2: Scanner avec ClamAV ---- */
    printf(COLOR_CYAN "[CLAMAV]  " COLOR_RESET
           "Scan: %s\n", report->filename);
    clamav_scan_file(&g_clamav, filepath, report);

    /* ---- ÉTAPE 3: Analyse multi-couches ---- */
    correlation_analyze(filepath, report);

scan_done:
    /* ---- ÉTAPE 4: Actions post-scan ---- */
    g_stats.files_scanned++;
    g_stats.total_bytes += report->filesize;

    /* Sauvegarder menace en base */
    if (report->final_result == RESULT_MALWARE &&
        report->clamav_result == RESULT_MALWARE) {
        database_save_threat(&g_db, report, "CURRENT_SCAN");
        database_save_audit(&g_db, "THREAT_DETECTED",
                            filepath, "avshield");
    }

    /* ==============================
   QUARANTAINE
   - MALWARE : TOUJOURS (même si option non cochée)
   - SUSPICIOUS : seulement si option utilisateur cochée
   ============================== */

if (report->final_result == RESULT_MALWARE && !report->quarantined && g_config.quarantine_auto) {

    quarantine_add(report);
    database_save_quarantine(&g_db, report);

    database_save_audit(&g_db, "QUARANTINE_MALWARE",
                        filepath, "avshield");

    report->quarantined = 1;

} else if (report->final_result == RESULT_SUSPICIOUS && !report->quarantined && g_config.quarantine_auto) {

    quarantine_add(report);
    database_save_quarantine(&g_db, report);

    database_save_audit(&g_db, "QUARANTINE_SUSPICIOUS",
                        filepath, "avshield");

    report->quarantined = 1;
}

    /* Logger le résultat */
    logger_scan_result(report);

    return 0;
}

/* ============================================
   AFFICHER LA PROGRESSION
   ============================================ */
void scanner_print_progress(int current, int total,
                             const char *filename) {
    if (total <= 0) return;

    int percent = (current * 100) / total;
    int bar_len = 30;
    int filled  = (bar_len * percent) / 100;

    printf("\r" COLOR_CYAN "[" COLOR_RESET);
    for (int i = 0; i < bar_len; i++) {
        if (i < filled)
            printf(COLOR_GREEN "█" COLOR_RESET);
        else
            printf("░");
    }
    printf(COLOR_CYAN "] " COLOR_RESET
           "%3d%% | %d/%d | %-30.30s",
           percent, current, total, filename);
    fflush(stdout);
}

/* ============================================
   SCANNER UN DOSSIER RÉCURSIVEMENT
   ============================================ */
int scanner_scan_directory(const char *dirpath,
                            ScanReport *report) {
    DIR *dir;
    struct dirent *entry;
    char filepath[MAX_PATH_LEN];
    struct stat st;

    /* Ouvrir le dossier */
    dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Impossible d'ouvrir: %s\n", dirpath);
        return -1;
    }

    g_stats.dirs_scanned++;

    /* Parcourir les entrées */
    while ((entry = readdir(dir)) != NULL) {
        /* Ignorer . et .. */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;

        /* Ignorer fichiers cachés si configuré */
        if (!g_config.scan_hidden &&
            entry->d_name[0] == '.') continue;

        /* Construire le chemin complet */
        snprintf(filepath, sizeof(filepath),
                 "%s/%s", dirpath, entry->d_name);

        /* Vérifier le type */
        if (lstat(filepath, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            /* Récursion si activée */
            if (g_config.recursive) {
                /* Ignorer dossiers système */
                if (strcmp(filepath, "/proc") == 0 ||
                    strcmp(filepath, "/sys")  == 0 ||
                    strcmp(filepath, "/dev")  == 0) continue;

                scanner_scan_directory(filepath, report);
            }
        } else if (S_ISREG(st.st_mode)) {
            /* C'est un fichier régulier */
            if (!scanner_is_valid_file(filepath)) continue;

            /* Agrandir le tableau de fichiers */
            report->total_files++;
            report->files = (FileReport *)realloc(
                report->files,
                report->total_files * sizeof(FileReport));

            if (!report->files) {
                fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                        "Mémoire insuffisante\n");
                closedir(dir);
                return -1;
            }

            /* Scanner le fichier */
            FileReport *fr = &report->files[
                report->total_files - 1];
            scanner_scan_file(filepath, fr);

            /* Mettre à jour les compteurs */
            switch (fr->final_result) {
                case RESULT_CLEAN:
                    report->clean_files++;
                    break;
                case RESULT_SUSPICIOUS:
                    report->suspicious_files++;
                    break;
                case RESULT_MALWARE:
                    report->malware_files++;
                    break;
                default:
                    report->error_files++;
            }

            /* Afficher progression */
            scanner_print_progress(
                report->total_files,
                report->total_files,
                entry->d_name);
        }
    }

    closedir(dir);
    return 0;
}

/* ============================================
   OBTENIR LES STATISTIQUES
   ============================================ */
void scanner_get_stats(ScannerStats *stats) {
    memcpy(stats, &g_stats, sizeof(ScannerStats));
}

/* ============================================
   NETTOYAGE
   ============================================ */
void scanner_cleanup(void) {
    clamav_cleanup(&g_clamav);
    database_close(&g_db);
    logger_write(LOG_INFO, "Scanner nettoyé");
}
