#include "../include/common.h"
#include "../include/logger.h"
#include "../include/scanner.h"
#include "../include/quarantine.h"
#include "../include/report.h"
#include "../include/database.h"
#include <time.h>

/* ============================================
   AFFICHER LA BANNIÈRE
   ============================================ */
static void print_banner(void) {
    printf("\n");
    printf(COLOR_CYAN
    "  ╔═══════════════════════════════════════════╗\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "  ║   █████╗ ██╗   ██╗    ███████╗██╗  ██╗   ║\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "  ║  ██╔══██╗██║   ██║    ██╔════╝██║  ██║   ║\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "  ║  ███████║██║   ██║    ███████╗███████║   ║\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "  ║  ██╔══██║╚██╗ ██╔╝    ╚════██║██╔══██║   ║\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "  ║  ██║  ██║ ╚████╔╝     ███████║██║  ██║   ║\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "  ║  ╚═╝  ╚═╝  ╚═══╝      ╚══════╝╚═╝  ╚═╝   ║\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "  ╠═══════════════════════════════════════════╣\n"
    COLOR_RESET);
    printf(COLOR_CYAN "  ║  " COLOR_RESET
    "%-43s" COLOR_CYAN "║\n" COLOR_RESET,
    "  Antivirus Multi-Couches v" AV_VERSION);
    printf(COLOR_CYAN "  ║  " COLOR_RESET
    COLOR_GREEN "%-43s" COLOR_RESET COLOR_CYAN "║\n" COLOR_RESET,
    "  ClamAV + SHA256 + Heuristique + Entropie");
    printf(COLOR_CYAN
    "  ╚═══════════════════════════════════════════╝\n"
    COLOR_RESET);
    printf("\n");
}

/* ============================================
   AFFICHER L'AIDE
   ============================================ */
static void print_help(void) {
    printf("\n");
    printf(COLOR_CYAN "USAGE:\n" COLOR_RESET);
    printf("  ./avshield <commande> [options]\n\n");

    printf(COLOR_CYAN "COMMANDES:\n" COLOR_RESET);
    printf("  " COLOR_GREEN "scan <chemin>" COLOR_RESET
           "              Scanner un fichier ou dossier\n");
    printf("  " COLOR_GREEN "scan <chemin> --auto" COLOR_RESET
           "       Scanner + quarantaine automatique\n");
    printf("  " COLOR_GREEN "scan <chemin> --report" COLOR_RESET
           "     Scanner + générer rapport JSON\n");
    printf("  " COLOR_GREEN "scan <chemin> --html" COLOR_RESET
           "       Scanner + générer rapport HTML\n");
    printf("  " COLOR_GREEN "quarantine list" COLOR_RESET
           "            Lister les fichiers en quarantaine\n");
    printf("  " COLOR_GREEN "quarantine restore <nom>" COLOR_RESET
           "   Restaurer un fichier\n");
    printf("  " COLOR_GREEN "quarantine delete <nom>" COLOR_RESET
           "    Supprimer un fichier en quarantaine\n");
    printf("  " COLOR_GREEN "report list" COLOR_RESET
           "                Lister les rapports\n");
    printf("  " COLOR_GREEN "stats" COLOR_RESET
           "                      Afficher les statistiques\n");
    printf("  " COLOR_GREEN "history" COLOR_RESET
           "                    Historique des scans\n");
    printf("  " COLOR_GREEN "help" COLOR_RESET
           "                       Afficher cette aide\n");

    printf("\n");
    printf(COLOR_CYAN "EXEMPLES:\n" COLOR_RESET);
    printf("  ./avshield scan /home/fatima/Downloads\n");
    printf("  ./avshield scan /home/fatima/fichier.exe --auto\n");
    printf("  ./avshield scan /home/fatima --report\n");
    printf("  ./avshield quarantine list\n");
    printf("  ./avshield stats\n");
    printf("\n");
}

/* ============================================
   COMMANDE SCAN
   ============================================ */
static int cmd_scan(const char *path, int auto_quarantine,
                     int gen_report, int gen_html, int gen_txt, ReportFormat fmt) {
    struct stat st;

    /* Vérifier que le chemin existe */
    if (stat(path, &st) != 0) {
        printf(COLOR_RED "[ERROR] " COLOR_RESET
               "Chemin introuvable: %s\n", path);
        return -1;
    }

    /* Configurer le scanner */
    ScannerConfig config = {
        .recursive       = 1,
        .scan_hidden     = 0,
        .max_file_size   = MAX_FILE_SIZE,
        .follow_symlinks = 0,
        .quarantine_auto = auto_quarantine
    };

    /* Initialiser le scanner */
    if (scanner_init(&config) != 0) return -1;

    /* Initialiser le rapport */
    ScanReport report;
    memset(&report, 0, sizeof(ScanReport));

    /* Générer l'ID du scan */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(report.scan_id, sizeof(report.scan_id),
             "SCAN_%Y%m%d_%H%M%S", tm_info);
    strftime(report.start_time, sizeof(report.start_time),
             "%Y-%m-%d %H:%M:%S", tm_info);
    strncpy(report.target_path, path, MAX_PATH_LEN - 1);

    /* Démarrer le chronomètre */
    clock_t start = clock();

    printf(COLOR_CYAN "\n[AV-SHIELD] " COLOR_RESET
           "Démarrage du scan: %s\n\n", path);

    /* Lancer le scan */
    if (S_ISDIR(st.st_mode)) {
        /* Scanner un dossier */
        scanner_scan_directory(path, &report);
    } else {
        /* Scanner un seul fichier */
        report.files = (FileReport *)malloc(sizeof(FileReport));
        if (!report.files) return -1;

        scanner_scan_file(path, &report.files[0]);
        report.total_files = 1;

        switch (report.files[0].final_result) {
            case RESULT_CLEAN:
                report.clean_files = 1;
                break;
            case RESULT_SUSPICIOUS:
                report.suspicious_files = 1;
                break;
            case RESULT_MALWARE:
                report.malware_files = 1;
                break;
            default:
                report.error_files = 1;
        }
    }

    /* Arrêter le chronomètre */
    clock_t end = clock();
    report.scan_duration = (double)(end - start) / CLOCKS_PER_SEC;

    /* Heure de fin */
    now = time(NULL);
    tm_info = localtime(&now);
    strftime(report.end_time, sizeof(report.end_time),
             "%Y-%m-%d %H:%M:%S", tm_info);

    /* Afficher le résumé */
    printf("\n");
    report_print_summary(&report);

    /* Générer le rapport si demandé */
    if (gen_report) {
        report_generate(&report, REPORT_JSON);
    }
    if (gen_html) {
        report_generate(&report, REPORT_HTML);
    }
    if (gen_txt) {
        report_generate(&report, REPORT_TXT);
    }

    /* Sauvegarder le scan en base */
    Database db;
    if (database_init(&db) == 0) {
        database_save_scan(&db, &report);
        database_save_audit(&db, "SCAN_COMPLETE",
                            path, "fatima");
        database_close(&db);
    }

    /* Libérer la mémoire */
    if (report.files) free(report.files);

    /* Nettoyage */
    scanner_cleanup();

    return 0;
}

/* ============================================
   COMMANDE STATS
   ============================================ */
static void cmd_stats(void) {
    Database db;
    if (database_init(&db) == 0) {
        database_print_stats(&db);
        database_close(&db);
    }
}

/* ============================================
   COMMANDE HISTORY
   ============================================ */
static void cmd_history(void) {
    Database db;
    if (database_init(&db) != 0) return;

    ScanHistory history[20];
    int count = database_get_scan_history(
                    &db, history, 20);

    printf("\n");
    printf(COLOR_CYAN
    "╔══════════════════════════════════════════════════╗\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "║              HISTORIQUE DES SCANS                ║\n"
    COLOR_RESET);
    printf(COLOR_CYAN
    "╠══════════════════════════════════════════════════╣\n"
    COLOR_RESET);

    if (count <= 0) {
        printf(COLOR_CYAN "║ " COLOR_RESET
               "%-48s" COLOR_CYAN "║\n" COLOR_RESET,
               "Aucun scan effectué");
    } else {
        for (int i = 0; i < count; i++) {
            printf(COLOR_CYAN "║ " COLOR_RESET
                   "%-48s" COLOR_CYAN "║\n" COLOR_RESET,
                   history[i].scan_id);
            printf(COLOR_CYAN "║ " COLOR_RESET
                   "  Cible  : %-38s"
                   COLOR_CYAN "║\n" COLOR_RESET,
                   history[i].target_path);
            printf(COLOR_CYAN "║ " COLOR_RESET
                   "  Total  : %-5d | "
                   COLOR_RED "Malwares: %-5d" COLOR_RESET
                   "          " COLOR_CYAN "║\n" COLOR_RESET,
                   history[i].total_files,
                   history[i].malware_files);
            printf(COLOR_CYAN
            "║──────────────────────────────────────────────────║\n"
            COLOR_RESET);
        }
    }

    printf(COLOR_CYAN
    "╚══════════════════════════════════════════════════╝\n"
    COLOR_RESET);

    database_close(&db);
}

/* ============================================
   POINT D'ENTRÉE PRINCIPAL
   ============================================ */
int main(int argc, char *argv[]) {
    /* Afficher la bannière */
    print_banner();

    /* Initialiser le logger */
    if (logger_init() != 0) {
        fprintf(stderr, "Impossible d'initialiser le logger\n");
        return 1;
    }

    logger_write(LOG_INFO, "AV-Shield démarré");
    logger_audit("START", "avshield");

    /* Vérifier les arguments */
    if (argc < 2) {
        print_help();
        logger_close();
        return 0;
    }

    /* ---- COMMANDE: scan ---- */
    if (strcmp(argv[1], "scan") == 0) {
        if (argc < 3) {
            printf(COLOR_RED "[ERROR] " COLOR_RESET
                   "Usage: ./avshield scan <chemin>\n");
            logger_close();
            return 1;
        }

        /* Options */
        int auto_q    = 0;
        int gen_rep   = 0;
        int gen_html  = 0;
        int gen_txt   = 0;
        ReportFormat fmt = REPORT_JSON;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--auto")   == 0) auto_q   = 1;
            if (strcmp(argv[i], "--report") == 0) gen_rep  = 1;
            if (strcmp(argv[i], "--html")   == 0) gen_html = 1;
            if (strcmp(argv[i], "--txt")    == 0) gen_txt  = 1;
        }
        cmd_scan(argv[2], auto_q, gen_rep, gen_html, gen_txt, fmt);
    }

    /* ---- COMMANDE: quarantine ---- */
    else if (strcmp(argv[1], "quarantine") == 0) {
        if (argc < 3) {
            quarantine_print_list();
        }
        else if (strcmp(argv[2], "list") == 0) {
            quarantine_print_list();
        }
        else if (strcmp(argv[2], "restore") == 0 && argc >= 4) {
            /* Restaurer vers le dossier courant */
            char restore_path[MAX_PATH_LEN];
            snprintf(restore_path, sizeof(restore_path),
                     "./%s", argv[3]);
            if (quarantine_restore(argv[3],
                                   restore_path) == 0) {
                /* Mettre à jour la base */
                Database db;
                if (database_init(&db) == 0) {
                    database_update_quarantine_restored(
                        &db, argv[3]);
                    database_save_audit(&db, "RESTORE",
                                        argv[3], "fatima");
                    database_close(&db);
                }
            }
        }
        else if (strcmp(argv[2], "delete") == 0 && argc >= 4) {
            quarantine_delete(argv[3]);
        }
        else {
            printf(COLOR_RED "[ERROR] " COLOR_RESET
                   "Commande quarantaine invalide\n");
        }
    }

    /* ---- COMMANDE: report ---- */
    else if (strcmp(argv[1], "report") == 0) {
        if (argc < 3 || strcmp(argv[2], "list") == 0) {
            report_print_list();
        }
    }

    /* ---- COMMANDE: stats ---- */
    else if (strcmp(argv[1], "stats") == 0) {
        cmd_stats();
    }

    /* ---- COMMANDE: history ---- */
    else if (strcmp(argv[1], "history") == 0) {
        cmd_history();
    }

    /* ---- COMMANDE: help ---- */
    else if (strcmp(argv[1], "help") == 0) {
        print_help();
    }

    /* ---- COMMANDE INCONNUE ---- */
    else {
        printf(COLOR_RED "[ERROR] " COLOR_RESET
               "Commande inconnue: %s\n", argv[1]);
        print_help();
        logger_close();
        return 1;
    }

    logger_write(LOG_INFO, "AV-Shield terminé");
    logger_close();
    return 0;
}
