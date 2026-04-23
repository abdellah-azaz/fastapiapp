#include "../include/clamav_engine.h"
#include "../include/logger.h"

/* ============================================
   INITIALISATION DU MOTEUR CLAMAV
   ============================================ */
int clamav_init(ClamavEngine *engine) {
    int rc;

    /* Initialiser la bibliothèque ClamAV */
    rc = cl_init(CL_INIT_DEFAULT);
    if (rc != CL_SUCCESS) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "ClamAV init échoué: %s\n", cl_strerror(rc));
        return -1;
    }

    /* Créer le moteur */
    engine->engine = cl_engine_new();
    if (!engine->engine) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Impossible de créer le moteur ClamAV\n");
        return -1;
    }

    /* Charger les bases de signatures */
    printf(COLOR_CYAN "[INFO]   " COLOR_RESET
           "Chargement des signatures ClamAV...\n");
    #ifdef _WIN32
    const char *db_path = "C:\\Program Files\\ClamAV\\database";
#else
    const char *db_path = cl_retdbdir();
#endif
    rc = cl_load(db_path, engine->engine,
                 &engine->signatures, CL_DB_STDOPT);
    if (rc != CL_SUCCESS) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Chargement signatures échoué: %s\n", cl_strerror(rc));
        cl_engine_free(engine->engine);
        return -1;
    }

    /* Compiler le moteur */
    /* Paramètres moteur */
    cl_engine_set_num(engine->engine,
                      CL_ENGINE_MAX_FILESIZE, 100 * 1048576);
    cl_engine_set_num(engine->engine,
                      CL_ENGINE_MAX_SCANSIZE, 400 * 1048576);

    rc = cl_engine_compile(engine->engine);
    if (rc != CL_SUCCESS) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Compilation moteur échouée: %s\n", cl_strerror(rc));
        cl_engine_free(engine->engine);
        return -1;
    }

    /* Sauvegarder la version */
    snprintf(engine->version, sizeof(engine->version),
             "%s", cl_retver());
    engine->initialized = 1;

    /* Afficher les informations */
    clamav_print_info(engine);

    char msg[128];
    snprintf(msg, sizeof(msg),
             "ClamAV initialisé: %u signatures chargées",
             engine->signatures);
    logger_write(LOG_INFO, msg);

    return 0;
}

/* ============================================
   SCANNER UN FICHIER AVEC CLAMAV
   ============================================ */
int clamav_scan_file(ClamavEngine *engine,
                     const char *filepath,
                     FileReport *report) {
    if (!engine->initialized) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Moteur ClamAV non initialisé\n");
        return -1;
    }

    /* Vérifier que le moteur est valide */
    if (!engine->engine) {
        report->clamav_result = RESULT_ERROR;
        return 0;
    }

    /* Vérifier que le fichier est lisible */
    if (access(filepath, R_OK) != 0) {
        report->clamav_result = RESULT_ERROR;
        return 0;
    }

    const char *virus_name = NULL;
    unsigned long scanned  = 0;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int rc = cl_scanfile(filepath,
                         &virus_name,
                         &scanned,
                         engine->engine,
                         &options);

    switch (rc) {
        case CL_CLEAN:
            report->clamav_result = RESULT_CLEAN;
            strncpy(report->threat_name, "None",
                    MAX_THREAT_NAME - 1);
            break;

        case CL_VIRUS:
            report->clamav_result = RESULT_MALWARE;
            if (virus_name) {
                strncpy(report->threat_name, virus_name,
                        MAX_THREAT_NAME - 1);
            }
            printf(COLOR_RED "\n[THREAT] " COLOR_RESET
                   "MALWARE DÉTECTÉ!\n");
            printf(COLOR_RED "         Fichier  : " COLOR_RESET
                   "%s\n", filepath);
            printf(COLOR_RED "         Menace   : " COLOR_RESET
                   "%s\n", virus_name ? virus_name : "Unknown");
            char msg[MAX_LOG_LEN];
            snprintf(msg, sizeof(msg),
                     "CLAMAV DETECTED: %s IN: %s",
                     virus_name ? virus_name : "Unknown",
                     filepath);
            logger_write(LOG_THREAT, msg);
            break;

        default:
            report->clamav_result = RESULT_ERROR;
            fprintf(stderr, COLOR_YELLOW "[WARN]   " COLOR_RESET
                    "Erreur scan ClamAV: %s — %s\n",
                    filepath, cl_strerror(rc));
            break;
    }
    return 0;
}

/* ============================================
   AFFICHER LES INFORMATIONS DU MOTEUR
   ============================================ */
void clamav_print_info(const ClamavEngine *engine) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════╗\n"
           COLOR_RESET);
    printf(COLOR_CYAN "║         MOTEUR CLAMAV CHARGÉ         ║\n"
           COLOR_RESET);
    printf(COLOR_CYAN "╠══════════════════════════════════════╣\n"
           COLOR_RESET);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Version    : %-25s" COLOR_CYAN "║\n" COLOR_RESET,
           engine->version);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Signatures : %-25u" COLOR_CYAN "║\n" COLOR_RESET,
           engine->signatures);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Statut     : " COLOR_GREEN "%-25s" COLOR_CYAN "║\n"
           COLOR_RESET, "ACTIF");
    printf(COLOR_CYAN "╚══════════════════════════════════════╝\n"
           COLOR_RESET);
    printf("\n");
}

/* ============================================
   NETTOYAGE DU MOTEUR
   ============================================ */
void clamav_cleanup(ClamavEngine *engine) {
    if (engine && engine->engine) {
        cl_engine_free(engine->engine);
        engine->engine      = NULL;
        engine->initialized = 0;
        logger_write(LOG_INFO, "Moteur ClamAV libéré");
    }
}
