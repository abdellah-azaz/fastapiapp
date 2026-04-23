#ifdef _WIN32
#include <direct.h>
#endif
#include "../include/quarantine.h"
#include "../include/logger.h"
#include <time.h>

/* ============================================
   INITIALISATION QUARANTAINE
   ============================================ */
int quarantine_init(void) {
    /* Créer le dossier quarantaine si inexistant */
    struct stat st = {0};
    if (stat(QUARANTINE_DIR, &st) == -1) {
        if (_mkdir(QUARANTINE_DIR) != 0) {
            fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                    "Impossible de créer le dossier quarantaine\n");
            return -1;
        }
    }

    /* Sécuriser le dossier quarantaine */
    chmod(QUARANTINE_DIR, 0700);

    logger_write(LOG_INFO, "Quarantaine initialisée");
    printf(COLOR_GREEN "[OK]     " COLOR_RESET
           "Dossier quarantaine prêt: %s\n", QUARANTINE_DIR);
    return 0;
}

/* ============================================
   GÉNÉRER UN NOM UNIQUE DE QUARANTAINE
   ============================================ */
static void generate_quarantine_name(const char *original_name,
                                      char *qname,
                                      size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);

    snprintf(qname, size, "QRN_%s_%s.quar",
             timestamp, original_name);
}

/* ============================================
   METTRE UN FICHIER EN QUARANTAINE
   ============================================ */
int quarantine_add(const FileReport *report) {
    char qname[MAX_FILENAME_LEN];
    char qpath[MAX_PATH_LEN];

    /* Générer le nom de quarantaine */
    generate_quarantine_name(report->filename, qname,
                              sizeof(qname));

    /* Construire le chemin complet */
    snprintf(qpath, sizeof(qpath), "%s%s",
             QUARANTINE_DIR, qname);

    /* Déplacer le fichier vers quarantaine */
    if (rename(report->filepath, qpath) != 0) {
        /* Si rename échoue (partitions différentes) */
        /* Copier puis supprimer */
        FILE *src = fopen(report->filepath, "rb");
        FILE *dst = fopen(qpath, "wb");

        if (!src || !dst) {
            if (src) fclose(src);
            if (dst) fclose(dst);
            fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                    "Quarantaine échouée pour: %s\n",
                    report->filepath);
            return -1;
        }

        /* Copier le contenu */
        unsigned char buffer[FILE_CHUNK_SIZE];
        size_t bytes;
        while ((bytes = fread(buffer, 1,
                              FILE_CHUNK_SIZE, src)) > 0) {
            fwrite(buffer, 1, bytes, dst);
        }

        fclose(src);
        fclose(dst);

        /* Supprimer l'original */
        remove(report->filepath);
    }

    /* Sécuriser — chmod 000 (aucun droit) */
    chmod(qpath, 0000);

    /* Afficher confirmation */
    printf(COLOR_RED "[QUARANTINE] " COLOR_RESET
           "Fichier isolé:\n");
    printf("             Original  : %s\n", report->filepath);
    printf("             Quarantine: %s\n", qpath);
    printf("             Menace    : %s\n", report->threat_name);

    /* Logger l'action */
    char msg[MAX_LOG_LEN];
    snprintf(msg, sizeof(msg),
             "QUARANTINE: %.200s → %.200s [%.100s]",
             report->filepath, qpath, report->threat_name);
    logger_write(LOG_AUDIT, msg);

    return 0;
}

/* ============================================
   RESTAURER UN FICHIER DEPUIS QUARANTAINE
   ============================================ */
int quarantine_restore(const char *quarantine_name,
                        const char *restore_path) {
    char qpath[MAX_PATH_LEN];
    snprintf(qpath, sizeof(qpath), "%s%s",
             QUARANTINE_DIR, quarantine_name);

    /* Vérifier que le fichier existe en quarantaine */
    struct stat st;
    if (stat(qpath, &st) == -1) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Fichier non trouvé en quarantaine: %s\n",
                quarantine_name);
        return -1;
    }

    /* Remettre les permissions pour pouvoir lire */
    chmod(qpath, 0600);

    /* Déplacer vers le chemin de restauration */
    if (rename(qpath, restore_path) != 0) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Restauration échouée: %s\n", quarantine_name);
        chmod(qpath, 0000); /* Remettre en sécurité */
        return -1;
    }

    printf(COLOR_GREEN "[RESTORE] " COLOR_RESET
           "Fichier restauré: %s → %s\n",
           quarantine_name, restore_path);

    /* Logger */
    char msg[MAX_LOG_LEN];
    snprintf(msg, sizeof(msg),
             "RESTORE: %s → %s", quarantine_name, restore_path);
    logger_write(LOG_AUDIT, msg);

    return 0;
}

/* ============================================
   SUPPRIMER UN FICHIER EN QUARANTAINE
   ============================================ */
int quarantine_delete(const char *quarantine_name) {
    char qpath[MAX_PATH_LEN];
    snprintf(qpath, sizeof(qpath), "%s%s",
             QUARANTINE_DIR, quarantine_name);

    /* Remettre permissions pour supprimer */
    chmod(qpath, 0600);

    if (remove(qpath) != 0) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Suppression échouée: %s\n", quarantine_name);
        return -1;
    }

    printf(COLOR_GREEN "[DELETE] " COLOR_RESET
           "Fichier supprimé définitivement: %s\n",
           quarantine_name);

    /* Logger */
    char msg[MAX_LOG_LEN];
    snprintf(msg, sizeof(msg),
             "DELETE: %s supprimé définitivement",
             quarantine_name);
    logger_write(LOG_AUDIT, msg);

    return 0;
}

/* ============================================
   LISTER LES FICHIERS EN QUARANTAINE
   ============================================ */
int quarantine_list(QuarantineEntry *entries, int max_entries) {
    DIR *dir = opendir(QUARANTINE_DIR);
    if (!dir) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Impossible d'ouvrir quarantaine\n");
        return -1;
    }

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL && count < max_entries) {
        /* Ignorer . et .. */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;

        /* Remplir l'entrée */
        strncpy(entries[count].quarantine_name,
                entry->d_name,
                MAX_FILENAME_LEN - 1);

        snprintf(entries[count].quarantine_path,
                 MAX_PATH_LEN,
                 "%s%s", QUARANTINE_DIR, entry->d_name);

        count++;
    }

    closedir(dir);
    return count;
}

/* ============================================
   AFFICHER LA LISTE QUARANTAINE
   ============================================ */
void quarantine_print_list(void) {
    DIR *dir = opendir(QUARANTINE_DIR);
    if (!dir) {
        printf(COLOR_YELLOW "[WARN]   " COLOR_RESET
               "Dossier quarantaine vide ou inexistant\n");
        return;
    }

    printf("\n");
    printf(COLOR_RED "╔══════════════════════════════════════════╗\n"
           COLOR_RESET);
    printf(COLOR_RED "║         FICHIERS EN QUARANTAINE          ║\n"
           COLOR_RESET);
    printf(COLOR_RED "╠══════════════════════════════════════════╣\n"
           COLOR_RESET);

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;

        printf(COLOR_RED "║ " COLOR_RESET
               "%-40s" COLOR_RED "║\n" COLOR_RESET,
               entry->d_name);
        count++;
    }

    if (count == 0) {
        printf(COLOR_RED "║ " COLOR_RESET
               "%-40s" COLOR_RED "║\n" COLOR_RESET,
               "Quarantaine vide");
    }

    printf(COLOR_RED "╠══════════════════════════════════════════╣\n"
           COLOR_RESET);
    printf(COLOR_RED "║ " COLOR_RESET
           "Total: %-34d" COLOR_RED "║\n" COLOR_RESET, count);
    printf(COLOR_RED "╚══════════════════════════════════════════╝\n"
           COLOR_RESET);
    printf("\n");

    closedir(dir);
}

/* ============================================
   COMPTER LES FICHIERS EN QUARANTAINE
   ============================================ */
int quarantine_count(void) {
    DIR *dir = opendir(QUARANTINE_DIR);
    if (!dir) return 0;

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            count++;
        }
    }

    closedir(dir);
    return count;
}

/* ============================================
   NETTOYAGE
   ============================================ */
void quarantine_cleanup(void) {
    logger_write(LOG_INFO, "Module quarantaine fermé");
}
