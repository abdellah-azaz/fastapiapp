#ifndef QUARANTINE_H
#define QUARANTINE_H

/* ============================================
   Sécurité: chmod 000 + renommage + chiffrement nom
   ============================================ */

#include "common.h"

/* ============================================
   STRUCTURE D'UN FICHIER EN QUARANTAINE
   ============================================ */
typedef struct {
    char original_path[MAX_PATH_LEN];
    char quarantine_path[MAX_PATH_LEN];
    char original_name[MAX_FILENAME_LEN];
    char quarantine_name[MAX_FILENAME_LEN];
    char sha256[MAX_HASH_LEN];
    char threat_name[MAX_THREAT_NAME];
    char quarantine_date[64];
    long filesize;
    int restored;
} QuarantineEntry;

/* Fonctions */
int  quarantine_init(void);
int  quarantine_add(const FileReport *report);
int  quarantine_restore(const char *quarantine_name, const char *restore_path);
int  quarantine_delete(const char *quarantine_name);
int  quarantine_list(QuarantineEntry *entries, int max_entries);
void quarantine_print_list(void);
int  quarantine_count(void);
void quarantine_cleanup(void);

#endif
