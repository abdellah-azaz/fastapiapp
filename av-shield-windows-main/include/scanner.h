#ifndef SCANNER_H
#define SCANNER_H

#include "common.h"

/* Configuration du scanner */
typedef struct {
    int recursive;          
    int scan_hidden;        
    long max_file_size;     
    int follow_symlinks;    
    int quarantine_auto;    
} ScannerConfig;

/* Statistiques en temps réel */
typedef struct {
    int files_scanned;      
    int dirs_scanned;       
    int files_skipped;      
    long total_bytes;       
} ScannerStats;

/* Fonctions */
int  scanner_init(ScannerConfig *config);
int  scanner_scan_file(const char *filepath, FileReport *report);
int  scanner_scan_directory(const char *dirpath, ScanReport *report);
int  scanner_is_valid_file(const char *filepath);
void scanner_get_stats(ScannerStats *stats);
void scanner_print_progress(int current, int total, const char *filename);
void scanner_cleanup(void);

#endif
