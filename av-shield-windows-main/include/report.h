#ifndef REPORT_H
#define REPORT_H

#include "common.h"

/* ============================================
   FORMAT DU RAPPORT
   ============================================ */
typedef enum {
    REPORT_JSON = 0,
    REPORT_HTML = 1,
    REPORT_TXT  = 2
} ReportFormat;

/* ============================================
   STRUCTURE MÉTADONNÉES RAPPORT
   ============================================ */
typedef struct {
    char report_id[64];
    char report_path[MAX_PATH_LEN];
    ReportFormat format;
    char generated_at[64];
    int success;
} ReportMetadata;

/* Fonctions */
int  report_generate(const ScanReport *scan, ReportFormat format);
int  report_generate_json(const ScanReport *scan, const char *output_path);
int  report_generate_html(const ScanReport *scan, const char *output_path);
int  report_generate_txt(const ScanReport *scan, const char *output_path);
void report_print_summary(const ScanReport *scan);
int  report_list(ReportMetadata *reports, int max_reports);
void report_print_list(void);

#endif
