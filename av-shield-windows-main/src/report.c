#include "../include/report.h"
#include "../include/logger.h"
#include "../include/correlation.h"
#include <time.h>

/* ============================================
   OBTENIR L'HEURE ACTUELLE
   ============================================ */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* ============================================
   GÉNÉRER UN ID UNIQUE DE RAPPORT
   ============================================ */
static void generate_report_id(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "RPT_%Y%m%d_%H%M%S", tm_info);
}

/* ============================================
   GÉNÉRER LE RAPPORT (DISPATCHER)
   ============================================ */
int report_generate(const ScanReport *scan, ReportFormat format) {
    char report_id[64];
    char output_path[MAX_PATH_LEN];

    generate_report_id(report_id, sizeof(report_id));

    switch (format) {
        case REPORT_JSON:
            snprintf(output_path, sizeof(output_path),
                     "%s%s.json", REPORTS_DIR, report_id);
            return report_generate_json(scan, output_path);

        case REPORT_HTML:
            snprintf(output_path, sizeof(output_path),
                     "%s%s.html", REPORTS_DIR, report_id);
            return report_generate_html(scan, output_path);

        case REPORT_TXT:
            snprintf(output_path, sizeof(output_path),
                     "%s%s.txt", REPORTS_DIR, report_id);
            return report_generate_txt(scan, output_path);

        default:
            return -1;
    }
}

/* ============================================
   RAPPORT JSON
   ============================================ */
int report_generate_json(const ScanReport *scan,
                          const char *output_path) {
    FILE *f = fopen(output_path, "w");
    if (!f) {
        fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET
                "Impossible de créer: %s\n", output_path);
        return -1;
    }

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    /* Début JSON */
    fprintf(f, "{\n");
    fprintf(f, "  \"av_shield\": \"%s v%s\",\n",
            AV_NAME, AV_VERSION);
    fprintf(f, "  \"report_id\": \"%s\",\n", scan->scan_id);
    fprintf(f, "  \"generated_at\": \"%s\",\n", timestamp);
    fprintf(f, "  \"scan_target\": \"%s\",\n", scan->target_path);
    fprintf(f, "  \"start_time\": \"%s\",\n", scan->start_time);
    fprintf(f, "  \"end_time\": \"%s\",\n", scan->end_time);
    fprintf(f, "  \"scan_duration\": %.2f,\n", scan->scan_duration);

    /* Statistiques */
    fprintf(f, "  \"statistics\": {\n");
    fprintf(f, "    \"total_files\": %d,\n", scan->total_files);
    fprintf(f, "    \"clean_files\": %d,\n", scan->clean_files);
    fprintf(f, "    \"suspicious_files\": %d,\n",
            scan->suspicious_files);
    fprintf(f, "    \"malware_files\": %d,\n", scan->malware_files);
    fprintf(f, "    \"error_files\": %d\n", scan->error_files);
    fprintf(f, "  },\n");

    /* Fichiers scannés */
    fprintf(f, "  \"files\": [\n");
    if (scan->files && scan->total_files > 0) {
        for (int i = 0; i < scan->total_files; i++) {
            const FileReport *fr = &scan->files[i];
            fprintf(f, "    {\n");
            fprintf(f, "      \"filename\": \"%s\",\n",
                    fr->filename);
            fprintf(f, "      \"filepath\": \"%s\",\n",
                    fr->filepath);
            fprintf(f, "      \"filesize\": %ld,\n",
                    fr->filesize);
            fprintf(f, "      \"sha256\": \"%s\",\n",
                    fr->sha256);
            fprintf(f, "      \"result\": \"%s\",\n",
                    correlation_result_to_string(fr->final_result));
            fprintf(f, "      \"threat\": \"%s\",\n",
                    fr->threat_name);
            fprintf(f, "      \"heuristic_score\": %d,\n",
                    fr->heuristic_score);
            fprintf(f, "      \"entropy\": %.4f,\n",
                    fr->entropy);
            fprintf(f, "      \"quarantined\": %s\n",
                    fr->quarantined ? "true" : "false");
            fprintf(f, "    }%s\n",
                    (i < scan->total_files - 1) ? "," : "");
        }
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    fclose(f);

    printf(COLOR_GREEN "[REPORT] " COLOR_RESET
           "Rapport JSON généré: %s\n", output_path);
    logger_write(LOG_INFO, "Rapport JSON généré");
    return 0;
}

/* ============================================
   RAPPORT HTML
   ============================================ */
int report_generate_html(const ScanReport *scan,
                          const char *output_path) {
    FILE *f = fopen(output_path, "w");
    if (!f) return -1;

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(f,
        "<!DOCTYPE html>\n"
        "<html lang='fr'>\n"
        "<head>\n"
        "<meta charset='UTF-8'>\n"
        "<title>AV-Shield Report</title>\n"
        "<style>\n"
        "body{font-family:Arial,sans-serif;"
        "background:#1a1a2e;color:#eee;margin:20px}\n"
        "h1{color:#00d4ff;text-align:center}\n"
        "h2{color:#00d4ff}\n"
        ".card{background:#16213e;border-radius:8px;"
        "padding:20px;margin:10px 0}\n"
        ".clean{color:#00ff88}\n"
        ".suspicious{color:#ffaa00}\n"
        ".malware{color:#ff4444}\n"
        "table{width:100%%;border-collapse:collapse}\n"
        "th{background:#0f3460;padding:10px;text-align:left}\n"
        "td{padding:8px;border-bottom:1px solid #333}\n"
        ".stat{display:inline-block;margin:10px;"
        "padding:15px;background:#0f3460;"
        "border-radius:8px;min-width:120px;text-align:center}\n"
        ".stat-num{font-size:2em;font-weight:bold}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n");

    /* Titre */
    fprintf(f,
        "<h1>🛡️ AV-Shield Rapport d'Analyse</h1>\n"
        "<div class='card'>\n"
        "<p><b>Rapport ID:</b> %s</p>\n"
        "<p><b>Cible:</b> %s</p>\n"
        "<p><b>Généré le:</b> %s</p>\n"
        "<p><b>Durée:</b> %.2f secondes</p>\n"
        "</div>\n",
        scan->scan_id, scan->target_path,
        timestamp, scan->scan_duration);

    /* Statistiques */
    fprintf(f, "<div class='card'><h2>📊 Statistiques</h2>\n");
    fprintf(f,
        "<div class='stat'>"
        "<div class='stat-num'>%d</div>Total</div>\n",
        scan->total_files);
    fprintf(f,
        "<div class='stat clean'>"
        "<div class='stat-num'>%d</div>Propres</div>\n",
        scan->clean_files);
    fprintf(f,
        "<div class='stat suspicious'>"
        "<div class='stat-num'>%d</div>Suspects</div>\n",
        scan->suspicious_files);
    fprintf(f,
        "<div class='stat malware'>"
        "<div class='stat-num'>%d</div>Malwares</div>\n",
        scan->malware_files);
    fprintf(f, "</div>\n");

    /* Tableau des fichiers */
    fprintf(f,
        "<div class='card'><h2>📁 Fichiers Analysés</h2>\n"
        "<table>\n"
        "<tr><th>Fichier</th><th>Résultat</th>"
        "<th>Menace</th><th>SHA-256</th>"
        "<th>Heuristique</th><th>Entropie</th></tr>\n");

    if (scan->files) {
        for (int i = 0; i < scan->total_files; i++) {
            const FileReport *fr = &scan->files[i];
            const char *css_class =
                (fr->final_result == RESULT_MALWARE)    ? "malware" :
                (fr->final_result == RESULT_SUSPICIOUS) ? "suspicious" :
                "clean";
            const char *result_str =
                correlation_result_to_string(fr->final_result);

            fprintf(f,
                "<tr class='%s'>"
                "<td>%s</td>"
                "<td class='%s'><b>%s</b></td>"
                "<td>%s</td>"
                "<td style='font-size:0.7em'>%.16s...</td>"
                "<td>%d</td>"
                "<td>%.4f</td>"
                "</tr>\n",
                css_class,
                fr->filename,
                css_class, result_str,
                fr->threat_name,
                fr->sha256,
                fr->heuristic_score,
                fr->entropy);
        }
    }

    fprintf(f,
        "</table></div>\n"
        "<div style='text-align:center;margin-top:20px;"
        "color:#666'>"
        "<p>AV-Shield v%s — Rapport généré le %s</p>"
        "</div>\n"
        "</body></html>\n",
        AV_VERSION, timestamp);

    fclose(f);

    printf(COLOR_GREEN "[REPORT] " COLOR_RESET
           "Rapport HTML généré: %s\n", output_path);
    logger_write(LOG_INFO, "Rapport HTML généré");
    return 0;
}

/* ============================================
   RAPPORT TXT
   ============================================ */
int report_generate_txt(const ScanReport *scan,
                         const char *output_path) {
    FILE *f = fopen(output_path, "w");
    if (!f) return -1;

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(f, "================================================\n");
    fprintf(f, "   AV-SHIELD v%s — RAPPORT D'ANALYSE\n", AV_VERSION);
    fprintf(f, "================================================\n");
    fprintf(f, "Rapport ID : %s\n", scan->scan_id);
    fprintf(f, "Cible      : %s\n", scan->target_path);
    fprintf(f, "Généré le  : %s\n", timestamp);
    fprintf(f, "Durée      : %.2f secondes\n", scan->scan_duration);
    fprintf(f, "------------------------------------------------\n");
    fprintf(f, "STATISTIQUES:\n");
    fprintf(f, "  Total fichiers  : %d\n", scan->total_files);
    fprintf(f, "  Fichiers propres: %d\n", scan->clean_files);
    fprintf(f, "  Suspects        : %d\n", scan->suspicious_files);
    fprintf(f, "  Malwares        : %d\n", scan->malware_files);
    fprintf(f, "------------------------------------------------\n");
    fprintf(f, "FICHIERS ANALYSÉS:\n\n");

    if (scan->files) {
        for (int i = 0; i < scan->total_files; i++) {
            const FileReport *fr = &scan->files[i];
            fprintf(f, "[%s] %s\n",
                    correlation_result_to_string(fr->final_result),
                    fr->filename);
            if (fr->final_result != RESULT_CLEAN) {
                fprintf(f, "     Menace    : %s\n",
                        fr->threat_name);
                fprintf(f, "     SHA-256   : %s\n",
                        fr->sha256);
                fprintf(f, "     Heurist.  : %d/100\n",
                        fr->heuristic_score);
                fprintf(f, "     Entropie  : %.4f\n",
                        fr->entropy);
                fprintf(f, "     Quarant.  : %s\n",
                        fr->quarantined ? "OUI" : "NON");
            }
        }
    }

    fprintf(f, "================================================\n");
    fprintf(f, "FIN DU RAPPORT — AV-Shield v%s\n", AV_VERSION);
    fprintf(f, "================================================\n");

    fclose(f);

    printf(COLOR_GREEN "[REPORT] " COLOR_RESET
           "Rapport TXT généré: %s\n", output_path);
    return 0;
}

/* ============================================
   AFFICHER RÉSUMÉ DANS LE TERMINAL
   ============================================ */
void report_print_summary(const ScanReport *scan) {
    printf("\n");
    printf(COLOR_CYAN
           "╔══════════════════════════════════════════╗\n"
           COLOR_RESET);
    printf(COLOR_CYAN
           "║         AV-SHIELD RÉSUMÉ DU SCAN         ║\n"
           COLOR_RESET);
    printf(COLOR_CYAN
           "╠══════════════════════════════════════════╣\n"
           COLOR_RESET);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Cible    : %-32s" COLOR_CYAN "║\n" COLOR_RESET,
           scan->target_path);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Durée    : %-8.2fs" COLOR_CYAN
           "                       ║\n" COLOR_RESET,
           scan->scan_duration);
    printf(COLOR_CYAN
           "╠══════════════════════════════════════════╣\n"
           COLOR_RESET);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Total    : " COLOR_WHITE "%-30d" COLOR_RESET
           COLOR_CYAN "║\n" COLOR_RESET, scan->total_files);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Propres  : " COLOR_GREEN "%-30d" COLOR_RESET
           COLOR_CYAN "║\n" COLOR_RESET, scan->clean_files);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Suspects : " COLOR_YELLOW "%-30d" COLOR_RESET
           COLOR_CYAN "║\n" COLOR_RESET, scan->suspicious_files);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Malwares : " COLOR_RED "%-30d" COLOR_RESET
           COLOR_CYAN "║\n" COLOR_RESET, scan->malware_files);
    printf(COLOR_CYAN
           "╚══════════════════════════════════════════╝\n"
           COLOR_RESET);
    printf("\n");
}

/* ============================================
   LISTER LES RAPPORTS
   ============================================ */
void report_print_list(void) {
    DIR *dir = opendir(REPORTS_DIR);
    if (!dir) {
        printf(COLOR_YELLOW "[WARN] " COLOR_RESET
               "Aucun rapport trouvé\n");
        return;
    }

    printf("\n" COLOR_CYAN
           "╔══════════════════════════════════════╗\n"
           COLOR_RESET);
    printf(COLOR_CYAN
           "║           RAPPORTS GÉNÉRÉS           ║\n"
           COLOR_RESET);
    printf(COLOR_CYAN
           "╠══════════════════════════════════════╣\n"
           COLOR_RESET);

    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;
        printf(COLOR_CYAN "║ " COLOR_RESET
               "%-36s" COLOR_CYAN "║\n" COLOR_RESET,
               entry->d_name);
        count++;
    }

    printf(COLOR_CYAN
           "╠══════════════════════════════════════╣\n"
           COLOR_RESET);
    printf(COLOR_CYAN "║ " COLOR_RESET
           "Total: %-31d" COLOR_CYAN "║\n" COLOR_RESET, count);
    printf(COLOR_CYAN
           "╚══════════════════════════════════════╝\n"
           COLOR_RESET);
    closedir(dir);
}
