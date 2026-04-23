#include "../include/correlation.h"
#include "../include/clamav_engine.h"
#include "../include/hash.h"
#include "../include/logger.h"

/* ============================================
   ANALYSE COMPLÈTE MULTI-COUCHES
   ============================================ */
int correlation_analyze(const char *filepath, FileReport *report) {
    HeuristicResult heuristic;
    EntropyResult   entropy;
    CorrelationResult corr;

    /* Initialiser */
    memset(&heuristic, 0, sizeof(heuristic));
    memset(&entropy,   0, sizeof(entropy));
    memset(&corr,      0, sizeof(corr));

    /* ---- COUCHE 1 : Hash SHA-256 ---- */
    printf(COLOR_BLUE "[SHA-256]   " COLOR_RESET
           "Calcul empreinte...\n");
    if (hash_sha256_file(filepath, report->sha256) != 0) {
        strncpy(report->sha256, "ERROR", MAX_HASH_LEN - 1);
    }

    /* ---- COUCHE 2 : Heuristique ---- */
    printf(COLOR_CYAN "[HEURISTIC] " COLOR_RESET
           "Analyse comportementale...\n");
    heuristic_analyze(filepath, &heuristic);
    report->heuristic_result = heuristic.result;
    report->heuristic_score  = heuristic.total_score;

    /* ---- COUCHE 3 : Entropie ---- */
    printf(COLOR_CYAN "[ENTROPY]   " COLOR_RESET
           "Calcul entropie Shannon...\n");
    entropy_calculate(filepath, &entropy);
    report->entropy = entropy.value;

    /* Remplir la structure de corrélation */
    corr.clamav_result    = report->clamav_result;
    corr.heuristic_result = heuristic.result;
    corr.entropy_result   = entropy.result;
    corr.heuristic_score  = heuristic.total_score;
    corr.entropy_value    = entropy.value;

    strncpy(corr.threat_name, report->threat_name,
            MAX_THREAT_NAME - 1);

    /* ---- DÉCISION FINALE ---- */
    correlation_decide(&corr);

    /* Copier la décision dans le rapport */
    report->final_result = corr.final_result;

    /* Afficher le résultat */
    correlation_print_result(&corr);

    /* Logger */
    char msg[MAX_LOG_LEN];
    snprintf(msg, sizeof(msg),
             "Corrélation: %s → %s (confiance: %d%%)",
             report->filename,
             correlation_result_to_string(corr.final_result),
             corr.confidence);
    logger_write(LOG_INFO, msg);

    return 0;
}

/* ============================================
   MOTEUR DE DÉCISION FINALE
   ============================================ */
int correlation_decide(CorrelationResult *result) {

    /* Cas 1 : ClamAV détecte → verdict MALWARE MAIS on conserve heuristique+entropie */
    if (result->clamav_result == RESULT_MALWARE) {
        result->final_result = RESULT_MALWARE;
        result->confidence   = 95;

        /* reason détaillée avec heuristique + entropie */
        snprintf(result->reason, sizeof(result->reason),
                 "ClamAV: %s | Heur=%d/100 | Ent=%.4f",
                 result->threat_name,
                 result->heuristic_score,
                 result->entropy_value);

        return 0; /* on peut return, car heur/entropie sont déjà calculées */
    }

    /* RÈGLE 2 — Heuristique + Entropie élevés */
    if (result->heuristic_score >= 80 &&
        result->entropy_value   >= ENTROPY_THRESHOLD) {

        result->final_result = RESULT_MALWARE;
        result->confidence   = 80;

        snprintf(result->reason, sizeof(result->reason),
                 "Score heuristique critique (%d) + Entropie critique (%.2f)",
                 result->heuristic_score,
                 result->entropy_value);

        strncpy(result->threat_name, "Suspected.Malware.Obfuscated",
                MAX_THREAT_NAME - 1);
        return 0;
    }

    /* RÈGLE 3 — Heuristique élevé seul */
    if (result->heuristic_score >= HEURISTIC_THRESHOLD) {
        result->final_result = RESULT_SUSPICIOUS;
        result->confidence   = 65;

        snprintf(result->reason, sizeof(result->reason),
                 "Score heuristique élevé: %d/100 (seuil: %d)",
                 result->heuristic_score,
                 HEURISTIC_THRESHOLD);

        strncpy(result->threat_name, "Suspected.Heuristic.Threat",
                MAX_THREAT_NAME - 1);
        return 0;
    }

    /* RÈGLE 4 — Entropie critique seule */
    if (result->entropy_value >= ENTROPY_THRESHOLD) {
        result->final_result = RESULT_SUSPICIOUS;
        result->confidence   = 55;

        snprintf(result->reason, sizeof(result->reason),
                 "Entropie critique: %.4f (seuil: %.1f)",
                 result->entropy_value, ENTROPY_THRESHOLD);

        strncpy(result->threat_name, "Suspected.Entropy.Anomaly",
                MAX_THREAT_NAME - 1);
        return 0;
    }

    /* RÈGLE 5 — CLEAN */
    result->final_result = RESULT_CLEAN;
    result->confidence   = 90;

    snprintf(result->reason, sizeof(result->reason),
             "CLEAN | Heur=%d/100 | Ent=%.4f",
             result->heuristic_score,
             result->entropy_value);

    strncpy(result->threat_name, "None", MAX_THREAT_NAME - 1);
    return 0;
}

/* ============================================
   AFFICHER LE RÉSULTAT FINAL
   ============================================ */
void correlation_print_result(const CorrelationResult *result) {
    const char *color;
    const char *label;

    switch (result->final_result) {
        case RESULT_MALWARE:
            color = COLOR_RED;
            label = "MALWARE";
            break;
        case RESULT_SUSPICIOUS:
            color = COLOR_YELLOW;
            label = "SUSPICIOUS";
            break;
        case RESULT_CLEAN:
            color = COLOR_GREEN;
            label = "CLEAN";
            break;
        default:
            color = COLOR_WHITE;
            label = "ERROR";
    }

    printf("\n");
    printf(COLOR_WHITE "┌─────────────────────────────────────┐\n"
           COLOR_RESET);
    printf(COLOR_WHITE "│         DÉCISION FINALE              │\n"
           COLOR_RESET);
    printf(COLOR_WHITE "├─────────────────────────────────────┤\n"
           COLOR_RESET);
    printf(COLOR_WHITE "│ " COLOR_RESET
           "Résultat  : %s%-10s" COLOR_RESET
           COLOR_WHITE "                  │\n" COLOR_RESET,
           color, label);
    printf(COLOR_WHITE "│ " COLOR_RESET
           "Confiance : %s%d%%"  COLOR_RESET
           COLOR_WHITE "                       │\n" COLOR_RESET,
           color, result->confidence);

    if (result->final_result != RESULT_CLEAN) {
        printf(COLOR_WHITE "│ " COLOR_RESET
               "Menace    : %-35s"
               COLOR_WHITE "│\n" COLOR_RESET,
               result->threat_name);
    }

    printf(COLOR_WHITE "│ " COLOR_RESET
           "Raison    : %-35s"
           COLOR_WHITE "│\n" COLOR_RESET,
           result->reason);
    printf(COLOR_WHITE "│ " COLOR_RESET
           "ClamAV    : %-10s"
           " Heuristique: %-5d"
           " Entropie: %-5.2f"
           COLOR_WHITE "│\n" COLOR_RESET,
           (result->clamav_result == RESULT_CLEAN) ? "CLEAN" :
           (result->clamav_result == RESULT_ERROR) ? "ERROR" : "INFECTED",
           result->heuristic_score,
           result->entropy_value);
    printf(COLOR_WHITE "└─────────────────────────────────────┘\n"
           COLOR_RESET);
    printf("\n");
}

/* ============================================
   CONVERTIR RÉSULTAT EN TEXTE
   ============================================ */
const char *correlation_result_to_string(ScanResult result) {
    switch (result) {
        case RESULT_CLEAN:      return "CLEAN";
        case RESULT_SUSPICIOUS: return "SUSPICIOUS";
        case RESULT_MALWARE:    return "MALWARE";
        case RESULT_ERROR:      return "ERROR";
        default:                return "UNKNOWN";
    }
}
