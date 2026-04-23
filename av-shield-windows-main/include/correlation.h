#ifndef CORRELATION_H
#define CORRELATION_H

#include "common.h"
#include "heuristic.h"
#include "entropy.h"

/* ============================================
   RÉSULTAT DE CORRÉLATION DÉTAILLÉ
   ============================================ */
typedef struct {
    /* Résultats de chaque couche */
    ScanResult clamav_result;
    ScanResult heuristic_result;
    ScanResult entropy_result;

    /* Scores */
    int heuristic_score;
    double entropy_value;

    /* Décision finale */
    ScanResult final_result;
    int confidence;
    char reason[512];
    char threat_name[MAX_THREAT_NAME];
} CorrelationResult;

/* ============================================
   POIDS DES COUCHES DE DÉTECTION
   ============================================ */
#define WEIGHT_CLAMAV      70
#define WEIGHT_HEURISTIC   20
#define WEIGHT_ENTROPY     10

/* Fonctions */
int  correlation_analyze(const char *filepath, FileReport *report);
int  correlation_decide(CorrelationResult *result);
void correlation_print_result(const CorrelationResult *result);
const char *correlation_result_to_string(ScanResult result);

#endif
