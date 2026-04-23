#ifndef HEURISTIC_H
#define HEURISTIC_H

#include "common.h"

/* ============================================
   INDICATEURS DE COMPROMISSION (IoC)
   ============================================ */
typedef struct {
    const char *pattern;
    int score;
    const char *description;
} IoCIndicator;

/* ============================================
   RÉSULTAT HEURISTIQUE DÉTAILLÉ
   ============================================ */
typedef struct {
    int total_score;
    int indicators_found;
    char found_patterns[512];
    ScanResult result;
} HeuristicResult;

/* Fonctions */
int  heuristic_init(void);
int  heuristic_analyze(const char *filepath, HeuristicResult *result);
int  heuristic_score_to_result(int score);
void heuristic_print_result(const HeuristicResult *result);
void heuristic_cleanup(void);

#endif
