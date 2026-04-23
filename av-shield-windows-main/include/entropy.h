#ifndef ENTROPY_H
#define ENTROPY_H

/* ============================================
   Formule: H = -Σ p(x) * log2(p(x))
   ============================================ */

#include "common.h"
#include <math.h>

/* ============================================
   NIVEAUX D'ENTROPIE
   ============================================ */
typedef enum {
    ENTROPY_NORMAL     = 0,   /* 0.0 - 5.0 : fichier texte normal */
    ENTROPY_MODERATE   = 1,   /* 5.0 - 6.5 : fichier compressé normal */
    ENTROPY_HIGH       = 2,   /* 6.5 - 7.0 : attention */
    ENTROPY_CRITICAL   = 3    /* 7.0 - 8.0 : obfusqué / chiffré */
} EntropyLevel;

/* ============================================
   RÉSULTAT D'ANALYSE D'ENTROPIE
   ============================================ */
typedef struct {
    double value;
    EntropyLevel level;
    ScanResult result;
    char interpretation[256];
} EntropyResult;

/* Fonctions */
int    entropy_calculate(const char *filepath, EntropyResult *result);
double entropy_compute_value(const unsigned char *data, size_t size);
const char *entropy_level_to_string(EntropyLevel level);
void   entropy_print_result(const EntropyResult *result);

#endif
