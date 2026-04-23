#include "../include/entropy.h"

/* ============================================
   CALCULER LA VALEUR D'ENTROPIE
   ============================================ */
double entropy_compute_value(const unsigned char *data, size_t size) {
    if (!data || size == 0) return 0.0;

    /* Compter la fréquence de chaque octet (0-255) */
    unsigned long freq[256] = {0};
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }

    /* Appliquer la formule de Shannon */
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)size;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

/* ============================================
   ANALYSER L'ENTROPIE D'UN FICHIER
   ============================================ */
int entropy_calculate(const char *filepath, EntropyResult *result) {
    /* Ouvrir le fichier */
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Entropie: impossible d'ouvrir %s\n",
                filepath);
        return -1;
    }

    /* Obtenir la taille du fichier */
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Fichier vide */
    if (filesize <= 0) {
        fclose(file);
        result->value          = 0.0;
        result->level          = ENTROPY_NORMAL;
        result->result         = RESULT_CLEAN;
        strncpy(result->interpretation,
                "Fichier vide", sizeof(result->interpretation) - 1);
        return 0;
    }

    /* Limiter la taille pour les gros fichiers */
    size_t read_size = (filesize > MAX_FILE_SIZE) ?
                        MAX_FILE_SIZE : (size_t)filesize;

    /* Allouer la mémoire */
    unsigned char *buffer = (unsigned char *)malloc(read_size);
    if (!buffer) {
        fclose(file);
        return -1;
    }

    /* Lire le fichier */
    size_t bytes_read = fread(buffer, 1, read_size, file);
    fclose(file);

    /* Calculer l'entropie */
    result->value = entropy_compute_value(buffer, bytes_read);
    free(buffer);

    /* Déterminer le niveau */
    if (result->value < 5.0) {
        result->level  = ENTROPY_NORMAL;
        result->result = RESULT_CLEAN;
        strncpy(result->interpretation,
                "Entropie normale — fichier texte ou code source",
                sizeof(result->interpretation) - 1);

    } else if (result->value < 6.5) {
        result->level  = ENTROPY_MODERATE;
        result->result = RESULT_CLEAN;
        strncpy(result->interpretation,
                "Entropie modérée — fichier compressé normal",
                sizeof(result->interpretation) - 1);

    } else if (result->value < 7.0) {
        result->level  = ENTROPY_HIGH;
        result->result = RESULT_SUSPICIOUS;
        strncpy(result->interpretation,
                "Entropie élevée — fichier potentiellement suspect",
                sizeof(result->interpretation) - 1);

    } else {
        result->level  = ENTROPY_CRITICAL;
        result->result = RESULT_SUSPICIOUS;
        strncpy(result->interpretation,
                "Entropie critique — fichier probablement chiffré ou obfusqué",
                sizeof(result->interpretation) - 1);
    }

    return 0;
}

/* ============================================
   CONVERTIR NIVEAU EN TEXTE
   ============================================ */
const char *entropy_level_to_string(EntropyLevel level) {
    switch (level) {
        case ENTROPY_NORMAL:   return "NORMAL";
        case ENTROPY_MODERATE: return "MODERATE";
        case ENTROPY_HIGH:     return "HIGH";
        case ENTROPY_CRITICAL: return "CRITICAL";
        default:               return "UNKNOWN";
    }
}

/* ============================================
   AFFICHER LE RÉSULTAT
   ============================================ */
void entropy_print_result(const EntropyResult *result) {
    const char *color;

    switch (result->level) {
        case ENTROPY_NORMAL:
            color = COLOR_GREEN;
            break;
        case ENTROPY_MODERATE:
            color = COLOR_BLUE;
            break;
        case ENTROPY_HIGH:
            color = COLOR_YELLOW;
            break;
        case ENTROPY_CRITICAL:
            color = COLOR_RED;
            break;
        default:
            color = COLOR_WHITE;
    }

    printf(COLOR_CYAN "[ENTROPY] " COLOR_RESET);
    printf("Valeur: %s%.4f" COLOR_RESET
           " | Niveau: %s%-8s" COLOR_RESET
           " | %s\n",
           color, result->value,
           color, entropy_level_to_string(result->level),
           result->interpretation);
}
