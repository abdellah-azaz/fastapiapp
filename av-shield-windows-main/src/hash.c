#include "../include/hash.h"

/* ============================================
   CALCULER SHA-256 D'UN FICHIER
   ============================================ */
int hash_sha256_file(const char *filepath, char *output_hash) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Impossible d'ouvrir: %s\n", filepath);
        return -1;
    }

    /* Initialiser le contexte OpenSSL EVP */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    /* Lire le fichier par blocs et mettre à jour le hash */
    unsigned char buffer[FILE_CHUNK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return -1;
        }
    }

    /* Finaliser le hash */
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hash_len = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    fclose(file);

    /* Convertir en hexadécimal lisible */
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[hash_len * 2] = '\0';

    return 0;
}

/* ============================================
   CALCULER SHA-256 D'UNE CHAÎNE
   ============================================ */
int hash_sha256_string(const char *input, char *output_hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hash_len = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);

    /* Convertir en hexadécimal */
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[hash_len * 2] = '\0';

    return 0;
}

/* ============================================
   COMPARER DEUX HASH
   ============================================ */
int hash_compare(const char *hash1, const char *hash2) {
    return strncmp(hash1, hash2, MAX_HASH_LEN) == 0 ? 1 : 0;
}

/* ============================================
   AFFICHER LE HASH
   ============================================ */
void hash_print(const char *filepath, const char *hash) {
    printf(COLOR_BLUE "[SHA-256] " COLOR_RESET);
    printf("%-40s → %s\n", filepath, hash);
}
