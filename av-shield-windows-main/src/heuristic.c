#include "../include/heuristic.h"

#ifdef _WIN32
static void *memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void*)h;
    if (hl < nl) return NULL;
    for (size_t i = 0; i <= hl - nl; i++) {
        if (memcmp((char*)h + i, n, nl) == 0) return (char*)h + i;
    }
    return NULL;
}
#endif


/* ============================================
   BASE DE DONNÉES DES INDICATEURS IoC
   ============================================ */
static const IoCIndicator ioc_indicators[] = {
    /* Commandes dangereuses Windows */
    { "powershell",        30, "Execution PowerShell suspecte"        },
    { "cmd.exe",           25, "Execution CMD cachee"                 },
    { "wscript",           25, "Windows Script Host suspect"          },
    { "cscript",           25, "Windows Script suspect"               },
    { "regsvr32",          30, "Enregistrement DLL suspect"           },
    { "rundll32",          30, "Execution DLL suspecte"               },
    { "mshta",             35, "HTA Application suspecte"             },

    /* Python malveillant */
    { "socket.connect",    25, "Connexion reseau Python suspecte"     },
    { "socket.socket",     20, "Creation socket suspecte"             },
    { "os.popen",          25, "Execution commande OS suspecte"       },
    { "os.system",         20, "Execution systeme suspecte"           },
    { "subprocess.Popen",  25, "Sous-processus suspect"               },
    { "reverse_shell",     50, "Reverse shell detecte"                },
    { "bind_shell",        50, "Bind shell detecte"                   },
    /* Téléchargement et réseau */
    { "wget",              20, "Telechargement reseau suspect"        },
    { "curl",              20, "Telechargement reseau suspect"        },
    { "http://",           15, "URL HTTP non securisee"               },
    { "ftp://",            20, "Connexion FTP suspecte"               },
    { "/bin/bash -i",      45, "Shell interactif suspect"             },
    { "nc -e",             45, "Netcat reverse shell"                 },
    { "ncat",              35, "Netcat suspect"                       },

    /* Obfuscation */
    { "base64",            20, "Encodage Base64 suspect"              },
    { "base64 -d",         35, "Decodage Base64 suspect"              },
    { "eval(",             30, "Evaluation de code dynamique"         },
    { "exec(",             30, "Execution de code dynamique"          },
    { "fromCharCode",      25, "Obfuscation JavaScript"               },

    /* Fichiers systeme sensibles Linux */
    { "/etc/passwd",       35, "Acces fichier mots de passe"          },
    { "/etc/shadow",       45, "Acces fichier shadow"                 },
    { "/etc/sudoers",      40, "Modification droits sudo"             },
    { "/root/",            30, "Acces repertoire root"                },
    { "~/.ssh/",           40, "Acces cles SSH"                       },
    { "authorized_keys",   40, "Modification cles SSH"                },

    /* Modifications systeme dangereuses */
    { "chmod 777",         25, "Permissions dangereuses"              },
    { "chmod +x",          20, "Ajout droit execution"                },
    { "chown root",        35, "Changement proprietaire root"         },
    { "rm -rf",            30, "Suppression massive fichiers"         },
    { "mkfs",              45, "Formatage disque"                     },
    { "dd if=",            35, "Ecriture directe disque"              },

    /* Persistance malware */
    { "crontab",           20, "Tache planifiee suspecte"             },
    { "/etc/cron",         25, "Modification cron suspecte"           },
    { "systemctl enable",  25, "Service persistant suspect"           },
    { ".bashrc",           20, "Modification profil bash"             },
    { ".bash_profile",     20, "Modification profil bash"             },

    /* Cryptomining */
    { "xmrig",             50, "Cryptominer XMRig detecte"            },
    { "stratum+tcp",       50, "Protocole minage crypto"              },
    { "minerd",            50, "Daemon de minage detecte"             },

    /* Ransomware */
    { "encrypt",           20, "Fonction chiffrement suspecte"        },
    { "ransom",            40, "Mot-cle ransomware detecte"           },
    { "bitcoin",           25, "Reference crypto-monnaie"             },
    { "wallet",            20, "Reference portefeuille crypto"        },

    /* Fin de liste */
    { NULL, 0, NULL }
};

/* ============================================
   INITIALISATION
   ============================================ */
int heuristic_init(void) {
    /* Compter les indicateurs */
    int count = 0;
    while (ioc_indicators[count].pattern != NULL) count++;

    char msg[128];
    snprintf(msg, sizeof(msg),
             "Heuristique initialisée: %d indicateurs IoC chargés", count);
    printf(COLOR_CYAN "[INFO]   " COLOR_RESET "%s\n", msg);
    return 0;
}

/* ============================================
   ANALYSER UN FICHIER
   ============================================ */
int heuristic_analyze(const char *filepath, HeuristicResult *result) {
    /* Initialiser le résultat */
    result->total_score      = 0;
    result->indicators_found = 0;
    result->found_patterns[0]= '\0';
    result->result           = RESULT_CLEAN;

    /* Ouvrir le fichier */
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Heuristique: impossible d'ouvrir %s\n",
                filepath);
        return -1;
    }

    /* Lire le fichier par blocs */
    unsigned char buffer[FILE_CHUNK_SIZE + 1];
    size_t bytes_read;
    char found_list[512] = {0};

    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, file)) > 0) {
        buffer[bytes_read] = '\0';

        /* Chercher chaque indicateur IoC */
        int i = 0;
        while (ioc_indicators[i].pattern != NULL) {
            /* Recherche du pattern dans le buffer */
            if (memmem(buffer, bytes_read,
                       ioc_indicators[i].pattern,
                       strlen(ioc_indicators[i].pattern)) != NULL) {

                /* Pattern trouvé — ajouter le score */
                result->total_score      += ioc_indicators[i].score;
                result->indicators_found++;

                /* Ajouter à la liste des patterns trouvés */
                if (strlen(found_list) + strlen(ioc_indicators[i].pattern)
                    < 480) {
                    if (strlen(found_list) > 0)
                        strncat(found_list, ", ", 3);
                    strncat(found_list,
                            ioc_indicators[i].pattern,
                            sizeof(found_list) - strlen(found_list) - 1);
                }
            }
            i++;
        }
    }

    fclose(file);

    /* Copier la liste des patterns trouvés */
    strncpy(result->found_patterns, found_list,
            sizeof(result->found_patterns) - 1);

    /* Décision finale */
    result->result = heuristic_score_to_result(result->total_score);

    return 0;
}

/* ============================================
   CONVERTIR SCORE EN RÉSULTAT
   ============================================ */
int heuristic_score_to_result(int score) {
    if (score >= 80)
        return RESULT_MALWARE;
    else if (score >= HEURISTIC_THRESHOLD)
        return RESULT_SUSPICIOUS;
    else
        return RESULT_CLEAN;
}

/* ============================================
   AFFICHER LE RÉSULTAT
   ============================================ */
void heuristic_print_result(const HeuristicResult *result) {
    const char *color;
    const char *label;

    if (result->result == RESULT_MALWARE) {
        color = COLOR_RED;
        label = "MALWARE";
    } else if (result->result == RESULT_SUSPICIOUS) {
        color = COLOR_YELLOW;
        label = "SUSPICIOUS";
    } else {
        color = COLOR_GREEN;
        label = "CLEAN";
    }

    printf(COLOR_CYAN "[HEURISTIC] " COLOR_RESET);
    printf("Score: %s%d/100" COLOR_RESET
           " | IoC trouvés: %d"
           " | Résultat: %s%s" COLOR_RESET "\n",
           color, result->total_score,
           result->indicators_found,
           color, label);

    /* Afficher les patterns trouvés */
    if (result->indicators_found > 0) {
        printf(COLOR_YELLOW "            Patterns: %s\n" COLOR_RESET,
               result->found_patterns);
    }
}

/* ============================================
   NETTOYAGE
   ============================================ */
void heuristic_cleanup(void) {

}
