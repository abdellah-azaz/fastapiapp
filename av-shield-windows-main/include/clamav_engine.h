#ifndef CLAMAV_ENGINE_H
#define CLAMAV_ENGINE_H

#include "common.h"
#include <clamav.h>

/* État du moteur ClamAV */
typedef struct {
    struct cl_engine *engine;   
    unsigned int signatures;     
    int initialized;             
    char db_path[MAX_PATH_LEN];  
    char version[64];            
} ClamavEngine;

/* Fonctions */
int  clamav_init(ClamavEngine *engine);
int  clamav_scan_file(ClamavEngine *engine, const char *filepath, FileReport *report);
void clamav_print_info(const ClamavEngine *engine);
void clamav_cleanup(ClamavEngine *engine);

#endif
