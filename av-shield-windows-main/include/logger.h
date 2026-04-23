#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

/* Types d'événements à logger */
typedef enum {
    LOG_INFO    = 0,   
    LOG_WARNING = 1,   
    LOG_THREAT  = 2,   
    LOG_ERR   = 3,   
    LOG_AUDIT   = 4    
} LogLevel;

/* Fonctions */
int  logger_init(void);
void logger_write(LogLevel level, const char *message);
void logger_scan_result(const FileReport *report);
void logger_audit(const char *action, const char *target);
void logger_close(void);

#endif 
