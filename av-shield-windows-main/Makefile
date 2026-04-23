# Compilateur et options
CC      = gcc
CFLAGS  = -Wall -Wextra -I./include \
          -fstack-protector-strong \
          -D_FORTIFY_SOURCE=2
LDFLAGS = -lclamav -lssl -lcrypto -lsqlite3 -lm

# Nom du programme final
TARGET  = avshield

# Dossiers
SRC_DIR = src
OBJ_DIR = obj

# Fichiers sources
SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/logger.c \
       $(SRC_DIR)/database.c \
       $(SRC_DIR)/hash.c \
       $(SRC_DIR)/entropy.c \
       $(SRC_DIR)/heuristic.c \
       $(SRC_DIR)/clamav_engine.c \
       $(SRC_DIR)/correlation.c \
       $(SRC_DIR)/quarantine.c \
       $(SRC_DIR)/report.c \
       $(SRC_DIR)/scanner.c

# Fichiers objets
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# ============================================
#   RÈGLE PRINCIPALE
# ============================================
all: $(OBJ_DIR) $(TARGET)
	@echo ""
	@echo "\033[1;32m[OK] AV-Shield compilé avec succès !\033[0m"
	@echo "\033[1;36mUsage: ./avshield help\033[0m"
	@echo ""

# Créer le dossier obj
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compiler le programme final
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Compiler chaque fichier .c en .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# ============================================
#   RÈGLES UTILITAIRES
# ============================================

# Nettoyer les fichiers compilés
clean:
	rm -rf $(OBJ_DIR) $(TARGET)
	@echo "\033[1;33m[CLEAN] Fichiers compilés supprimés\033[0m"

# Recompiler depuis zéro
re: clean all

# Installer (copier dans /usr/local/bin)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@echo "\033[1;32m[OK] avshield installé\033[0m"

# Désinstaller
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "\033[1;33m[OK] avshield désinstallé\033[0m"

# Afficher les infos
info:
	@echo "Compilateur : $(CC)"
	@echo "Flags       : $(CFLAGS)"
	@echo "Libs        : $(LDFLAGS)"
	@echo "Sources     : $(SRCS)"

.PHONY: all clean re install uninstall info
