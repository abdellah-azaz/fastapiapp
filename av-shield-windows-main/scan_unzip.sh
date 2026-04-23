#!/bin/bash
# Script qui extrait les zips protégés puis lance avshield

TARGET="$1"
TMPDIR="/tmp/avshield_extracted_$$"
mkdir -p "$TMPDIR"

echo "🔓 Extraction des archives protégées..."

find "$TARGET" -name "*.zip" | while read zipfile; do
    # Chercher le fichier .pass correspondant
    dir=$(dirname "$zipfile")
    passfile=$(find "$dir" -name "*.pass" | head -1)
    
    if [ -f "$passfile" ]; then
        password=$(cat "$passfile")
        name=$(basename "$zipfile" .zip)
        mkdir -p "$TMPDIR/$name"
        
        # Extraire avec le mot de passe
        unzip -P "$password" "$zipfile" -d "$TMPDIR/$name" 2>/dev/null
        echo "✅ Extrait: $name (pass: $password)"
    else
        # Essayer sans mot de passe
        unzip "$zipfile" -d "$TMPDIR/$(basename $zipfile .zip)" 2>/dev/null
    fi
done

echo ""
echo "🛡️  Lancement du scan AV-Shield sur les fichiers extraits..."
echo "📁 Dossier temporaire: $TMPDIR"
echo ""

~/av-shield/avshield scan "$TMPDIR"

echo ""
echo "🧹 Nettoyage des fichiers temporaires..."
rm -rf "$TMPDIR"
echo "✅ Terminé"
