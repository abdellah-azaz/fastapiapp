/* ============================================
   MISE À JOUR AUTOMATIQUE DES STATS
   ============================================ */
function updateStats() {
    fetch('/api/stats')
        .then(r => r.json())
        .then(data => {
            /* Mettre à jour si les éléments existent */
            const els = {
                'stat-scans'      : data.total_scans,
                'stat-threats'    : data.total_threats,
                'stat-quarantine' : data.total_quarantine,
                'stat-clean'      : data.total_clean
            };
            for (const [id, val] of Object.entries(els)) {
                const el = document.getElementById(id);
                if (el) el.textContent = val;
            }
        })
        .catch(() => {});
}

/* ============================================
   FORMATER LA TAILLE DES FICHIERS
   ============================================ */
function formatSize(bytes) {
    if (bytes === 0)        return '0 B';
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1024*1024)  return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/1024/1024).toFixed(1) + ' MB';
}

/* ============================================
   FORMATER UNE DATE
   ============================================ */
function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const d = new Date(dateStr);
    return d.toLocaleDateString('fr-FR') + ' ' +
           d.toLocaleTimeString('fr-FR');
}

/* ============================================
   AFFICHER UNE NOTIFICATION
   ============================================ */
function showNotification(message, type) {
    /* Créer la notification */
    const notif = document.createElement('div');
    notif.className = 'notification ' + (type || 'info');
    notif.textContent = message;

    /* Style inline */
    Object.assign(notif.style, {
        position    : 'fixed',
        top         : '80px',
        right       : '20px',
        padding     : '15px 25px',
        borderRadius: '8px',
        fontWeight  : 'bold',
        zIndex      : '9999',
        transition  : 'all 0.3s',
        maxWidth    : '400px'
    });

    /* Couleur selon type */
    if (type === 'success') {
        notif.style.background = 'rgba(0,255,136,0.15)';
        notif.style.border     = '1px solid #00ff88';
        notif.style.color      = '#00ff88';
    } else if (type === 'error') {
        notif.style.background = 'rgba(255,68,68,0.15)';
        notif.style.border     = '1px solid #ff4444';
        notif.style.color      = '#ff4444';
    } else {
        notif.style.background = 'rgba(0,212,255,0.15)';
        notif.style.border     = '1px solid #00d4ff';
        notif.style.color      = '#00d4ff';
    }

    document.body.appendChild(notif);

    /* Supprimer après 3 secondes */
    setTimeout(() => {
        notif.style.opacity = '0';
        setTimeout(() => notif.remove(), 300);
    }, 3000);
}

/* ============================================
   COPIER DANS LE PRESSE-PAPIER
   ============================================ */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => showNotification('✅ Copié !', 'success'))
        .catch(() => showNotification('❌ Erreur copie', 'error'));
}

/* ============================================
   CONFIRMER UNE ACTION DANGEREUSE
   ============================================ */
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

/* ============================================
   BADGE RÉSULTAT
   ============================================ */
function resultBadge(result) {
    const badges = {
        'CLEAN'      : '<span style="color:#00ff88">✅ CLEAN</span>',
        'SUSPICIOUS' : '<span style="color:#ffaa00">⚠️ SUSPECT</span>',
        'MALWARE'    : '<span style="color:#ff4444">☠️ MALWARE</span>',
        'ERROR'      : '<span style="color:#8b949e">❓ ERREUR</span>'
    };
    return badges[result] || result;
}

/* ============================================
   INITIALISATION AU CHARGEMENT
   ============================================ */
document.addEventListener('DOMContentLoaded', function() {

    /* Mise à jour stats toutes les 30 secondes */
    setInterval(updateStats, 30000);

    /* Marquer le lien actif dans la navbar */
    const path  = window.location.pathname;
    const links = document.querySelectorAll('.nav-links a');
    links.forEach(link => {
        if (link.getAttribute('href') === path) {
            link.classList.add('active');
        }
    });

    /* Permettre Enter dans les champs de scan */
    const scanInput = document.getElementById('scan-path') ||
                      document.getElementById('quick-path');
    if (scanInput) {
        scanInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const btn = document.getElementById('scan-btn');
                if (btn) btn.click();
                else if (typeof quickScan === 'function') quickScan();
            }
        });
    }

    console.log('🛡️ AV-Shield Interface chargée');
});
