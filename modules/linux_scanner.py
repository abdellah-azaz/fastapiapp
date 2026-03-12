import os
import json
import datetime
import platform
import subprocess
import socket
import concurrent.futures
import urllib.request
import re

# Global check for root/sudo
ES_ROOT = os.geteuid() == 0

def run_cmd(commande):
    try:
        r = subprocess.run(
            commande, shell=True, capture_output=True, text=True, timeout=10
        )
        return r.stdout.strip()
    except Exception:
        return ""

def collecter_systeme():
    print("  -> [1/8] Informations système...")
    hostname = socket.gethostname()
    distro = run_cmd("lsb_release -ds") or platform.system()
    kernel = platform.release()
    arch = platform.machine()
    
    ram_raw = run_cmd("free -g | grep Mem: | awk '{print $2}'")
    ram_gb = int(ram_raw) if ram_raw.isdigit() else 0
    cpu_count = os.cpu_count()

    print(f"     OK {hostname} - {distro}")
    return {
        "hostname": hostname,
        "distro": distro,
        "kernel": kernel,
        "architecture": arch,
        "ram_gb": ram_gb,
        "cpu_cores": cpu_count,
        "est_root": ES_ROOT
    }

def collecter_comptes():
    print("  -> [2/8] Comptes utilisateurs...")
    
    # Liste des utilisateurs avec shell (non système)
    users_raw = run_cmd("grep -E '/bin/(bash|sh|zsh)' /etc/passwd | cut -d: -f1")
    utilisateurs = [{"nom": u, "actif": True, "mdp_expire_jamais": False} for u in users_raw.splitlines()]

    # Utilisateurs avec UID 0
    uid0_raw = run_cmd("grep 'x:0:' /etc/passwd | cut -d: -f1")
    uid0 = uid0_raw.splitlines()

    # Membres du groupe sudo/admin
    sudoers_raw = run_cmd("grep -Po '^sudo:.*:\K.*' /etc/group || grep -Po '^admin:.*:\K.*' /etc/group")
    sudoers = [s.strip() for s in sudoers_raw.replace(',', '\n').splitlines() if s.strip()]

    # Permissions sur /etc/shadow
    shadow_perms = run_cmd("stat -c '%a' /etc/shadow")
    
    print(f"     OK {len(utilisateurs)} utilisateur(s) - {len(uid0)} root(s)")
    return {
        "utilisateurs": utilisateurs,
        "uid0": uid0,
        "sudoers": sudoers,
        "shadow_permissions": shadow_perms,
        "nombre_admins": len(sudoers)
    }

def collecter_reseau():
    print("  -> [3/8] Réseau interne...")
    
    # Ports en écoute
    ports_raw = run_cmd("ss -tuln | grep LISTEN | awk '{print $5}' | grep -Po ':[0-9]+$' | tr -d ':'")
    ports_ouverts_obj = []
    for p in sorted(list(set([int(p) for p in ports_raw.splitlines() if p.isdigit()]))):
        try:
            service = socket.getservbyport(p)
        except Exception:
            service = "inconnu"
        ports_ouverts_obj.append({"port": p, "service": service})

    # État du pare-feu (UFW)
    ufw_status = run_cmd("ufw status | grep 'Status:' | awk '{print $2}'") or "inactive"

    # Partages réseau (Samba)
    samba_active = run_cmd("systemctl is-active smbd") == "active"

    print(f"     OK {len(ports_ouverts_obj)} port(s) ouvert(s)")
    return {
        "ports_ouverts": ports_ouverts_obj,
        "ufw_status": ufw_status,
        "samba_active": samba_active,
    }

def collecter_ports_externes():
    print("  -> [4/8] Ports exposés à internet...")
    
    ip_publique = None
    for service in ["https://api.ipify.org", "https://ipv4.icanhazip.com"]:
        try:
            ip_publique = urllib.request.urlopen(service, timeout=5).read().decode("utf-8").strip()
            socket.inet_aton(ip_publique)
            break
        except Exception:
            continue

    if not ip_publique:
        print("     ERREUR - IP publique non récupérée")
        return {"ip_publique": "inconnu", "ports_exposes": [], "nombre_exposes": 0}

    print(f"     IP publique : {ip_publique}")

    PORTS_A_TESTER = {
        21: ("FTP", "CRITIQUE"), 22: ("SSH", "ÉLEVÉ"), 23: ("Telnet", "CRITIQUE"),
        80: ("HTTP", "MOYEN"), 443: ("HTTPS", "MOYEN"), 445: ("SMB", "CRITIQUE"),
        3306: ("MySQL", "ÉLEVÉ"), 3389: ("RDP", "CRITIQUE"), 8080: ("HTTP Alt", "MOYEN")
    }

    def tester_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            resultat = sock.connect_ex((ip_publique, port))
            sock.close()
            return resultat == 0
        except Exception:
            return False

    ports_exposes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futurs = {ex.submit(tester_port, port): port for port in PORTS_A_TESTER}
        for futur in concurrent.futures.as_completed(futurs):
            port = futurs[futur]
            if futur.result():
                service, risque = PORTS_A_TESTER[port]
                ports_exposes.append({"port": port, "service": service, "risque": risque})

    print(f"     OK {len(ports_exposes)} port(s) exposé(s)")
    return {
        "ip_publique": ip_publique,
        "ports_exposes": ports_exposes,
        "nombre_exposes": len(ports_exposes)
    }

def collecter_securite():
    print("  -> [5/8] Configuration sécurité...")
    
    # AppArmor / SELinux
    apparmor = run_cmd("aa-status --enabled") == "Yes"
    selinux = run_cmd("getenforce") or "Disabled"

    # SSH Conf
    ssh_root = run_cmd("grep '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}'") or "unknown"
    ssh_pass = run_cmd("grep '^PasswordAuthentication' /etc/ssh/sshd_config | awk '{print $2}'") or "unknown"

    # SUID files suspects
    suid_files = run_cmd("find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | head -n 5")
    
    print("     OK sécurité collectée")
    return {
        "apparmor_enabled": apparmor,
        "selinux_status": selinux,
        "ssh_permit_root": ssh_root,
        "ssh_password_auth": ssh_pass,
        "suid_examples": suid_files.splitlines()
    }

def collecter_logiciels():
    print("  -> [6/8] Logiciels et mises à jour...")
    
    # Vérification des mises à jour de sécurité
    updates_raw = run_cmd("/usr/lib/update-notifier/apt-check --human-readable")
    # Format type: "X packages can be updated. Y updates are security updates."
    sec_updates = 0
    match = re.search(r"(\d+) updates are security updates", updates_raw)
    if match:
        sec_updates = int(match.group(1))

    pkg_count = run_cmd("dpkg -l | wc -l")
    
    print(f"     OK {pkg_count} paquets - {sec_updates} MAJ sécurité")
    return {
        "total_paquets": int(pkg_count) if pkg_count.isdigit() else 0,
        "maj_securite_pendantes": sec_updates
    }

def collecter_persistence():
    print("  -> [7/8] Persistance et Services...")
    
    # Services actifs
    services_raw = run_cmd("systemctl list-units --type=service --state=running --no-legend | head -n 10")
    
    # Cron jobs
    cron_raw = run_cmd("ls /etc/cron.d /etc/cron.daily")
    
    print("     OK persistance collectée")
    return {
        "services_running_top": services_raw.splitlines(),
        "cron_files": cron_raw.splitlines()
    }

def collecter_logs():
    print("  -> [8/8] Analyse des logs d'authentification...")
    
    # Échecs de connexion (auth.log)
    failed_raw = run_cmd("grep 'Failed password' /var/log/auth.log | wc -l")
    
    print(f"     OK {failed_raw} échecs détectés")
    return {
        "echecs_connexion": int(failed_raw) if failed_raw.isdigit() else 0
    }

if __name__ == "__main__":
    print("=" * 50)
    print("  AuditAI - Scanner Linux (Ubuntu)")
    print("=" * 50 + "\n")

    scan = {
        "date_scan": datetime.datetime.now().isoformat(),
        "systeme": collecter_systeme(),
        "comptes": collecter_comptes(),
        "reseau": collecter_reseau(),
        "ports_externes": collecter_ports_externes(),
        "securite": collecter_securite(),
        "logiciels": collecter_logiciels(),
        "persistence": collecter_persistence(),
        "logs": collecter_logs(),
    }

    # Analyse des risques simplifiée
    risques = []
    
    if scan["comptes"]["shadow_permissions"] not in ["640", "600", "400"]:
        risques.append(("CRITIQUE", f"Permissions /etc/shadow trop larges ({scan['comptes']['shadow_permissions']})"))
    
    if len(scan["comptes"]["uid0"]) > 1:
        risques.append(("ÉLEVÉ", f"Plusieurs utilisateurs avec UID 0 : {scan['comptes']['uid0']}"))
    
    if scan["reseau"]["ufw_status"] != "active":
        risques.append(("CRITIQUE", "Pare-feu UFW désactivé"))
    
    if scan["securite"]["ssh_permit_root"] in ["yes", "unknown"]:
        risques.append(("MOYEN", "SSH : Root login autorisé ou non configuré"))
        
    if scan["logiciels"]["maj_securite_pendantes"] > 0:
        risques.append(("ÉLEVÉ", f"{scan['logiciels']['maj_securite_pendantes']} mises à jour de sécurité en attente"))

    if scan["logs"]["echecs_connexion"] > 50:
        risques.append(("ÉLEVÉ", f"Nombreux échecs de connexion ({scan['logs']['echecs_connexion']})"))

    scan["risques"] = [{"niveau": r[0], "message": r[1]} for r in risques]

    # Sauvegarde
    os.makedirs("/tmp/AuditAI/data", exist_ok=True)
    chemin = "/tmp/AuditAI/data/scan_linux.json"
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(scan, f, indent=4, ensure_ascii=False)

    print("\n" + "-" * 50)
    print(f"  AUDIT DE SÉCURITÉ - {scan['systeme']['hostname']} - {scan['date_scan'][:10]}")
    print("-" * 50)

    if risques:
        print("\n  RISQUES DÉTECTÉS :\n")
        for niveau, message in risques:
            print(f"  {niveau:10} - {message}")
    else:
        print("\n  Aucun risque détecté.")

    print(f"\n  Rapport sauvegardé dans : {chemin}")
    print("-" * 50)
