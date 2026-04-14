"""
SSH Remote Scanner Module
Connects to a remote Linux host via SSH and performs:
  1. Vulnerability audit (same checks as linux_scanner.py)
  2. Antivirus scan (ClamAV via clamscan on the remote host)
"""

import json
import datetime
import paramiko


def _get_ssh_client(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    """Create and return an authenticated SSH client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=username, password=password, timeout=15)
    return client


def run_ssh_cmd(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    """Execute a command on the remote host and return stdout."""
    try:
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def test_connection(host: str, port: int, username: str, password: str) -> dict:
    """Test SSH connectivity and return basic host info."""
    try:
        client = _get_ssh_client(host, port, username, password)
        hostname = run_ssh_cmd(client, "hostname")
        distro = run_ssh_cmd(client, "lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | head -1")
        kernel = run_ssh_cmd(client, "uname -r")
        client.close()
        return {
            "success": True,
            "hostname": hostname,
            "distro": distro,
            "kernel": kernel,
            "message": f"Connexion SSH réussie à {hostname}"
        }
    except paramiko.AuthenticationException:
        return {"success": False, "message": "Échec d'authentification SSH. Vérifiez le nom d'utilisateur/mot de passe."}
    except Exception as e:
        return {"success": False, "message": f"Erreur de connexion SSH: {str(e)}"}


# ---------------------------------------------------------------------------
# Vulnerability Audit (mirrors linux_scanner.py but over SSH)
# ---------------------------------------------------------------------------

def _collecter_systeme(client):
    hostname = run_ssh_cmd(client, "hostname")
    distro = run_ssh_cmd(client, "lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'\"' -f2")
    kernel = run_ssh_cmd(client, "uname -r")
    arch = run_ssh_cmd(client, "uname -m")
    ram_raw = run_ssh_cmd(client, "free -g | grep Mem: | awk '{print $2}'")
    ram_gb = int(ram_raw) if ram_raw.isdigit() else 0
    cpu_raw = run_ssh_cmd(client, "nproc")
    cpu_count = int(cpu_raw) if cpu_raw.isdigit() else 0
    is_root = run_ssh_cmd(client, "id -u") == "0"

    return {
        "hostname": hostname,
        "distro": distro,
        "kernel": kernel,
        "architecture": arch,
        "ram_gb": ram_gb,
        "cpu_cores": cpu_count,
        "est_root": is_root
    }


def _collecter_comptes(client):
    users_raw = run_ssh_cmd(client, "grep -E '/bin/(bash|sh|zsh)' /etc/passwd | cut -d: -f1")
    utilisateurs = [{"nom": u, "actif": True, "mdp_expire_jamais": False} for u in users_raw.splitlines() if u]

    uid0_raw = run_ssh_cmd(client, "grep 'x:0:' /etc/passwd | cut -d: -f1")
    uid0 = [u for u in uid0_raw.splitlines() if u]

    sudoers_raw = run_ssh_cmd(client, "grep -Po '^sudo:.*:\\K.*' /etc/group 2>/dev/null || grep -Po '^admin:.*:\\K.*' /etc/group 2>/dev/null")
    sudoers = [s.strip() for s in sudoers_raw.replace(',', '\n').splitlines() if s.strip()]

    shadow_perms = run_ssh_cmd(client, "stat -c '%a' /etc/shadow 2>/dev/null")

    return {
        "utilisateurs": utilisateurs,
        "uid0": uid0,
        "sudoers": sudoers,
        "shadow_permissions": shadow_perms,
        "nombre_admins": len(sudoers)
    }


def _collecter_reseau(client):
    ports_raw = run_ssh_cmd(client, "ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}' | grep -Po ':[0-9]+$' | tr -d ':'")
    ports = sorted(list(set([int(p) for p in ports_raw.splitlines() if p.isdigit()])))
    ports_ouverts_obj = []
    for p in ports:
        ports_ouverts_obj.append({"port": p, "service": "inconnu"})

    ufw_status = run_ssh_cmd(client, "ufw status 2>/dev/null | grep 'Status:' | awk '{print $2}'") or "inactive"
    samba_active = run_ssh_cmd(client, "systemctl is-active smbd 2>/dev/null") == "active"

    return {
        "ports_ouverts": ports_ouverts_obj,
        "ufw_status": ufw_status,
        "samba_active": samba_active,
    }


def _collecter_securite(client):
    apparmor = run_ssh_cmd(client, "aa-status --enabled 2>/dev/null") == "Yes"
    selinux = run_ssh_cmd(client, "getenforce 2>/dev/null") or "Disabled"
    ssh_root = run_ssh_cmd(client, "grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'") or "unknown"
    ssh_pass = run_ssh_cmd(client, "grep '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'") or "unknown"
    suid_files = run_ssh_cmd(client, "find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | head -n 5")

    return {
        "apparmor_enabled": apparmor,
        "selinux_status": selinux,
        "ssh_permit_root": ssh_root,
        "ssh_password_auth": ssh_pass,
        "suid_examples": suid_files.splitlines()
    }


def _collecter_logiciels(client):
    import re
    updates_raw = run_ssh_cmd(client, "/usr/lib/update-notifier/apt-check --human-readable 2>/dev/null")
    sec_updates = 0
    match = re.search(r"(\d+) updates are security updates", updates_raw)
    if match:
        sec_updates = int(match.group(1))
    pkg_count = run_ssh_cmd(client, "dpkg -l 2>/dev/null | wc -l")
    return {
        "total_paquets": int(pkg_count) if pkg_count.isdigit() else 0,
        "maj_securite_pendantes": sec_updates
    }


def _collecter_persistence(client):
    services_raw = run_ssh_cmd(client, "systemctl list-units --type=service --state=running --no-legend 2>/dev/null | head -n 10")
    cron_raw = run_ssh_cmd(client, "ls /etc/cron.d /etc/cron.daily 2>/dev/null")
    return {
        "services_running_top": services_raw.splitlines(),
        "cron_files": cron_raw.splitlines()
    }


def _collecter_logs(client):
    failed_raw = run_ssh_cmd(client, "grep 'Failed password' /var/log/auth.log 2>/dev/null | wc -l")
    return {
        "echecs_connexion": int(failed_raw) if failed_raw.isdigit() else 0
    }


def _analyser_risques(scan: dict) -> list:
    """Same risk analysis logic as linux_scanner.py."""
    risques = []

    if scan["comptes"]["shadow_permissions"] not in ["640", "600", "400", ""]:
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

    return [{"niveau": r[0], "message": r[1]} for r in risques]


def run_remote_vulnerability_scan(host: str, port: int, username: str, password: str) -> dict:
    """Connect via SSH and run a full vulnerability audit on the remote host."""
    try:
        client = _get_ssh_client(host, port, username, password)

        scan = {
            "date_scan": datetime.datetime.now().isoformat(),
            "remote_host": host,
            "systeme": _collecter_systeme(client),
            "comptes": _collecter_comptes(client),
            "reseau": _collecter_reseau(client),
            "securite": _collecter_securite(client),
            "logiciels": _collecter_logiciels(client),
            "persistence": _collecter_persistence(client),
            "logs": _collecter_logs(client),
        }

        scan["risques"] = _analyser_risques(scan)

        client.close()
        return {"success": True, "data": scan}

    except paramiko.AuthenticationException:
        return {"success": False, "message": "Échec d'authentification SSH."}
    except Exception as e:
        return {"success": False, "message": f"Erreur SSH: {str(e)}"}


# ---------------------------------------------------------------------------
# Antivirus Scan via SSH (uses clamscan on the remote host)
# ---------------------------------------------------------------------------

def run_remote_av_scan(host: str, port: int, username: str, password: str, scan_path: str = "/home") -> dict:
    """Connect via SSH and run an antivirus scan using clamscan on the remote host."""
    try:
        client = _get_ssh_client(host, port, username, password)

        # Check if clamscan is available
        clamscan_check = run_ssh_cmd(client, "which clamscan 2>/dev/null")
        if not clamscan_check:
            # Fallback: check for clamdscan
            clamscan_check = run_ssh_cmd(client, "which clamdscan 2>/dev/null")

        if not clamscan_check:
            client.close()
            return {
                "success": False,
                "message": "ClamAV (clamscan) n'est pas installé sur l'hôte distant. Installez-le avec: sudo apt install clamav"
            }

        # Run clamscan with recursive, infected-only output
        scan_cmd = f"clamscan -r --infected --no-summary {scan_path} 2>/dev/null; echo '---SUMMARY---'; clamscan -r --no-summary {scan_path} 2>/dev/null | tail -0; clamscan -r {scan_path} 2>/dev/null | tail -5"
        import uuid
        import time
        start_time = time.time()
        raw_output = run_ssh_cmd(client, f"clamscan -r {scan_path} 2>/dev/null", timeout=300)
        scan_duration = time.time() - start_time

        # Parse clamscan output
        files = []
        summary_lines = {}
        in_summary = False
        infected_count = 0
        total_files = 0

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("----------- SCAN SUMMARY -----------"):
                in_summary = True
                continue

            if in_summary:
                if ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        summary_lines[parts[0].strip()] = parts[1].strip()
            else:
                # Parse file scan results
                if ": " in line:
                    filepath, result = line.rsplit(": ", 1)
                    is_infected = "FOUND" in result.upper()
                    files.append({
                        "filename": filepath.split('/')[-1].strip(),
                        "filepath": filepath.strip(),
                        "filesize": 0,
                        "sha256": "",
                        "result": "MALWARE" if is_infected else "CLEAN",
                        "threat": result.replace("FOUND", "").strip() if is_infected else "",
                        "heuristic_score": 100 if is_infected else 0,
                        "entropy": 0.0,
                        "quarantined": False
                    })
                    if is_infected:
                        infected_count += 1
                    total_files += 1

        client.close()

        return {
            "success": True,
            "data": {
                "report_id": str(uuid.uuid4()),
                "generated_at": datetime.datetime.now().isoformat(),
                "remote_host": host,
                "scan_target": scan_path,
                "scan_duration": scan_duration,
                "statistics": {
                    "total_files": int(total_files),
                    "malware_files": int(infected_count),
                    "clean_files": int(total_files - infected_count),
                    "suspicious_files": 0
                },
                "files": files,
                "raw_output": raw_output[-2000:] if len(raw_output) > 2000 else raw_output
            }
        }

    except paramiko.AuthenticationException:
        return {"success": False, "message": "Échec d'authentification SSH."}
    except Exception as e:
        return {"success": False, "message": f"Erreur SSH: {str(e)}"}
