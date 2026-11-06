"""Genera un Excel sintético de eventos de seguridad (SIEM/EDR/Firewall/IAM)
con escenarios de ataque embebidos para demostrar la herramienta.

Uso:  python generate_sample_data.py
Salida: sample_data/security_events.xlsx
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

random.seed(42)
START = datetime(2026, 10, 26, 0, 0, 0)

INTERNAL_HOSTS = [
    ("WS-FIN-01", "10.10.20.11", "m.rojas"), ("WS-FIN-02", "10.10.20.12", "c.perez"),
    ("WS-HR-01", "10.10.30.21", "a.gomez"), ("WS-DEV-01", "10.10.40.31", "l.castro"),
    ("WS-DEV-02", "10.10.40.32", "j.mora"), ("WS-EXE-01", "10.10.50.41", "ceo.office"),
    ("SRV-AD-01", "10.10.1.10", "svc_ad"), ("SRV-DB-01", "10.10.2.20", "svc_sql"),
    ("SRV-WEB-01", "10.10.3.30", "svc_web"), ("SRV-FILE-01", "10.10.2.25", "svc_file"),
]
EXT_IPS_BAD = ["185.220.101.45", "45.155.205.233", "91.240.118.172", "194.165.16.77", "103.75.201.4"]
EXT_IPS_OK = ["8.8.8.8", "142.250.78.14", "13.107.42.14", "52.96.108.18", "151.101.1.69"]


def ts(day: int, hour: int, minute: int | None = None) -> datetime:
    m = random.randint(0, 59) if minute is None else minute
    return START + timedelta(days=day, hours=hour, minutes=m, seconds=random.randint(0, 59))


rows: list[dict] = []


def add(t, source, event_type, desc, host, src_ip, dst_ip, user, severity, action="Allowed", port=None, process=None):
    rows.append({
        "Timestamp": t, "Fuente": source, "Tipo de Evento": event_type, "Descripción": desc,
        "Host": host, "IP Origen": src_ip, "IP Destino": dst_ip, "Usuario": user,
        "Severidad Original": severity, "Acción": action, "Puerto": port, "Proceso": process,
    })


# --- Ruido benigno / informativo -------------------------------------------
benign = [
    ("Windows Security", "Logon Success", "Inicio de sesión exitoso", "Informational"),
    ("Proxy", "Web Access", "Acceso web permitido a sitio categorizado como Business", "Informational"),
    ("Windows Security", "Logoff", "Cierre de sesión de usuario", "Informational"),
    ("Antivirus", "Signature Update", "Actualización de firmas completada", "Informational"),
    ("Firewall", "Connection Allowed", "Conexión permitida por política estándar", "Low"),
]
for _ in range(220):
    h, ip, u = random.choice(INTERNAL_HOSTS)
    src, et, d, sev = random.choice(benign)
    add(ts(random.randint(0, 6), random.randint(7, 19)), src, et, d, h, ip,
        random.choice(EXT_IPS_OK), u, sev, "Allowed", random.choice([80, 443]))

# --- Escenario 1: Fuerza bruta SSH/RDP externa (T1110) ----------------------
atk = "185.220.101.45"
for i in range(45):
    add(ts(1, 2, i % 60), "Windows Security", "Failed Logon",
        "Múltiples intentos fallidos de autenticación RDP desde IP externa",
        "SRV-AD-01", atk, "10.10.1.10", random.choice(["administrator", "admin", "svc_backup", "root"]),
        "Medium", "Blocked", 3389)
add(ts(1, 3, 10), "Windows Security", "Logon Success",
    "Inicio de sesión exitoso tras múltiples fallos desde IP externa", "SRV-AD-01", atk, "10.10.1.10",
    "svc_backup", "High", "Allowed", 3389)

# --- Escenario 2: Phishing + ejecución de macro/PowerShell (T1566, T1059) ---
add(ts(2, 9, 5), "Email Gateway", "Phishing Detected", "Correo con adjunto .xlsm malicioso entregado al usuario",
    "WS-FIN-01", "91.240.118.172", "10.10.20.11", "m.rojas", "High", "Delivered")
add(ts(2, 9, 12), "EDR", "Process Creation", "Excel lanzó powershell.exe con comando codificado en Base64 (-enc)",
    "WS-FIN-01", "10.10.20.11", "", "m.rojas", "Critical", "Allowed", None, "powershell.exe")
add(ts(2, 9, 14), "EDR", "Suspicious Script", "PowerShell descargó payload desde dominio recién registrado",
    "WS-FIN-01", "10.10.20.11", "45.155.205.233", "m.rojas", "Critical", "Allowed", 443, "powershell.exe")
add(ts(2, 9, 20), "Firewall", "C2 Beaconing", "Tráfico periódico hacia IP con mala reputación (beaconing cada 60s)",
    "WS-FIN-01", "10.10.20.11", "45.155.205.233", "m.rojas", "High", "Allowed", 443)
for i in range(12):
    add(ts(2, 10 + i // 4, (i * 15) % 60), "Firewall", "C2 Beaconing",
        "Conexión recurrente hacia servidor de comando y control conocido",
        "WS-FIN-01", "10.10.20.11", "45.155.205.233", "m.rojas", "High", "Allowed", 443)

# --- Escenario 3: Movimiento lateral + credential dumping (T1003, T1021) ----
add(ts(3, 1, 20), "EDR", "Credential Dumping", "Acceso a memoria de LSASS detectado (posible Mimikatz)",
    "WS-FIN-01", "10.10.20.11", "", "m.rojas", "Critical", "Blocked", None, "rundll32.exe")
add(ts(3, 1, 40), "Windows Security", "Remote Service", "Inicio de sesión de red tipo 3 con credenciales de administrador desde estación de trabajo",
    "SRV-FILE-01", "10.10.20.11", "10.10.2.25", "adm.domain", "High", "Allowed", 445)
add(ts(3, 1, 55), "Windows Security", "Remote Service", "Ejecución remota mediante PsExec / servicio remoto en servidor de archivos",
    "SRV-FILE-01", "10.10.20.11", "10.10.2.25", "adm.domain", "High", "Allowed", 445, "psexesvc.exe")
add(ts(3, 2, 30), "Windows Security", "Privilege Escalation", "Usuario agregado al grupo Domain Admins",
    "SRV-AD-01", "10.10.20.11", "10.10.1.10", "adm.domain", "Critical", "Allowed")

# --- Escenario 4: Exfiltración de datos (T1048, T1041) ----------------------
for i in range(6):
    add(ts(4, 3, i * 7), "Firewall", "Large Outbound Transfer",
        "Transferencia saliente anómala de gran volumen (>2 GB) hacia IP externa",
        "SRV-FILE-01", "10.10.2.25", "103.75.201.4", "svc_file", "High", "Allowed", 443)
add(ts(4, 3, 50), "DLP", "Data Exfiltration", "Archivo comprimido con datos financieros enviado a destino no autorizado",
    "SRV-FILE-01", "10.10.2.25", "103.75.201.4", "svc_file", "Critical", "Allowed", 443)

# --- Escenario 5: Ransomware preparación (T1486, T1490) ---------------------
add(ts(5, 4, 12), "EDR", "Shadow Copy Deletion", "Eliminación de Volume Shadow Copies con vssadmin",
    "SRV-DB-01", "10.10.2.20", "", "svc_sql", "Critical", "Allowed", None, "vssadmin.exe")
for i in range(8):
    add(ts(5, 4, 15 + i), "EDR", "Mass File Encryption", "Modificación masiva de archivos con extensión desconocida (.locked)",
        "SRV-DB-01", "10.10.2.20", "", "svc_sql", "Critical", "Blocked", None, "unknown.exe")

# --- Escenario 6: Ataques web a SRV-WEB-01 (T1190) --------------------------
for i in range(18):
    add(ts(random.randint(0, 6), random.randint(0, 23)), "WAF", "SQL Injection",
        "Intento de inyección SQL detectado en parámetro de formulario de login",
        "SRV-WEB-01", random.choice(EXT_IPS_BAD), "10.10.3.30", "", "High", "Blocked", 443)
for i in range(10):
    add(ts(random.randint(0, 6), random.randint(0, 23)), "WAF", "Directory Traversal",
        "Intento de path traversal (../../etc/passwd)", "SRV-WEB-01",
        random.choice(EXT_IPS_BAD), "10.10.3.30", "", "Medium", "Blocked", 443)
for i in range(15):
    add(ts(random.randint(0, 6), random.randint(0, 23)), "IDS", "Port Scan",
        "Escaneo de puertos detectado desde IP externa", "SRV-WEB-01",
        random.choice(EXT_IPS_BAD), "10.10.3.30", "", "Low", "Blocked")

# --- Escenario 7: Insider / políticas (T1078, T1052) ------------------------
add(ts(3, 23, 10), "IAM", "Off-hours Access", "Acceso a sistema de nómina fuera de horario laboral",
    "WS-HR-01", "10.10.30.21", "10.10.2.20", "a.gomez", "Medium", "Allowed")
add(ts(4, 22, 40), "DLP", "USB Copy", "Copia de 1.2 GB de archivos confidenciales a dispositivo USB",
    "WS-HR-01", "10.10.30.21", "", "a.gomez", "High", "Allowed")
add(ts(6, 14, 5), "IAM", "Impossible Travel", "Inicio de sesión desde dos países distintos en 10 minutos",
    "WS-EXE-01", "10.10.50.41", "52.96.108.18", "ceo.office", "High", "Allowed")

# --- Escenario 8: Malware commodity / PUA / falsos positivos ----------------
for _ in range(9):
    h, ip, u = random.choice(INTERNAL_HOSTS[:6])
    add(ts(random.randint(0, 6), random.randint(8, 18)), "Antivirus", "PUA Detected",
        "Programa potencialmente no deseado detectado y puesto en cuarentena", h, ip, "", u,
        "Low", "Quarantined", None, "setup_helper.exe")
for _ in range(7):
    h, ip, u = random.choice(INTERNAL_HOSTS[:6])
    add(ts(random.randint(0, 6), random.randint(8, 18)), "Antivirus", "Malware Detected",
        "Troyano detectado en archivo descargado y eliminado automáticamente", h, ip, "", u,
        "Medium", "Quarantined", None, "invoice.exe")
for _ in range(14):
    h, ip, u = random.choice(INTERNAL_HOSTS[3:5])
    add(ts(random.randint(0, 6), random.randint(8, 18)), "EDR", "Admin Tool Use",
        "Uso legítimo de herramienta de administración por equipo de desarrollo (posible falso positivo)",
        h, ip, "", u, "Low", "Allowed", None, "psexec.exe")

df = pd.DataFrame(rows).sort_values("Timestamp").reset_index(drop=True)
df.insert(0, "ID", [f"EVT-{i + 1:05d}" for i in range(len(df))])

out = Path(__file__).parent / "sample_data" / "security_events.xlsx"
out.parent.mkdir(exist_ok=True)
df.to_excel(out, index=False, sheet_name="Eventos")
print(f"OK -> {out}  ({len(df)} eventos)")
