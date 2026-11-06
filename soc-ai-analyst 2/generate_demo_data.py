"""Genera un segundo Excel de demostración (para subirlo manualmente en el video).

Empresa ficticia "Aurora Logística". Encabezados en INGLÉS para demostrar que la app
reconoce columnas en español o inglés. Datos 100% sintéticos.

Uso:  python generate_demo_data.py
Salida: sample_data/demo_video_eventos.xlsx
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

random.seed(7)
START = datetime(2026, 11, 2, 0, 0, 0)

HOSTS = [
    ("LAP-VENTAS-03", "172.16.10.23", "r.vargas"), ("LAP-VENTAS-07", "172.16.10.27", "d.quintero"),
    ("LAP-CONTA-02", "172.16.20.12", "e.batista"), ("LAP-RRHH-01", "172.16.30.5", "k.santamaria"),
    ("LAP-GERENCIA-01", "172.16.40.2", "g.aurora"), ("SRV-ERP-01", "172.16.1.50", "svc_erp"),
    ("SRV-DC-01", "172.16.1.10", "svc_dc"), ("SRV-FILES-02", "172.16.1.60", "svc_files"),
    ("SRV-WEB-PORTAL", "172.16.2.80", "svc_portal"),
]
BAD_IPS = ["5.188.206.14", "45.9.148.108", "185.234.219.60", "193.32.162.157", "91.92.251.103"]
OK_IPS = ["8.8.4.4", "1.1.1.1", "104.16.132.229", "20.190.151.9", "52.109.12.20"]

rows = []


def t(day, hour, minute=None):
    m = random.randint(0, 59) if minute is None else minute
    return START + timedelta(days=day, hours=hour, minutes=m, seconds=random.randint(0, 59))


def add(ts, source, etype, desc, host, src, dst, user, sev, action="Allowed", port=None, proc=None):
    rows.append({"Event ID": None, "Timestamp": ts, "Source": source, "Event Type": etype, "Description": desc,
                 "Hostname": host, "Src IP": src, "Dst IP": dst, "User": user, "Severity": sev,
                 "Action": action, "Port": port, "Process": proc})


# Ruido de fondo
noise = [
    ("Windows Security", "Logon Success", "Inicio de sesión exitoso", "Informational"),
    ("Windows Security", "Logoff", "Cierre de sesión de usuario", "Informational"),
    ("Proxy", "Web Access", "Acceso web permitido a sitio de categoría Business", "Informational"),
    ("Firewall", "Connection Allowed", "Conexión permitida por política estándar", "Low"),
    ("Antivirus", "Signature Update", "Actualización de firmas completada", "Informational"),
]
for _ in range(260):
    h, ip, u = random.choice(HOSTS)
    s, e, d, sv = random.choice(noise)
    add(t(random.randint(0, 5), random.randint(7, 19)), s, e, d, h, ip, random.choice(OK_IPS), u, sv, "Allowed",
        random.choice([80, 443]))

# Caso 1: toma de cuenta VPN de gerencia (fuerza bruta -> éxito -> viaje imposible)
atk = "91.92.251.103"
for i in range(38):
    add(t(1, 1, (i * 1) % 60), "VPN Gateway", "Failed Logon",
        "Múltiples intentos fallidos de autenticación VPN desde IP externa", "SRV-DC-01", atk, "172.16.1.10",
        random.choice(["g.aurora", "admin", "administrator", "r.vargas"]), "Medium", "Blocked", 443)
add(t(1, 2, 5), "VPN Gateway", "Logon Success", "Inicio de sesión exitoso tras múltiples fallos desde IP externa",
    "SRV-DC-01", atk, "172.16.1.10", "g.aurora", "High", "Allowed", 443)
add(t(1, 2, 15), "IAM", "Impossible Travel", "Inicio de sesión desde dos países distintos en 12 minutos",
    "LAP-GERENCIA-01", "172.16.40.2", "20.190.151.9", "g.aurora", "High", "Allowed")

# Caso 2: phishing -> PowerShell -> C2 -> LSASS en ventas
add(t(2, 10, 3), "Email Gateway", "Phishing Detected", "Correo con adjunto .xlsm malicioso entregado al usuario",
    "LAP-VENTAS-03", "77.91.68.52", "172.16.10.23", "r.vargas", "High", "Delivered")
add(t(2, 10, 9), "EDR", "Process Creation", "Excel lanzó powershell.exe con comando codificado en Base64 (-enc)",
    "LAP-VENTAS-03", "172.16.10.23", "", "r.vargas", "Critical", "Allowed", None, "powershell.exe")
add(t(2, 10, 11), "EDR", "Suspicious Script", "PowerShell descargó payload desde dominio recién registrado",
    "LAP-VENTAS-03", "172.16.10.23", "77.91.68.52", "r.vargas", "Critical", "Allowed", 443, "powershell.exe")
for i in range(14):
    add(t(2, 10 + i // 4, (i * 13) % 60), "Firewall", "C2 Beaconing",
        "Conexión recurrente hacia servidor de comando y control conocido", "LAP-VENTAS-03",
        "172.16.10.23", "77.91.68.52", "r.vargas", "High", "Allowed", 443)
add(t(2, 15, 20), "EDR", "Credential Dumping", "Acceso a memoria de LSASS detectado (posible Mimikatz)",
    "LAP-VENTAS-03", "172.16.10.23", "", "r.vargas", "Critical", "Blocked", None, "rundll32.exe")

# Caso 3: movimiento lateral al ERP y escalamiento
add(t(3, 2, 10), "Windows Security", "Remote Service", "Ejecución remota mediante PsExec / servicio remoto en servidor ERP",
    "SRV-ERP-01", "172.16.10.23", "172.16.1.50", "adm.aurora", "High", "Allowed", 445, "psexesvc.exe")
add(t(3, 2, 25), "Windows Security", "Privilege Escalation", "Usuario agregado al grupo Domain Admins",
    "SRV-DC-01", "172.16.10.23", "172.16.1.10", "adm.aurora", "Critical", "Allowed")

# Caso 4: exfiltración desde servidor de archivos
for i in range(5):
    add(t(4, 3, i * 9), "Firewall", "Large Outbound Transfer",
        "Transferencia saliente anómala de gran volumen (>3 GB) hacia IP externa", "SRV-FILES-02",
        "172.16.1.60", "193.32.162.157", "svc_files", "High", "Allowed", 443)
add(t(4, 3, 55), "DLP", "Data Exfiltration", "Archivo comprimido con contratos de clientes enviado a destino no autorizado",
    "SRV-FILES-02", "172.16.1.60", "193.32.162.157", "svc_files", "Critical", "Allowed", 443)

# Caso 5: ransomware bloqueado parcialmente en contabilidad
add(t(5, 5, 2), "EDR", "Shadow Copy Deletion", "Eliminación de Volume Shadow Copies con vssadmin",
    "LAP-CONTA-02", "172.16.20.12", "", "e.batista", "Critical", "Allowed", None, "vssadmin.exe")
for i in range(6):
    add(t(5, 5, 4 + i), "EDR", "Mass File Encryption", "Modificación masiva de archivos con extensión desconocida (.locked)",
        "LAP-CONTA-02", "172.16.20.12", "", "e.batista", "Critical", "Blocked", None, "unknown.exe")

# Caso 6: ataques al portal web
for _ in range(20):
    add(t(random.randint(0, 5), random.randint(0, 23)), "WAF", "SQL Injection",
        "Intento de inyección SQL detectado en parámetro de búsqueda", "SRV-WEB-PORTAL",
        random.choice(BAD_IPS), "172.16.2.80", "", "High", "Blocked", 443)
for _ in range(9):
    add(t(random.randint(0, 5), random.randint(0, 23)), "WAF", "Directory Traversal",
        "Intento de path traversal (../../etc/passwd)", "SRV-WEB-PORTAL", random.choice(BAD_IPS),
        "172.16.2.80", "", "Medium", "Blocked", 443)
for _ in range(16):
    add(t(random.randint(0, 5), random.randint(0, 23)), "IDS", "Port Scan", "Escaneo de puertos detectado desde IP externa",
        "SRV-WEB-PORTAL", random.choice(BAD_IPS), "172.16.2.80", "", "Low", "Blocked")

# Caso 7: actividad interna sospechosa
add(t(2, 22, 30), "IAM", "Off-hours Access", "Acceso a sistema de nómina fuera de horario laboral",
    "LAP-RRHH-01", "172.16.30.5", "172.16.1.50", "k.santamaria", "Medium", "Allowed")
add(t(3, 21, 15), "DLP", "USB Copy", "Copia de 2 GB de archivos confidenciales a dispositivo USB",
    "LAP-RRHH-01", "172.16.30.5", "", "k.santamaria", "High", "Allowed")

# Malware común y falsos positivos
for _ in range(10):
    h, ip, u = random.choice(HOSTS[:5])
    add(t(random.randint(0, 5), random.randint(8, 18)), "Antivirus", "PUA Detected",
        "Programa potencialmente no deseado detectado y puesto en cuarentena", h, ip, "", u, "Low", "Quarantined", None,
        "toolbar_setup.exe")
for _ in range(6):
    h, ip, u = random.choice(HOSTS[:5])
    add(t(random.randint(0, 5), random.randint(8, 18)), "Antivirus", "Malware Detected",
        "Troyano detectado en archivo descargado y eliminado automáticamente", h, ip, "", u, "Medium", "Quarantined",
        None, "factura.exe")
for _ in range(12):
    h, ip, u = random.choice(HOSTS[5:8])
    add(t(random.randint(0, 5), random.randint(8, 18)), "EDR", "Admin Tool Use",
        "Uso legítimo de herramienta de administración por TI (posible falso positivo)", h, ip, "", "ti.soporte",
        "Low", "Allowed", None, "psexec.exe")

df = pd.DataFrame(rows).sort_values("Timestamp").reset_index(drop=True)
df["Event ID"] = [f"AUR-{i + 1:05d}" for i in range(len(df))]
out = Path(__file__).parent / "sample_data" / "demo_video_eventos.xlsx"
out.parent.mkdir(exist_ok=True)
df.to_excel(out, index=False, sheet_name="Alertas SIEM")
print(f"OK -> {out} ({len(df)} eventos)")
