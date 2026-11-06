"""Motor de clasificación y triaje de eventos (reglas + contexto + correlación).

Cada evento recibe: categoría, táctica/técnica MITRE ATT&CK, puntaje de riesgo
(0-100), severidad calculada, veredicto de triaje, estado de mitigación y
recomendación. Después se correlacionan eventos en incidentes por host.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import pandas as pd

SEVERITY_ORDER = ["Crítica", "Alta", "Media", "Baja", "Informativa"]
SEVERITY_COLORS = {
    "Crítica": "#b91c1c", "Alta": "#ea580c", "Media": "#d97706",
    "Baja": "#2563eb", "Informativa": "#6b7280",
}
VERDICT_ORDER = ["Verdadero positivo probable", "Sospechoso - requiere análisis",
                 "Falso positivo probable", "Benigno / ruido"]


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    category: str
    tactic: str
    technique: str
    base: int
    verdict: str
    recommendation: str


RULES: list[Rule] = [
    Rule("Credential Dumping", r"lsass|mimikatz|credential dump|volcado de credenciales|sam database",
         "Acceso a credenciales", "Credential Access", "T1003 - OS Credential Dumping", 92,
         "Verdadero positivo probable",
         "Aislar el host, rotar credenciales expuestas (incluida KRBTGT si aplica) y capturar memoria para forense."),
    Rule("Ransomware", r"shadow cop|vssadmin|mass file encrypt|\.locked|ransom|cifrado masivo",
         "Impacto / Ransomware", "Impact", "T1486 - Data Encrypted for Impact / T1490 - Inhibit System Recovery", 95,
         "Verdadero positivo probable",
         "Aislar de inmediato el servidor de la red, activar el plan de respuesta a ransomware y validar respaldos offline."),
    Rule("Exfiltración", r"exfiltrat|large outbound|transferencia saliente|exfiltraci|datos financieros enviado",
         "Exfiltración de datos", "Exfiltration", "T1048 - Exfiltration Over Alternative Protocol", 85,
         "Verdadero positivo probable",
         "Bloquear el destino en el perímetro, preservar logs de red y evaluar notificación por fuga de datos."),
    Rule("Escalamiento de privilegios", r"domain admins|privilege escalation|escalamiento de privilegios|added to (admin|privileged)",
         "Escalamiento de privilegios", "Privilege Escalation", "T1078.002 - Valid Accounts: Domain Accounts", 90,
         "Verdadero positivo probable",
         "Revertir el cambio de grupo, auditar cuentas privilegiadas y forzar restablecimiento de contraseñas."),
    Rule("Uso de herramienta admin", r"admin tool use|uso legítimo de herramienta|posible falso positivo",
         "Actividad administrativa", "Execution", "T1569.002 - Service Execution", 15,
         "Falso positivo probable",
         "Validar con el equipo responsable y considerar una regla de exclusión documentada."),
    Rule("Movimiento lateral", r"psexec|remote service|servicio remoto|lateral|wmi exec|smb admin",
         "Movimiento lateral", "Lateral Movement", "T1021.002 - SMB/Windows Admin Shares", 78,
         "Sospechoso - requiere análisis",
         "Verificar si la actividad es administrativa legítima; de lo contrario aislar origen y destino."),
    Rule("Ejecución PowerShell ofuscada", r"powershell.*(-enc|base64|codificad|download)|encoded command|suspicious script|payload",
         "Ejecución maliciosa", "Execution", "T1059.001 - PowerShell", 88,
         "Verdadero positivo probable",
         "Aislar el equipo, extraer el script decodificado, buscar IOCs en la flota y bloquear dominios/IPs contactados."),
    Rule("Beaconing C2", r"beacon|\bc2\b|command and control|comando y control",
         "Comando y control", "Command and Control", "T1071.001 - Application Layer Protocol: Web", 80,
         "Verdadero positivo probable",
         "Bloquear la IP/dominio C2, aislar el host emisor y buscar otras comunicaciones al mismo destino."),
    Rule("Phishing", r"phish|malicious attachment|adjunto .*malicios|spearphish",
         "Phishing", "Initial Access", "T1566.001 - Spearphishing Attachment", 75,
         "Verdadero positivo probable",
         "Eliminar el correo de todos los buzones, bloquear remitente/URL y concientizar al usuario afectado."),
    Rule("Fuerza bruta", r"failed logon|múltiples intentos fallidos|multiples intentos|brute|password spray|login failed",
         "Ataque de autenticación", "Credential Access", "T1110 - Brute Force", 58,
         "Sospechoso - requiere análisis",
         "Bloquear la IP origen, habilitar MFA/bloqueo de cuenta y revisar si hubo un inicio de sesión exitoso posterior."),
    Rule("Inicio de sesión tras fallos", r"exitoso tras (múltiples )?fallos|success after (multiple )?fail",
         "Compromiso de cuenta", "Initial Access", "T1078 - Valid Accounts", 86,
         "Verdadero positivo probable",
         "Deshabilitar la cuenta, cerrar sesiones activas, restablecer credenciales y revisar la actividad posterior."),
    Rule("Inyección SQL", r"sql injection|sqli|inyección sql",
         "Ataque a aplicación web", "Initial Access", "T1190 - Exploit Public-Facing Application", 62,
         "Sospechoso - requiere análisis",
         "Validar que el WAF bloqueó el intento, revisar logs de aplicación y parchear/validar la entrada del parámetro."),
    Rule("Path traversal", r"traversal|\.\./|path traversal",
         "Ataque a aplicación web", "Initial Access", "T1190 - Exploit Public-Facing Application", 52,
         "Sospechoso - requiere análisis",
         "Confirmar bloqueo en WAF y revisar que la aplicación no exponga archivos del sistema."),
    Rule("Exfiltración por USB", r"usb|removable|medio extraíble",
         "Fuga de datos (interna)", "Exfiltration", "T1052.001 - Exfiltration over USB", 70,
         "Sospechoso - requiere análisis",
         "Contactar al usuario y su jefatura, revisar justificación y aplicar política de control de dispositivos."),
    Rule("Viaje imposible", r"impossible travel|viaje imposible",
         "Compromiso de cuenta", "Initial Access", "T1078 - Valid Accounts", 72,
         "Sospechoso - requiere análisis",
         "Contactar al usuario para validar, forzar re-autenticación con MFA y revisar sesiones activas."),
    Rule("Acceso fuera de horario", r"off-hours|fuera de horario|after hours",
         "Comportamiento anómalo de usuario", "Initial Access", "T1078 - Valid Accounts", 45,
         "Sospechoso - requiere análisis",
         "Validar con el responsable del usuario si el acceso fue autorizado."),
    Rule("Malware detectado", r"malware|trojan|troyano|virus|worm",
         "Malware", "Execution", "T1204 - User Execution", 50,
         "Sospechoso - requiere análisis",
         "Confirmar que la cuarentena fue exitosa, escanear el equipo y revisar el vector de entrada."),
    Rule("Escaneo de puertos", r"port scan|escaneo de puertos|network scan|reconocimiento",
         "Reconocimiento", "Discovery", "T1046 - Network Service Discovery", 25,
         "Benigno / ruido",
         "Sin acción inmediata; considerar bloqueo por reputación y monitorear si precede a explotación."),
    Rule("PUA", r"\bpua\b|potentially unwanted|no deseado",
         "Software no deseado", "Execution", "T1204 - User Execution", 18,
         "Falso positivo probable",
         "Confirmar cuarentena y reforzar política de instalación de software."),
    Rule("Ruido informativo", r"inicio de sesión exitoso|logon success|logoff|cierre de sesión|signature update|actualización de firmas|conexión permitida|acceso web permitido|web access|connection allowed",
         "Actividad rutinaria", "N/A", "N/A", 5,
         "Benigno / ruido",
         "Sin acción requerida."),
]
_COMPILED = [(r, re.compile(r.pattern, re.I)) for r in RULES]

SEV_FLOOR = {"critical": 80, "crítica": 80, "critica": 80, "high": 60, "alta": 60,
             "medium": 35, "media": 35, "low": 15, "baja": 15, "informational": 0, "info": 0,
             "informativa": 0}
MITIGATED_RE = re.compile(r"block|deny|denied|bloque|quarantin|cuarentena|drop|reject|prevent", re.I)
ALLOWED_RE = re.compile(r"allow|permit|delivered|success|permitido|entregado", re.I)


def is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved)


def _match(text: str) -> Rule | None:
    for rule, rx in _COMPILED:
        if rx.search(text):
            return rule
    return None


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "Crítica"
    if score >= 65:
        return "Alta"
    if score >= 40:
        return "Media"
    if score >= 20:
        return "Baja"
    return "Informativa"


def classify(df: pd.DataFrame) -> pd.DataFrame:
    """Devuelve una copia enriquecida del DataFrame normalizado."""
    out = df.copy()
    cats, tactics, techs, rules, verdicts, recs, scores, mitig = [], [], [], [], [], [], [], []

    # Contexto agregado
    src_counts = out["ip_origen"].value_counts()
    ext_src = out["ip_origen"].map(is_external)

    for i, row in out.iterrows():
        text = f"{row['tipo_evento']} {row['descripcion']} {row['proceso']}"
        rule = _match(text)
        sev_floor = SEV_FLOOR.get(str(row["severidad_original"]).lower(), 0)
        if rule is None:
            base = max(sev_floor, 20)
            cat, tac, tec, name = "Sin clasificar", "N/A", "N/A", "Sin regla"
            verdict = "Sospechoso - requiere análisis" if base >= 40 else "Benigno / ruido"
            rec = "Revisar manualmente; evaluar la creación de una regla de clasificación."
        else:
            base = max(rule.base, int(sev_floor * 0.9))
            cat, tac, tec, name = rule.category, rule.tactic, rule.technique, rule.name
            verdict, rec = rule.verdict, rule.recommendation

        score = float(base)
        action = str(row["accion"])
        is_mitigated = bool(MITIGATED_RE.search(action))
        if is_mitigated:
            score -= 15
        elif ALLOWED_RE.search(action) and base >= 60:
            score += 5

        host = str(row["host"]).upper()
        if host.startswith("SRV") or any(k in host for k in ("AD", "DB", "DC")):
            score += 6 if base >= 20 else 0
        if ext_src.iloc[i] and base >= 40:
            score += 4
        if src_counts.get(row["ip_origen"], 0) >= 10 and ext_src.iloc[i] and base >= 40:
            score += 6  # repetición desde la misma IP externa

        score = max(0.0, min(100.0, score))
        # Si se mitigó un evento "verdadero positivo", pasa a sospechoso de menor urgencia
        if is_mitigated and verdict == "Verdadero positivo probable" and score < 70:
            verdict = "Sospechoso - requiere análisis"

        cats.append(cat); tactics.append(tac); techs.append(tec); rules.append(name)
        verdicts.append(verdict); recs.append(rec); scores.append(round(score, 1))
        mitig.append("Mitigado" if is_mitigated else ("No mitigado" if base >= 40 else "N/A"))

    out["categoria"] = cats
    out["tactica_mitre"] = tactics
    out["tecnica_mitre"] = techs
    out["regla"] = rules
    out["riesgo"] = scores
    out["severidad"] = [severity_from_score(s) for s in scores]
    out["veredicto"] = verdicts
    out["mitigacion"] = mitig
    out["recomendacion"] = recs
    out["ip_origen_externa"] = ext_src.values
    return out


def build_incidents(df: pd.DataFrame, min_score: float = 65, min_events: int = 1) -> pd.DataFrame:
    """Correlaciona eventos relevantes por host en incidentes ordenados por riesgo."""
    rel = df[(df["riesgo"] >= 40) & df["tactica_mitre"].ne("N/A")]
    if rel.empty:
        return pd.DataFrame(columns=["incidente", "host", "usuarios", "inicio", "fin", "eventos",
                                     "tacticas", "riesgo_max", "severidad", "no_mitigados"])
    rows = []
    for host, g in rel.groupby("host"):
        if g["riesgo"].max() < min_score or len(g) < min_events or not host:
            continue
        g = g.sort_values("timestamp")
        tactics = list(dict.fromkeys(g["tactica_mitre"]))
        chain_bonus = min(10, 3 * max(0, len(tactics) - 1))
        rmax = min(100.0, g["riesgo"].max() + chain_bonus)
        rows.append({
            "host": host,
            "usuarios": ", ".join(sorted({u for u in g["usuario"] if u})[:3]),
            "inicio": g["timestamp"].min(), "fin": g["timestamp"].max(),
            "eventos": len(g), "tacticas": " → ".join(tactics),
            "riesgo_max": round(rmax, 1), "severidad": severity_from_score(rmax),
            "no_mitigados": int((g["mitigacion"] == "No mitigado").sum()),
        })
    inc = pd.DataFrame(rows).sort_values(["riesgo_max", "eventos"], ascending=False).reset_index(drop=True)
    inc.insert(0, "incidente", [f"INC-{i + 1:03d}" for i in range(len(inc))])
    return inc


def summarize(df: pd.DataFrame, incidents: pd.DataFrame) -> dict:
    """Métricas agregadas que alimentan dashboard, informe y agente IA."""
    ts = df["timestamp"].dropna()
    ext = df[df["ip_origen_externa"] & (df["riesgo"] >= 40)]
    top_ips = ext["ip_origen"].value_counts().head(8)
    return {
        "total": int(len(df)),
        "periodo_inicio": ts.min() if len(ts) else None,
        "periodo_fin": ts.max() if len(ts) else None,
        "por_severidad": {s: int((df["severidad"] == s).sum()) for s in SEVERITY_ORDER},
        "por_veredicto": {v: int((df["veredicto"] == v).sum()) for v in VERDICT_ORDER},
        "por_categoria": df["categoria"].value_counts().to_dict(),
        "por_tactica": df[df["tactica_mitre"] != "N/A"]["tactica_mitre"].value_counts().to_dict(),
        "por_fuente": df["fuente"].value_counts().to_dict(),
        "top_hosts": df[df["riesgo"] >= 40]["host"].replace("", pd.NA).dropna().value_counts().head(8).to_dict(),
        "top_ips_externas": {k: int(v) for k, v in top_ips.items()},
        "top_usuarios": df[df["riesgo"] >= 40]["usuario"].replace("", pd.NA).dropna().value_counts().head(8).to_dict(),
        "no_mitigados_altos": int(((df["riesgo"] >= 65) & (df["mitigacion"] == "No mitigado")).sum()),
        "mitigados": int((df["mitigacion"] == "Mitigado").sum()),
        "incidentes": int(len(incidents)),
        "riesgo_promedio_relevante": round(float(df[df["riesgo"] >= 40]["riesgo"].mean() or 0), 1) if (df["riesgo"] >= 40).any() else 0.0,
        "tecnicas": df[df["tecnica_mitre"] != "N/A"]["tecnica_mitre"].value_counts().head(10).to_dict(),
    }


def posture_score(summary: dict) -> tuple[int, str]:
    """Puntaje de exposición 0-100 (mayor = peor) y nivel textual."""
    s = summary["por_severidad"]
    raw = s["Crítica"] * 6 + s["Alta"] * 3 + s["Media"] * 1 + summary["no_mitigados_altos"] * 2
    score = int(min(100, raw / max(1, summary["total"]) * 60 + min(40, summary["incidentes"] * 8)))
    level = "Crítico" if score >= 75 else "Alto" if score >= 50 else "Moderado" if score >= 25 else "Bajo"
    return score, level
