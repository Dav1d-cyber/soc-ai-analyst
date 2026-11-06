"""Agente de IA que redacta el análisis (ejecutivo + técnico).

Modo 1 (recomendado): Claude vía API de Anthropic -> narrativa generada por IA
                      a partir de los datos ya clasificados.
Modo 2 (offline):     generador local basado en plantillas, sin API key. Sirve como
                      respaldo para que la herramienta nunca falle durante una demo.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

import pandas as pd

from .classifier import posture_score

DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")

SYSTEM_PROMPT = """Eres un Analista SOC Nivel 2 senior y redactas informes de incidentes para \
dos audiencias: la alta gerencia (resumen ejecutivo, sin jerga) y el equipo técnico (detalle \
accionable con MITRE ATT&CK). Escribes en español, de forma precisa, sin inventar datos: \
usa EXCLUSIVAMENTE la información del contexto JSON provisto. Si algo no está en los datos, \
indícalo como 'no determinado'. Responde SOLO con un objeto JSON válido, sin markdown."""

SCHEMA_HINT = """{
  "executive": {
    "headline": "frase de una línea con la conclusión principal",
    "summary": "2-3 párrafos para gerencia, sin jerga técnica",
    "business_impact": "impacto potencial al negocio en 3-4 oraciones",
    "risk_level": "Crítico|Alto|Moderado|Bajo",
    "key_findings": ["3 a 5 hallazgos clave"],
    "priority_actions": [{"priority": "Inmediata|Corto plazo|Mediano plazo", "action": "...", "owner": "rol sugerido"}]
  },
  "technical": {
    "overview": "párrafo técnico del panorama de ataque",
    "incident_analyses": [{"incident": "INC-001", "host": "...", "narrative": "cadena de ataque y evidencia", "mitre": ["T####"], "containment": ["pasos"], "confidence": "Alta|Media|Baja"}],
    "iocs": [{"type": "IP|Usuario|Host|Proceso", "value": "...", "note": "..."}],
    "detection_gaps": ["brechas de detección observadas"],
    "recommended_detections": ["reglas/casos de uso a implementar"],
    "false_positive_notes": "notas sobre falsos positivos y afinamiento"
  }
}"""


def build_context(df: pd.DataFrame, incidents: pd.DataFrame, summary: dict, max_events: int = 25) -> dict[str, Any]:
    """Contexto compacto (no se envía el Excel completo) para el agente."""
    top = df.sort_values("riesgo", ascending=False).head(max_events)
    cols = ["id", "timestamp", "fuente", "tipo_evento", "host", "ip_origen", "ip_destino", "usuario",
            "tecnica_mitre", "riesgo", "severidad", "mitigacion"]
    ev = top[cols].copy()
    ev["timestamp"] = ev["timestamp"].astype(str)
    inc = incidents.copy()
    for c in ("inicio", "fin"):
        inc[c] = inc[c].astype(str)

    def conv(v):
        if isinstance(v, (pd.Timestamp,)):
            return str(v)
        return v

    return {
        "resumen": {k: conv(v) for k, v in summary.items()},
        "puntaje_exposicion": posture_score(summary)[0],
        "incidentes_correlacionados": inc.head(10).to_dict("records"),
        "eventos_mas_riesgosos": ev.to_dict("records"),
    }


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("La respuesta no contiene JSON.")
    return json.loads(text[start:end + 1])


def generate_with_claude(context: dict, api_key: str, model: str = DEFAULT_MODEL) -> dict:
    """Llama a Claude y devuelve el informe estructurado."""
    import anthropic  # import perezoso: la app funciona sin el SDK en modo offline

    client = anthropic.Anthropic(api_key=api_key)
    user = (
        "Genera el informe de análisis SOC con el siguiente esquema JSON exacto:\n"
        f"{SCHEMA_HINT}\n\nCONTEXTO (datos reales ya clasificados):\n"
        f"{json.dumps(context, ensure_ascii=False, default=str)}"
    )
    msg = client.messages.create(
        model=model, max_tokens=6000,
        system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user}],
    )
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    data = _extract_json(text)
    data["_engine"] = f"Claude ({model})"
    return data



DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


def generate_with_gemini(context: dict, api_key: str, model: str = DEFAULT_GEMINI_MODEL) -> dict:
    """Llama a la API de Google Gemini (plan gratuito de AI Studio) por HTTP, sin SDK adicional."""
    import urllib.error
    import urllib.request

    user = (
        "Genera el informe de análisis SOC con el siguiente esquema JSON exacto:\n"
        f"{SCHEMA_HINT}\n\nCONTEXTO (datos reales ya clasificados):\n"
        f"{json.dumps(context, ensure_ascii=False, default=str)}"
    )
    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore")[:300]
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    parts = payload["candidates"][0]["content"]["parts"]
    text = "".join(p.get("text", "") for p in parts)
    data = _extract_json(text)
    data["_engine"] = f"Gemini ({model})"
    return data

# ---------------------------------------------------------------------------
# Generador local (respaldo sin API)
# ---------------------------------------------------------------------------
_ACTIONS_BY_TACTIC = {
    "Impact": ("Inmediata", "Aislar el/los servidores con indicios de cifrado y activar el plan de respuesta a ransomware; validar respaldos offline.", "CISO / Infraestructura"),
    "Exfiltration": ("Inmediata", "Bloquear destinos de exfiltración, preservar evidencia y evaluar obligaciones de notificación por fuga de datos.", "CISO / Legal"),
    "Credential Access": ("Inmediata", "Restablecer credenciales comprometidas (cuentas de servicio y privilegiadas) y habilitar MFA.", "Identidad / SOC"),
    "Command and Control": ("Inmediata", "Bloquear IPs/dominios de comando y control en el perímetro y buscar otros hosts que los contacten.", "SOC / Redes"),
    "Privilege Escalation": ("Inmediata", "Auditar y revertir cambios de membresía en grupos privilegiados.", "Identidad / SOC"),
    "Initial Access": ("Corto plazo", "Reforzar la protección de correo y exposición externa (RDP, aplicaciones web) con MFA y WAF.", "Seguridad / TI"),
}


def generate_local(df: pd.DataFrame, incidents: pd.DataFrame, summary: dict) -> dict:
    score, level = posture_score(summary)
    sev = summary["por_severidad"]
    crit_high = sev["Crítica"] + sev["Alta"]
    n_inc = summary["incidentes"]
    top_host = next(iter(summary["top_hosts"]), "N/D")
    top_ip = next(iter(summary["top_ips_externas"]), "N/D")
    tactics = list(summary["por_tactica"].keys())[:5]
    ini, fin = summary["periodo_inicio"], summary["periodo_fin"]
    periodo = f"{ini:%d/%m/%Y} al {fin:%d/%m/%Y}" if ini is not None and fin is not None and pd.notna(ini) else "el periodo analizado"
    fp = summary["por_veredicto"].get("Falso positivo probable", 0)
    noise = summary["por_veredicto"].get("Benigno / ruido", 0)

    headline = (f"Se detectaron {n_inc} incidentes correlacionados con nivel de exposición {level.lower()}; "
                f"{summary['no_mitigados_altos']} eventos de alto riesgo no fueron mitigados automáticamente.")
    summary_txt = (
        f"Durante {periodo} se analizaron {summary['total']} eventos de seguridad de múltiples fuentes. "
        f"De ellos, {crit_high} fueron clasificados como de severidad crítica o alta y se agruparon en {n_inc} "
        f"incidentes que requieren atención del equipo de respuesta.\n"
        f"Los patrones observados son consistentes con una intrusión en varias etapas: acceso inicial, ejecución, "
        f"robo de credenciales, movimiento hacia sistemas críticos y posible fuga de información. "
        f"El sistema más afectado fue {top_host} y la dirección externa más activa fue {top_ip}.\n"
        f"Una proporción importante de los eventos ({noise + fp} de {summary['total']}) correspondió a actividad rutinaria o "
        f"falsos positivos probables, lo que muestra oportunidades de afinamiento para reducir la carga operativa."
    )
    impact = ("La combinación de robo de credenciales, acceso a servidores críticos y transferencias de datos hacia el exterior "
              "puede derivar en fuga de información confidencial, interrupción de operaciones por cifrado de sistemas y "
              "exposición regulatoria. Cada hora sin contención aumenta el alcance potencial del incidente.")

    findings = []
    if n_inc:
        findings.append(f"{n_inc} incidentes correlacionados; el de mayor riesgo afecta a {incidents.iloc[0]['host']} (riesgo {incidents.iloc[0]['riesgo_max']}).")
    findings.append(f"{sev['Crítica']} eventos críticos y {sev['Alta']} altos sobre un total de {summary['total']} analizados.")
    if tactics:
        findings.append("Tácticas MITRE ATT&CK más frecuentes: " + ", ".join(tactics) + ".")
    findings.append(f"{summary['mitigados']} eventos fueron mitigados automáticamente por controles existentes (bloqueo/cuarentena).")
    findings.append(f"{fp} falsos positivos probables y {noise} eventos de ruido pueden reducirse con afinamiento de reglas.")

    actions = []
    seen = set()
    for t in list(summary["por_tactica"].keys()):
        if t in _ACTIONS_BY_TACTIC and t not in seen:
            p, a, o = _ACTIONS_BY_TACTIC[t]
            actions.append({"priority": p, "action": a, "owner": o})
            seen.add(t)
    actions.append({"priority": "Mediano plazo", "action": "Afinar reglas con alto ruido y documentar exclusiones para herramientas administrativas legítimas.", "owner": "SOC"})
    actions.append({"priority": "Mediano plazo", "action": "Ejecutar ejercicio de simulación (tabletop) basado en esta cadena de ataque.", "owner": "CISO"})

    # Análisis técnico por incidente
    analyses = []
    for _, r in incidents.head(8).iterrows():
        g = df[(df["host"] == r["host"]) & (df["riesgo"] >= 40)].sort_values("timestamp")
        techs = sorted({t.split(" - ")[0] for t in g["tecnica_mitre"] if t != "N/A"})
        steps = list(dict.fromkeys(g["regla"]))
        ips = [ip for ip in dict.fromkeys(g["ip_origen"]) if ip and g[g["ip_origen"] == ip]["ip_origen_externa"].any()]
        narrative = (
            f"Entre {r['inicio']:%d/%m %H:%M} y {r['fin']:%d/%m %H:%M} el host {r['host']} registró {r['eventos']} eventos relevantes "
            f"(usuarios: {r['usuarios'] or 'n/d'}). Secuencia observada: {' → '.join(steps)}. "
            f"Tácticas: {r['tacticas']}. "
            + (f"IPs externas involucradas: {', '.join(ips[:4])}. " if ips else "")
            + f"{r['no_mitigados']} eventos no fueron mitigados."
        )
        contain = list(dict.fromkeys(g.sort_values("riesgo", ascending=False)["recomendacion"]))[:4]
        analyses.append({
            "incident": r["incidente"], "host": r["host"], "narrative": narrative, "mitre": techs,
            "containment": contain,
            "confidence": "Alta" if r["riesgo_max"] >= 85 else "Media",
        })

    iocs = [{"type": "IP", "value": ip, "note": f"{n} eventos de riesgo desde esta IP externa"}
            for ip, n in summary["top_ips_externas"].items()]
    iocs += [{"type": "Host", "value": h, "note": f"{n} eventos de riesgo"} for h, n in list(summary["top_hosts"].items())[:4]]
    iocs += [{"type": "Usuario", "value": u, "note": f"{n} eventos de riesgo asociados"} for u, n in list(summary["top_usuarios"].items())[:4]]

    return {
        "executive": {
            "headline": headline, "summary": summary_txt, "business_impact": impact,
            "risk_level": level, "key_findings": findings, "priority_actions": actions,
        },
        "technical": {
            "overview": (f"Se identificaron {len(summary['tecnicas'])} técnicas MITRE ATT&CK distintas. Las más frecuentes: "
                         + "; ".join(f"{k} ({v})" for k, v in list(summary["tecnicas"].items())[:5]) + "."),
            "incident_analyses": analyses,
            "iocs": iocs,
            "detection_gaps": [
                "Eventos de inicio de sesión exitoso tras múltiples fallos no generan alerta de severidad alta por sí mismos.",
                "Phishing entregado al buzón sin cuarentena previa (acción 'Delivered').",
                "Movimiento lateral con credenciales administrativas desde estaciones de trabajo no está bloqueado.",
            ],
            "recommended_detections": [
                "Correlación: >10 fallos de autenticación + éxito desde la misma IP en 15 min.",
                "Office → PowerShell con parámetros -enc / descarga de red (cadena padre-hijo).",
                "Acceso a LSASS por procesos no firmados; alerta inmediata.",
                "Volumen saliente >1 GB hacia IP sin historial en 24 h desde servidores de archivos.",
                "Alta en grupos privilegiados fuera de ventana de cambios.",
            ],
            "false_positive_notes": (f"{fp} eventos fueron clasificados como falsos positivos probables (p. ej. herramientas de "
                                     "administración usadas por desarrollo y software no deseado en cuarentena). Se recomienda "
                                     "crear exclusiones documentadas por host/usuario en lugar de silenciar la regla."),
        },
        "_engine": "Motor local (sin API) — plantillas deterministas",
    }


def generate_report_content(df, incidents, summary, api_key: str | None = None, model: str | None = None,
                            provider: str = "claude") -> tuple[dict, str | None]:
    """Devuelve (contenido, advertencia).

    provider: "claude" | "gemini" | "local". Si la API falla o no hay clave, cae al motor local.
    """
    provider = (provider or "claude").lower()
    if provider == "local":
        return generate_local(df, incidents, summary), None

    env_var = "GEMINI_API_KEY" if provider == "gemini" else "ANTHROPIC_API_KEY"
    api_key = api_key or os.getenv(env_var)
    label = "Gemini" if provider == "gemini" else "Claude"
    if not api_key:
        return generate_local(df, incidents, summary), f"Sin API key de {label}: se usó el motor local. Configura {env_var} para narrativa con IA."
    try:
        ctx = build_context(df, incidents, summary)
        if provider == "gemini":
            return generate_with_gemini(ctx, api_key, model or DEFAULT_GEMINI_MODEL), None
        return generate_with_claude(ctx, api_key, model or DEFAULT_MODEL), None
    except Exception as exc:
        return generate_local(df, incidents, summary), f"No se pudo usar {label} ({type(exc).__name__}: {exc}). Se usó el motor local."
