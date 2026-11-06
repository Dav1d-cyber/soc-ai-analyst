# 🛡️ SOC AI Analyst

Aplicación web que convierte un **Excel con eventos de seguridad** en:

1. **Clasificación automática** de cada evento (categoría, táctica/técnica **MITRE ATT&CK**, riesgo 0-100, severidad, veredicto de triaje, estado de mitigación y recomendación).
2. **Dashboard interactivo** (Streamlit + Plotly) con filtros, línea de tiempo, mapa de calor, top hosts/IPs y cronología por incidente.
3. **Informe PDF en dos niveles** — *Ejecutivo* (gerencia) y *Técnico* (equipo SOC) — redactado por un **agente de IA (Claude)**.

> Proyecto final del curso **Analista de SOC Nivel 2 — Comunidad DOJO**.

## Arquitectura

```
Excel/CSV ─► loader.py ─► classifier.py ─► incidentes (correlación por host)
              (normaliza     (reglas + MITRE +          │
               columnas)      score de riesgo)          ▼
                                              ai_agent.py (Claude API)  ──►  report.py ─► PDF
                                              └─ respaldo: motor local        (ReportLab)
                          app.py (Streamlit): dashboard · tabla · incidentes · informe
```

| Módulo | Responsabilidad |
|---|---|
| `soc/loader.py` | Lee .xlsx/.xls/.csv y mapea columnas en español/inglés a un esquema canónico |
| `soc/classifier.py` | 20 reglas con MITRE ATT&CK, score contextual (mitigación, criticidad de activo, IP externa, repetición), correlación en incidentes |
| `soc/ai_agent.py` | Envía a Claude un contexto compacto (no el Excel completo) y recibe el informe en JSON; si no hay API key o falla, usa un generador local |
| `soc/report.py` | PDF con portada, parte ejecutiva, parte técnica, gráficos y anexo |
| `app.py` | Interfaz web |
| `generate_report_cli.py` | Genera el PDF sin interfaz (útil para el repo/CI) |

## Instalación y uso

```bash
git clone <tu-repo>.git && cd soc-ai-analyst
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env        # y pega tu ANTHROPIC_API_KEY (opcional pero recomendado)
streamlit run app.py
```

1. Sube tu Excel (o pulsa **Usar datos de ejemplo**).
2. Revisa **Dashboard**, **Clasificación** e **Incidentes**.
3. En **Informe con IA** pulsa *Generar informe* y descarga el PDF.

El agente de IA puede ser **Gemini** (Google, con plan gratuito en aistudio.google.com) o **Claude** (Anthropic, requiere saldo); se elige en la barra lateral. Sin API key la app funciona con un motor local determinista (útil como respaldo en demos). **Para el entregable final genera el PDF con un proveedor de IA configurado**, de modo que la narrativa sea producida por el agente.

Por línea de comandos:

```bash
python generate_sample_data.py                                   # regenera el Excel de ejemplo
python generate_report_cli.py sample_data/security_events.xlsx -o reports/informe_soc_ejemplo.pdf --provider gemini
```

## Formato del Excel

Columnas reconocidas (español o inglés, el orden no importa): `Timestamp/Fecha`, `Fuente/Source`, `Tipo de Evento/Event Type`, `Descripción/Message`, `Host`, `IP Origen/Src IP`, `IP Destino/Dst IP`, `Usuario/User`, `Severidad/Severity`, `Acción/Action`, `Puerto/Port`, `Proceso/Process`. Solo se exige una columna de tipo de evento o de descripción.

## Cómo se calcula el riesgo

`riesgo = base de la regla (o piso por severidad original) − 15 si fue mitigado (+5 si se permitió un evento grave) + 6 si el host es servidor/AD/DB + 4 si la IP origen es externa + 6 si esa IP se repite ≥10 veces`.
Severidad: Crítica ≥85 · Alta ≥65 · Media ≥40 · Baja ≥20 · Informativa <20.
Los eventos con riesgo ≥40 se correlacionan por host en incidentes y se muestra su cadena de tácticas.

## Datos de ejemplo

`sample_data/security_events.xlsx` (378 eventos sintéticos) contiene 8 escenarios: fuerza bruta RDP, phishing + PowerShell, volcado de LSASS y movimiento lateral, exfiltración, preparación de ransomware, ataques web, actividad interna sospechosa y falsos positivos. **Los datos son ficticios.**

## Entregables del curso

- [x] Código fuente (este repositorio)
- [x] Informe PDF generado: `reports/informe_soc_ejemplo.pdf`
- [ ] Video de demostración: _agregar enlace aquí_ (guion en `docs/GUION_VIDEO.md`)

## Limitaciones

La clasificación es asistida por reglas e IA y debe validarse por un analista antes de contener en producción. El agente solo ve un resumen y los 25 eventos de mayor riesgo; no se envía el Excel completo.
