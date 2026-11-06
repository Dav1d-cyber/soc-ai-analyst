# 🛡️ SOC AI Analyst

Aplicación web que convierte un **Excel con eventos de seguridad** en:

1. **Clasificación automática** de cada evento: categoría, táctica y técnica **MITRE ATT&CK**, riesgo de 0 a 100, severidad, veredicto de triaje, estado de mitigación y recomendación.
2. **Dashboard interactivo** (Streamlit + Plotly) con filtros, línea de tiempo, mapa de calor, top de hosts e IPs, y cronología por incidente.
3. **Informe PDF en dos niveles**, *ejecutivo* (gerencia) y *técnico* (equipo SOC), redactado por un **agente de IA** (Gemini o Claude).

> Proyecto final del curso **Analista de SOC Nivel 2** de la comunidad **DOJO**.
> Autor: **Seferino Sánchez**

## Entregables

| Entregable | Ubicación |
|---|---|
| Código fuente | Este repositorio |
| Informe PDF generado por el agente de IA | Carpeta [`reports/`](reports/) |
| Video de demostración | **PEGAR_AQUÍ_EL_ENLACE_DEL_VIDEO** |

## Cómo funciona

```
Excel/CSV ─► loader.py ─► classifier.py ─► incidentes (correlación por host)
              (normaliza     (reglas + MITRE +          │
               columnas)      score de riesgo)          ▼
                                              ai_agent.py (Gemini / Claude)  ──►  report.py ─► PDF
                                              └─ respaldo: motor local            (ReportLab)
                          app.py (Streamlit): dashboard · tabla · incidentes · informe
```

| Módulo | Responsabilidad |
|---|---|
| `soc/loader.py` | Lee .xlsx/.xls/.csv y mapea columnas en español o inglés a un esquema canónico |
| `soc/classifier.py` | Reglas mapeadas a MITRE ATT&CK, puntaje contextual (mitigación, criticidad del activo, IP externa, repetición) y correlación en incidentes |
| `soc/ai_agent.py` | Envía al modelo un contexto compacto (no el Excel completo) y recibe el informe en JSON. Si no hay clave o falla, usa un generador local |
| `soc/report.py` | PDF con portada, parte ejecutiva, parte técnica, gráficos y anexo |
| `app.py` | Interfaz web |
| `generate_report_cli.py` | Genera el PDF sin interfaz |

## Instalación y uso

```bash
git clone https://github.com/Dav1d-cyber/soc-ai-analyst.git
cd soc-ai-analyst
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

La app abre en `http://localhost:8501`. La próxima vez solo necesitas `source .venv/bin/activate` y `streamlit run app.py`.

1. Sube tu Excel o pulsa **Usar datos de ejemplo**.
2. Revisa las pestañas **Dashboard**, **Clasificación** e **Incidentes**.
3. En **Informe con IA** elige el proveedor, pulsa *Generar informe* y descarga el PDF.

### Agente de IA

En la barra lateral se elige el proveedor:

- **Gemini** (Google AI Studio, con plan gratuito): crea tu clave en [aistudio.google.com](https://aistudio.google.com).
- **Claude** (Anthropic): crea tu clave en [console.anthropic.com](https://console.anthropic.com) (requiere saldo).
- **Motor local**: sin IA, plantillas deterministas. Sirve como respaldo.

Puedes pegar la clave en la barra lateral, o guardarla en un archivo `.env`:

```bash
cp .env.example .env     # y completa GEMINI_API_KEY o ANTHROPIC_API_KEY
```

El archivo `.env` está en `.gitignore` y **no debe subirse al repositorio**.

### Línea de comandos

```bash
python generate_sample_data.py   # regenera el Excel de ejemplo
python generate_demo_data.py     # regenera el Excel de la demo
python generate_report_cli.py sample_data/security_events.xlsx -o reports/informe.pdf --provider gemini
```

## Formato del Excel

Columnas reconocidas (español o inglés, el orden no importa): `Timestamp/Fecha`, `Fuente/Source`, `Tipo de Evento/Event Type`, `Descripción/Message`, `Host/Hostname`, `IP Origen/Src IP`, `IP Destino/Dst IP`, `Usuario/User`, `Severidad/Severity`, `Acción/Action`, `Puerto/Port`, `Proceso/Process`. Solo se exige una columna de tipo de evento o de descripción.

## Cómo se calcula el riesgo

`riesgo = base de la regla (o piso por severidad original) − 15 si fue mitigado (+5 si se permitió un evento grave) + 6 si el host es servidor/AD/DB + 4 si la IP origen es externa + 6 si esa IP se repite ≥10 veces`

Severidad: Crítica ≥85 · Alta ≥65 · Media ≥40 · Baja ≥20 · Informativa <20.
Los eventos con riesgo ≥40 se correlacionan por host en incidentes, y se muestra su cadena de tácticas.

## Datos de ejemplo

Todos los datos son **ficticios**, generados con scripts incluidos en el repositorio.

| Archivo | Eventos | Contenido |
|---|---|---|
| `sample_data/security_events.xlsx` | 378 | Fuerza bruta RDP, phishing + PowerShell, volcado de LSASS, movimiento lateral, exfiltración, ransomware, ataques web, actividad interna sospechosa y falsos positivos |
| `sample_data/demo_video_eventos.xlsx` | 408 | Empresa ficticia "Aurora Logística", encabezados en inglés, con toma de cuenta VPN, cadena phishing → C2 → credenciales, exfiltración y ransomware |

## Limitaciones

- La clasificación es asistida por reglas e IA y debe ser validada por un analista antes de ejecutar acciones de contención en producción.
- El agente recibe un resumen y los 25 eventos de mayor riesgo, no el Excel completo.
- En el plan gratuito de algunos proveedores, los datos enviados pueden usarse para mejorar sus productos. No cargues eventos reales de una organización.

## Mejoras futuras

- Más reglas de detección y afinamiento por entorno.
- Integración directa con un SIEM en lugar de Excel.
- Enriquecimiento de IPs con inteligencia de amenazas.
