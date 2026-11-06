"""SOC AI Analyst — aplicación web (Streamlit).

Flujo: subir Excel -> clasificación automática -> dashboard interactivo -> informe PDF
(ejecutivo + técnico) redactado por un agente de IA (Claude) o por el motor local de respaldo.

Ejecutar:  streamlit run app.py
"""
from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

try:  # .env opcional
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from soc.ai_agent import DEFAULT_GEMINI_MODEL, DEFAULT_MODEL, generate_report_content
from soc.classifier import (SEVERITY_COLORS, SEVERITY_ORDER, build_incidents, classify,
                            posture_score, summarize)
from soc.loader import LoaderError, read_file
from soc.report import build_pdf

SAMPLE = Path(__file__).parent / "sample_data" / "security_events.xlsx"

st.set_page_config(page_title="SOC AI Analyst", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
      .block-container {padding-top: 1.6rem;}
      div[data-testid="stMetric"] {background: rgba(148,163,184,.10); border: 1px solid rgba(148,163,184,.25);
                                   padding: 12px 14px; border-radius: 10px;}
      .hero h1 {margin-bottom: 0;}
      .hero p {color: #94a3b8; margin-top: .2rem;}
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- pipeline
@st.cache_data(show_spinner="Procesando y clasificando eventos…")
def run_pipeline(raw: bytes, filename: str):
    df = read_file(raw, filename)
    classified = classify(df)
    incidents = build_incidents(classified)
    summary = summarize(classified, incidents)
    return classified, incidents, summary


def plotly_layout(fig, height=340):
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=40, b=10), legend_title_text="",
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


# --------------------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("1 · Cargar datos")
    up = st.file_uploader("Archivo Excel/CSV con eventos de seguridad", type=["xlsx", "xls", "csv"])
    use_sample = st.button("Usar datos de ejemplo", use_container_width=True, disabled=not SAMPLE.exists())
    if use_sample:
        st.session_state["use_sample"] = True
    if up is not None:
        st.session_state["use_sample"] = False

    st.divider()
    st.header("2 · Agente de IA")
    provider_label = st.selectbox("Proveedor de IA", ["Gemini (Google, plan gratuito)", "Claude (Anthropic)", "Motor local (sin IA)"])
    provider = {"Gemini": "gemini", "Claude": "claude", "Motor": "local"}[provider_label.split(" ")[0]]
    if provider == "gemini":
        api_key = st.text_input("Gemini API Key", type="password", value=os.getenv("GEMINI_API_KEY", ""),
                                help="Gratis en aistudio.google.com (Get API key).")
        model = st.text_input("Modelo", value=DEFAULT_GEMINI_MODEL)
    elif provider == "claude":
        api_key = st.text_input("Anthropic API Key", type="password", value=os.getenv("ANTHROPIC_API_KEY", ""),
                                help="Se crea en console.anthropic.com (requiere saldo).")
        model = st.text_input("Modelo", value=DEFAULT_MODEL)
    else:
        api_key, model = "", ""
    analyst = st.text_input("Nombre del analista", value="Analista SOC N2")
    st.caption("La API key solo se usa en tu sesión y no se guarda en disco.")

# --------------------------------------------------------------------------- header
st.markdown('<div class="hero"><h1>🛡️ SOC AI Analyst</h1>'
            '<p>Sube un Excel de eventos → clasificación MITRE ATT&CK → dashboard → informe ejecutivo y técnico con IA</p></div>',
            unsafe_allow_html=True)

raw = filename = None
if up is not None:
    raw, filename = up.getvalue(), up.name
elif st.session_state.get("use_sample") and SAMPLE.exists():
    raw, filename = SAMPLE.read_bytes(), SAMPLE.name

if raw is None:
    st.info("👈 Sube un archivo Excel o pulsa **Usar datos de ejemplo** para comenzar.")
    st.markdown(
        "**Columnas reconocidas** (español o inglés): Timestamp/Fecha, Fuente/Source, Tipo de Evento/Event Type, "
        "Descripción/Message, Host, IP Origen/Src IP, IP Destino/Dst IP, Usuario/User, Severidad/Severity, "
        "Acción/Action, Puerto/Port, Proceso/Process."
    )
    st.stop()

try:
    df, incidents, summary = run_pipeline(raw, filename)
except LoaderError as e:
    st.error(f"⚠️ {e}")
    st.stop()

# --------------------------------------------------------------------------- filtros
with st.sidebar:
    st.divider()
    st.header("3 · Filtros del dashboard")
    sev_sel = st.multiselect("Severidad", SEVERITY_ORDER, default=SEVERITY_ORDER)
    src_opts = sorted(df["fuente"].replace("", pd.NA).dropna().unique())
    src_sel = st.multiselect("Fuente", src_opts, default=src_opts)
    ts_valid = df["timestamp"].dropna()
    if len(ts_valid):
        d0, d1 = ts_valid.min().date(), ts_valid.max().date()
        rng = st.date_input("Rango de fechas", value=(d0, d1), min_value=d0, max_value=d1)
    else:
        rng = None

f = df[df["severidad"].isin(sev_sel) & (df["fuente"].isin(src_sel) | df["fuente"].eq(""))]
if rng and isinstance(rng, tuple) and len(rng) == 2:
    f = f[(f["timestamp"].isna()) | ((f["timestamp"].dt.date >= rng[0]) & (f["timestamp"].dt.date <= rng[1]))]

score, level = posture_score(summary)
tab_dash, tab_events, tab_inc, tab_report = st.tabs(["📊 Dashboard", "🗂️ Clasificación de eventos", "🚨 Incidentes", "📄 Informe con IA"])

# --------------------------------------------------------------------------- dashboard
with tab_dash:
    st.caption(f"Archivo: **{filename}** · {len(df):,} eventos · mostrando {len(f):,} tras filtros")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Nivel de exposición", f"{score}/100", level, delta_color="off")
    c2.metric("Eventos críticos/altos", int(f["severidad"].isin(["Crítica", "Alta"]).sum()))
    c3.metric("Incidentes correlacionados", summary["incidentes"])
    c4.metric("Altos no mitigados", summary["no_mitigados_altos"])
    c5.metric("Mitigados automáticamente", summary["mitigados"])

    a, b = st.columns([1, 2])
    with a:
        sev_df = f["severidad"].value_counts().reindex(SEVERITY_ORDER).dropna().reset_index()
        sev_df.columns = ["severidad", "eventos"]
        fig = px.pie(sev_df, names="severidad", values="eventos", hole=0.55, color="severidad",
                     color_discrete_map=SEVERITY_COLORS, title="Eventos por severidad")
        st.plotly_chart(plotly_layout(fig), use_container_width=True)
    with b:
        t = f.dropna(subset=["timestamp"]).copy()
        t["bloque"] = t["timestamp"].dt.floor("6h")
        tl = t.groupby(["bloque", "severidad"]).size().reset_index(name="eventos")
        fig = px.bar(tl, x="bloque", y="eventos", color="severidad", color_discrete_map=SEVERITY_COLORS,
                     category_orders={"severidad": SEVERITY_ORDER}, title="Línea de tiempo (bloques de 6 h)")
        st.plotly_chart(plotly_layout(fig), use_container_width=True)

    a, b = st.columns(2)
    with a:
        tac = f[f["tactica_mitre"] != "N/A"]["tactica_mitre"].value_counts().reset_index()
        tac.columns = ["tactica", "eventos"]
        fig = px.bar(tac.sort_values("eventos"), x="eventos", y="tactica", orientation="h",
                     title="Tácticas MITRE ATT&CK", color_discrete_sequence=["#6366f1"])
        st.plotly_chart(plotly_layout(fig), use_container_width=True)
    with b:
        cat = f["categoria"].value_counts().reset_index()
        cat.columns = ["categoria", "eventos"]
        fig = px.bar(cat.sort_values("eventos"), x="eventos", y="categoria", orientation="h",
                     title="Categorías de evento", color_discrete_sequence=["#0ea5e9"])
        st.plotly_chart(plotly_layout(fig), use_container_width=True)

    a, b, c = st.columns(3)
    risky = f[f["riesgo"] >= 40]
    with a:
        h = risky["host"].replace("", pd.NA).dropna().value_counts().head(8).reset_index()
        h.columns = ["host", "eventos"]
        fig = px.bar(h.sort_values("eventos"), x="eventos", y="host", orientation="h", title="Top hosts afectados",
                     color_discrete_sequence=["#ea580c"])
        st.plotly_chart(plotly_layout(fig, 300), use_container_width=True)
    with b:
        ips = risky[risky["ip_origen_externa"]]["ip_origen"].value_counts().head(8).reset_index()
        ips.columns = ["ip", "eventos"]
        fig = px.bar(ips.sort_values("eventos"), x="eventos", y="ip", orientation="h", title="Top IPs externas hostiles",
                     color_discrete_sequence=["#b91c1c"])
        st.plotly_chart(plotly_layout(fig, 300), use_container_width=True)
    with c:
        v = f["veredicto"].value_counts().reset_index()
        v.columns = ["veredicto", "eventos"]
        fig = px.bar(v, x="eventos", y="veredicto", orientation="h", title="Veredicto de triaje",
                     color_discrete_sequence=["#14b8a6"])
        st.plotly_chart(plotly_layout(fig, 300), use_container_width=True)

    hm = f.dropna(subset=["timestamp"]).copy()
    if len(hm):
        hm["dia"] = hm["timestamp"].dt.strftime("%Y-%m-%d")
        hm["hora"] = hm["timestamp"].dt.hour
        piv = hm[hm["riesgo"] >= 40].pivot_table(index="dia", columns="hora", values="id", aggfunc="count", fill_value=0)
        if not piv.empty:
            fig = px.imshow(piv, aspect="auto", color_continuous_scale="YlOrRd", title="Mapa de calor: eventos de riesgo por día y hora",
                            labels=dict(x="Hora", y="Día", color="Eventos"))
            st.plotly_chart(plotly_layout(fig, 300), use_container_width=True)

# --------------------------------------------------------------------------- eventos
with tab_events:
    st.subheader("Clasificación de eventos")
    q = st.text_input("Buscar (host, IP, usuario, descripción…)")
    ver_sel = st.multiselect("Veredicto", sorted(f["veredicto"].unique()), default=sorted(f["veredicto"].unique()))
    view = f[f["veredicto"].isin(ver_sel)]
    if q:
        mask = view.astype(str).apply(lambda col: col.str.contains(q, case=False, na=False)).any(axis=1)
        view = view[mask]
    cols = ["id", "timestamp", "fuente", "tipo_evento", "host", "ip_origen", "usuario", "categoria", "tactica_mitre",
            "tecnica_mitre", "riesgo", "severidad", "veredicto", "mitigacion", "recomendacion"]
    st.dataframe(view.sort_values("riesgo", ascending=False)[cols], use_container_width=True, height=520,
                 column_config={"riesgo": st.column_config.ProgressColumn("riesgo", min_value=0, max_value=100, format="%.0f"),
                                "timestamp": st.column_config.DatetimeColumn("timestamp", format="DD/MM/YYYY HH:mm")})
    st.download_button("⬇️ Descargar clasificación (CSV)", view[cols].to_csv(index=False).encode("utf-8-sig"),
                       "eventos_clasificados.csv", "text/csv")

# --------------------------------------------------------------------------- incidentes
with tab_inc:
    st.subheader("Incidentes correlacionados por host")
    if incidents.empty:
        st.success("No se detectaron incidentes de riesgo alto.")
    else:
        st.dataframe(incidents, use_container_width=True,
                     column_config={"riesgo_max": st.column_config.ProgressColumn("riesgo_max", min_value=0, max_value=100, format="%.0f")})
        sel = st.selectbox("Ver cronología del incidente", incidents["incidente"] + " · " + incidents["host"])
        host = sel.split(" · ")[1]
        tl = df[(df["host"] == host) & (df["riesgo"] >= 40)].sort_values("timestamp")
        fig = px.scatter(tl, x="timestamp", y="tactica_mitre", color="severidad", size="riesgo", hover_data=["tipo_evento", "descripcion", "mitigacion"],
                         color_discrete_map=SEVERITY_COLORS, title=f"Cronología de ataque en {host}")
        st.plotly_chart(plotly_layout(fig, 380), use_container_width=True)
        st.dataframe(tl[["timestamp", "fuente", "tipo_evento", "descripcion", "ip_origen", "usuario", "tecnica_mitre", "riesgo", "mitigacion", "recomendacion"]],
                     use_container_width=True)

# --------------------------------------------------------------------------- informe
with tab_report:
    st.subheader("Informe estructurado: ejecutivo + técnico")
    engine_txt = (f"{provider_label}" if (api_key and provider != "local") else "motor local (sin IA)")
    st.write(f"El agente redactará el informe con: **{engine_txt}**.")

    if st.button("🤖 Generar informe con IA", type="primary"):
        with st.spinner("El agente está analizando los hallazgos y redactando el informe…"):
            content, warn = generate_report_content(df, incidents, summary, api_key=api_key or None, model=model or None, provider=provider)
            pdf = build_pdf(df, incidents, summary, content, filename, analyst)
        st.session_state.update(report_content=content, report_pdf=pdf, report_warn=warn, report_file=filename)

    if "report_content" in st.session_state:
        content = st.session_state["report_content"]
        if st.session_state.get("report_warn"):
            st.warning(st.session_state["report_warn"])
        st.success(f"Informe generado · motor: {content.get('_engine')}")
        st.download_button("⬇️ Descargar informe PDF", st.session_state["report_pdf"],
                           f"informe_soc_{Path(st.session_state['report_file']).stem}.pdf", "application/pdf", type="primary")

        ex, te = content["executive"], content["technical"]
        e_tab, t_tab = st.tabs(["Vista previa · Ejecutivo", "Vista previa · Técnico"])
        with e_tab:
            st.markdown(f"### {ex['headline']}")
            st.markdown(f"**Nivel de riesgo:** {ex['risk_level']}")
            st.write(ex["summary"])
            st.markdown("**Impacto al negocio**")
            st.write(ex["business_impact"])
            st.markdown("**Hallazgos clave**")
            for k in ex["key_findings"]:
                st.markdown(f"- {k}")
            st.markdown("**Acciones prioritarias**")
            st.table(pd.DataFrame(ex["priority_actions"]))
        with t_tab:
            st.write(te["overview"])
            for a in te["incident_analyses"]:
                with st.expander(f"{a['incident']} · {a['host']} (confianza {a.get('confidence', 'N/D')})"):
                    st.write(a["narrative"])
                    st.markdown("**MITRE:** " + ", ".join(a.get("mitre", [])))
                    for c in a.get("containment", []):
                        st.markdown(f"- {c}")
            st.markdown("**IOCs / entidades**")
            st.dataframe(pd.DataFrame(te["iocs"]), use_container_width=True)
            st.markdown("**Brechas de detección**")
            for g in te["detection_gaps"]:
                st.markdown(f"- {g}")
            st.markdown("**Detecciones recomendadas**")
            for g in te["recommended_detections"]:
                st.markdown(f"- {g}")
            st.markdown("**Falsos positivos**")
            st.write(te["false_positive_notes"])
