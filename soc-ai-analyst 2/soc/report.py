"""Generación del informe PDF (nivel ejecutivo + nivel técnico) con ReportLab y Matplotlib."""
from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_CENTER  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph,  # noqa: E402
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from .classifier import SEVERITY_COLORS, SEVERITY_ORDER, posture_score  # noqa: E402

NAVY = colors.HexColor("#0f172a")
ACCENT = colors.HexColor("#0ea5e9")
LIGHT = colors.HexColor("#f1f5f9")
GRID = colors.HexColor("#cbd5e1")
LEVEL_COLOR = {"Crítico": "#b91c1c", "Alto": "#ea580c", "Moderado": "#d97706", "Bajo": "#16a34a"}


def _register_fonts() -> tuple[str, str, str]:
    """DejaVu (incluida con matplotlib) para soportar tildes, ñ y flechas."""
    d = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
    try:
        pdfmetrics.registerFont(TTFont("DV", str(d / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("DV-B", str(d / "DejaVuSans-Bold.ttf")))
        pdfmetrics.registerFont(TTFont("DV-I", str(d / "DejaVuSans-Oblique.ttf")))
        pdfmetrics.registerFontFamily("DV", normal="DV", bold="DV-B", italic="DV-I", boldItalic="DV-B")
        return "DV", "DV-B", "DV-I"
    except Exception:  # pragma: no cover
        return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"


F, FB, FI = _register_fonts()
plt.rcParams["font.family"] = "DejaVu Sans"


def _styles():
    ss = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("t", parent=ss["Title"], fontName=FB, fontSize=26, leading=31, textColor=colors.white, alignment=0),
        "subtitle": ParagraphStyle("st", fontName=F, fontSize=12, leading=16, textColor=colors.HexColor("#cbd5e1")),
        "h1": ParagraphStyle("h1", fontName=FB, fontSize=17, leading=21, textColor=NAVY, spaceBefore=4, spaceAfter=8),
        "h2": ParagraphStyle("h2", fontName=FB, fontSize=12.5, leading=16, textColor=ACCENT, spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("h3", fontName=FB, fontSize=10.5, leading=14, textColor=NAVY, spaceBefore=6, spaceAfter=2),
        "body": ParagraphStyle("b", fontName=F, fontSize=9.5, leading=14, textColor=colors.HexColor("#1e293b"), spaceAfter=5),
        "bullet": ParagraphStyle("bl", fontName=F, fontSize=9.5, leading=13.5, leftIndent=12, bulletIndent=2, spaceAfter=2),
        "cell": ParagraphStyle("c", fontName=F, fontSize=8, leading=10.5),
        "cellb": ParagraphStyle("cb", fontName=FB, fontSize=8, leading=10.5, textColor=colors.white),
        "small": ParagraphStyle("sm", fontName=FI, fontSize=8, leading=11, textColor=colors.HexColor("#64748b")),
        "kpi_n": ParagraphStyle("kn", fontName=FB, fontSize=20, leading=24, alignment=TA_CENTER),
        "kpi_l": ParagraphStyle("kl", fontName=F, fontSize=8, leading=10, alignment=TA_CENTER, textColor=colors.HexColor("#475569")),
        "headline": ParagraphStyle("hl", fontName=FB, fontSize=12.5, leading=17, textColor=NAVY, borderPadding=8,
                                    backColor=LIGHT, spaceAfter=10),
    }
    return s


def P(text, style):
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _fig_to_image(fig, width_cm: float) -> Image:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    img = Image(buf)
    ratio = img.imageHeight / img.imageWidth
    img.drawWidth, img.drawHeight = width_cm * cm, width_cm * cm * ratio
    return img


def _style_ax(ax):
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.spines["left"].set_color("#cbd5e1"); ax.spines["bottom"].set_color("#cbd5e1")
    ax.tick_params(colors="#475569", labelsize=8)


def chart_severity(summary):
    sev = [(k, summary["por_severidad"][k]) for k in SEVERITY_ORDER if summary["por_severidad"][k] > 0]
    fig, ax = plt.subplots(figsize=(4.2, 3.2))
    wedges, _ = ax.pie([v for _, v in sev], colors=[SEVERITY_COLORS[k] for k, _ in sev], startangle=90,
                       wedgeprops=dict(width=0.38, edgecolor="white"))
    ax.text(0, 0, f"{summary['total']}\neventos", ha="center", va="center", fontsize=11, fontweight="bold", color="#0f172a")
    ax.legend(wedges, [f"{k}: {v}" for k, v in sev], loc="center left", bbox_to_anchor=(0.95, 0.5), frameon=False, fontsize=8)
    ax.set_title("Eventos por severidad", fontsize=10, fontweight="bold", color="#0f172a")
    return fig


def chart_hbar(data: dict, title: str, color="#0ea5e9", n=8, figsize=(4.6, 3.2)):
    items = list(data.items())[:n][::-1]
    fig, ax = plt.subplots(figsize=figsize)
    ax.barh([str(k)[:34] for k, _ in items], [v for _, v in items], color=color)
    for i, (_, v) in enumerate(items):
        ax.text(v, i, f" {v}", va="center", fontsize=8, color="#334155")
    ax.set_title(title, fontsize=10, fontweight="bold", color="#0f172a", loc="left")
    _style_ax(ax)
    return fig


def chart_timeline(df: pd.DataFrame):
    d = df[df["timestamp"].notna()].copy()
    d["hora"] = d["timestamp"].dt.floor("6h")
    fig, ax = plt.subplots(figsize=(7.6, 2.9))
    bottom = None
    for sev in ["Informativa", "Baja", "Media", "Alta", "Crítica"]:
        s = d[d["severidad"] == sev].groupby("hora").size()
        s = s.reindex(sorted(d["hora"].unique()), fill_value=0)
        ax.bar(s.index, s.values, width=0.2, bottom=bottom, color=SEVERITY_COLORS[sev], label=sev)
        bottom = s.values if bottom is None else bottom + s.values
    ax.set_title("Línea de tiempo de eventos (bloques de 6 h)", fontsize=10, fontweight="bold", color="#0f172a", loc="left")
    ax.legend(ncol=5, frameon=False, fontsize=7.5, loc="upper right")
    _style_ax(ax)
    fig.autofmt_xdate()
    return fig


def chart_gauge(score: int, level: str):
    fig, ax = plt.subplots(figsize=(3.2, 1.9))
    import numpy as np
    theta = np.linspace(np.pi, 0, 200)
    for lo, hi, c in [(0, 25, "#16a34a"), (25, 50, "#d97706"), (50, 75, "#ea580c"), (75, 100, "#b91c1c")]:
        t = np.linspace(np.pi * (1 - lo / 100), np.pi * (1 - hi / 100), 50)
        ax.fill_between(np.cos(t), np.sin(t), 0.62 * np.sin(t), color=c, alpha=0.9) if False else None
        ax.plot(np.cos(t), np.sin(t), color=c, lw=12, solid_capstyle="butt")
    a = np.pi * (1 - score / 100)
    ax.plot([0, 0.78 * np.cos(a)], [0, 0.78 * np.sin(a)], color="#0f172a", lw=3)
    ax.scatter([0], [0], s=60, color="#0f172a", zorder=5)
    ax.text(0, -0.28, f"{score}/100 · {level}", ha="center", fontsize=11, fontweight="bold", color="#0f172a")
    ax.set_xlim(-1.2, 1.2); ax.set_ylim(-0.45, 1.15); ax.axis("off"); ax.set_aspect("equal")
    return fig


def _table(data, col_widths, header=True, zebra=True, font_size=8):
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    st = [
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        st += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
    if zebra:
        for r in range(1, len(data)):
            if r % 2 == 0:
                st.append(("BACKGROUND", (0, r), (-1, r), LIGHT))
    t.setStyle(TableStyle(st))
    return t


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(F, 7.5)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(2 * cm, 1.1 * cm, "Informe de Análisis SOC · Generado automáticamente por IA · Confidencial")
    canvas.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Página {doc.page}")
    canvas.setStrokeColor(GRID)
    canvas.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)
    canvas.restoreState()


def _cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, A4[1] - 0.6 * cm, A4[0], 0.6 * cm, fill=1, stroke=0)
    canvas.restoreState()


def build_pdf(df: pd.DataFrame, incidents: pd.DataFrame, summary: dict, content: dict,
              source_name: str = "eventos.xlsx", analyst: str = "Analista SOC N2") -> bytes:
    """Construye el PDF completo y devuelve sus bytes."""
    S = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm,
                            bottomMargin=2 * cm, title="Informe de Análisis SOC", author=analyst)
    W = A4[0] - 4 * cm
    score, level = posture_score(summary)
    ex, te = content["executive"], content["technical"]
    level = ex.get("risk_level", level)
    ini, fin = summary["periodo_inicio"], summary["periodo_fin"]
    periodo = f"{ini:%d/%m/%Y %H:%M} – {fin:%d/%m/%Y %H:%M}" if ini is not None and pd.notna(ini) else "N/D"
    story = []

    # ---------------- Portada ----------------
    story += [Spacer(1, 5.5 * cm),
              Paragraph("Informe de Análisis<br/>de Eventos de Seguridad", S["title"]), Spacer(1, 0.6 * cm),
              Paragraph("Nivel Ejecutivo y Nivel Técnico", S["subtitle"]), Spacer(1, 4 * cm)]
    meta = [["Archivo analizado", source_name], ["Periodo", periodo],
            ["Eventos procesados", f"{summary['total']:,}"], ["Incidentes correlacionados", str(summary["incidentes"])],
            ["Generado el", datetime.now().strftime("%d/%m/%Y %H:%M")],
            ["Motor de análisis", content.get("_engine", "N/D")], ["Elaborado por", analyst]]
    mt = Table([[Paragraph(f'<font color="#94a3b8">{escape(a)}</font>', S["cell"]),
                 Paragraph(f'<font color="white">{escape(b)}</font>', S["cell"])] for a, b in meta],
               colWidths=[4.5 * cm, W - 4.5 * cm])
    mt.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#334155")),
                            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story += [mt, PageBreak()]

    # ---------------- PARTE I: EJECUTIVA ----------------
    story += [Paragraph("PARTE I — Resumen Ejecutivo", S["h1"]), P(ex["headline"], S["headline"])]

    kp = [[Paragraph(f'<font color="{LEVEL_COLOR.get(level, "#0f172a")}">{escape(level)}</font>', S["kpi_n"]),
           Paragraph(str(summary["por_severidad"]["Crítica"] + summary["por_severidad"]["Alta"]), S["kpi_n"]),
           Paragraph(str(summary["incidentes"]), S["kpi_n"]),
           Paragraph(str(summary["no_mitigados_altos"]), S["kpi_n"]),
           Paragraph(str(summary["mitigados"]), S["kpi_n"])],
          [Paragraph(t, S["kpi_l"]) for t in ("Nivel de riesgo", "Eventos críticos/altos", "Incidentes", "Altos no mitigados", "Mitigados automáticamente")]]
    kt = Table(kp, colWidths=[W / 5] * 5)
    kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, GRID), ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
                            ("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [kt, Spacer(1, 8), Paragraph("Situación general", S["h2"])]
    for para in str(ex["summary"]).split("\n"):
        if para.strip():
            story.append(P(para.strip(), S["body"]))

    row = Table([[_fig_to_image(chart_gauge(score, level), 6.6), _fig_to_image(chart_severity(summary), 9.6)]],
                colWidths=[W * 0.4, W * 0.6])
    row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story += [row, Paragraph("Impacto potencial al negocio", S["h2"]), P(ex["business_impact"], S["body"]),
              Paragraph("Hallazgos clave", S["h2"])]
    for f in ex["key_findings"]:
        story.append(Paragraph(escape(str(f)), S["bullet"], bulletText="•"))

    story.append(Paragraph("Acciones prioritarias", S["h2"]))
    acts = [[Paragraph("Prioridad", S["cellb"]), Paragraph("Acción recomendada", S["cellb"]), Paragraph("Responsable", S["cellb"])]]
    for a in ex["priority_actions"]:
        acts.append([P(a.get("priority", ""), S["cell"]), P(a.get("action", ""), S["cell"]), P(a.get("owner", ""), S["cell"])])
    story += [_table(acts, [2.6 * cm, W - 6.6 * cm, 4 * cm]), PageBreak()]

    # ---------------- PARTE II: TÉCNICA ----------------
    story += [Paragraph("PARTE II — Análisis Técnico", S["h1"]),
              Paragraph("Metodología", S["h2"]),
              P("El archivo Excel se normalizó a un esquema canónico y cada evento se clasificó con reglas de detección mapeadas a MITRE ATT&CK. "
                "Se calculó un puntaje de riesgo (0-100) que combina la severidad original, el comportamiento observado, la criticidad del activo, "
                "la repetición desde IPs externas y si el evento fue mitigado. Los eventos de riesgo relevante se correlacionaron por host para "
                "formar incidentes. Umbrales de severidad: Crítica ≥85, Alta ≥65, Media ≥40, Baja ≥20.", S["body"]),
              Paragraph("Panorama técnico", S["h2"]), P(te["overview"], S["body"]),
              _fig_to_image(chart_timeline(df), 16.5)]

    r2 = Table([[_fig_to_image(chart_hbar(summary["por_tactica"], "Tácticas MITRE ATT&CK", "#6366f1"), 8.2),
                 _fig_to_image(chart_hbar(summary["por_categoria"], "Categorías de evento", "#0ea5e9"), 8.2)]],
               colWidths=[W / 2] * 2)
    story += [r2]

    if len(incidents):
        story += [Paragraph("Incidentes correlacionados", S["h2"])]
        rows = [[Paragraph(h, S["cellb"]) for h in ("ID", "Host", "Inicio", "Ev.", "Riesgo", "Severidad", "Cadena de tácticas")]]
        for _, r in incidents.iterrows():
            sc = SEVERITY_COLORS.get(r["severidad"], "#000")
            rows.append([P(r["incidente"], S["cell"]), P(r["host"], S["cell"]), P(f"{r['inicio']:%d/%m %H:%M}", S["cell"]),
                         P(r["eventos"], S["cell"]), P(r["riesgo_max"], S["cell"]),
                         Paragraph(f'<font color="{sc}"><b>{escape(r["severidad"])}</b></font>', S["cell"]),
                         P(r["tacticas"], S["cell"])])
        story.append(_table(rows, [1.5 * cm, 2.3 * cm, 2.2 * cm, 0.9 * cm, 1.5 * cm, 2.0 * cm, W - 10.4 * cm]))

    story += [Paragraph("Análisis detallado por incidente", S["h2"])]
    for a in te["incident_analyses"]:
        block = [Paragraph(f"{escape(a.get('incident', ''))} · {escape(a.get('host', ''))} "
                           f"<font size=8 color='#64748b'>(confianza: {escape(str(a.get('confidence', 'N/D')))})</font>", S["h3"]),
                 P(a.get("narrative", ""), S["body"])]
        if a.get("mitre"):
            block.append(Paragraph("<b>MITRE:</b> " + escape(", ".join(a["mitre"])), S["body"]))
        for c in a.get("containment", []):
            block.append(Paragraph(escape(str(c)), S["bullet"], bulletText="›"))
        block.append(Spacer(1, 4))
        story.append(KeepTogether(block))

    story.append(Paragraph("Indicadores de compromiso y entidades de interés", S["h2"]))
    ioc = [[Paragraph(h, S["cellb"]) for h in ("Tipo", "Valor", "Observación")]]
    for i in te["iocs"][:20]:
        ioc.append([P(i.get("type", ""), S["cell"]), P(i.get("value", ""), S["cell"]), P(i.get("note", ""), S["cell"])])
    story.append(_table(ioc, [2.2 * cm, 4.5 * cm, W - 6.7 * cm]))

    story.append(Paragraph("Brechas de detección", S["h2"]))
    for g in te["detection_gaps"]:
        story.append(Paragraph(escape(str(g)), S["bullet"], bulletText="•"))
    story.append(Paragraph("Detecciones recomendadas", S["h2"]))
    for g in te["recommended_detections"]:
        story.append(Paragraph(escape(str(g)), S["bullet"], bulletText="•"))
    story += [Paragraph("Falsos positivos y afinamiento", S["h2"]), P(te["false_positive_notes"], S["body"])]

    # Anexo
    story += [PageBreak(), Paragraph("Anexo — Top 25 eventos por riesgo", S["h1"])]
    top = df.sort_values(["riesgo", "timestamp"], ascending=[False, True]).head(25)
    rows = [[Paragraph(h, S["cellb"]) for h in ("ID", "Fecha", "Host", "Evento", "Técnica", "Riesgo", "Mitig.")]]
    for _, r in top.iterrows():
        ts = f"{r['timestamp']:%d/%m %H:%M}" if pd.notna(r["timestamp"]) else ""
        rows.append([P(r["id"], S["cell"]), P(ts, S["cell"]), P(r["host"], S["cell"]), P(r["tipo_evento"], S["cell"]),
                     P(str(r["tecnica_mitre"]).split(" - ")[0], S["cell"]), P(r["riesgo"], S["cell"]), P(r["mitigacion"], S["cell"])])
    story.append(_table(rows, [2.0 * cm, 2.2 * cm, 2.4 * cm, W - 12.8 * cm, 2.3 * cm, 1.5 * cm, 2.4 * cm]))
    story += [Spacer(1, 10),
              P("Nota: la clasificación es asistida por reglas e IA y debe ser validada por un analista antes de ejecutar acciones de contención en producción.", S["small"])]

    doc.build(story, onFirstPage=_cover, onLaterPages=_footer)
    return buf.getvalue()
