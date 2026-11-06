"""Genera el informe PDF desde la línea de comandos (sin interfaz web).

Uso:
  python generate_report_cli.py sample_data/security_events.xlsx -o reports/informe_soc_ejemplo.pdf
  ANTHROPIC_API_KEY=sk-... python generate_report_cli.py mis_eventos.xlsx          # Claude
  GEMINI_API_KEY=... python generate_report_cli.py mis_eventos.xlsx --provider gemini  # Gemini (gratis)
"""
from __future__ import annotations

import argparse
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from soc.ai_agent import generate_report_content
from soc.classifier import build_incidents, classify, summarize
from soc.loader import read_file
from soc.report import build_pdf


def main() -> None:
    ap = argparse.ArgumentParser(description="Excel de eventos -> informe PDF SOC (ejecutivo + técnico)")
    ap.add_argument("excel", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=None)
    ap.add_argument("--provider", choices=["claude", "gemini", "local"], default="claude")
    ap.add_argument("--model", default=None)
    ap.add_argument("--analyst", default="Analista SOC N2")
    a = ap.parse_args()

    df = read_file(a.excel.read_bytes(), a.excel.name)
    classified = classify(df)
    incidents = build_incidents(classified)
    summary = summarize(classified, incidents)
    content, warn = generate_report_content(classified, incidents, summary, model=a.model, provider=a.provider)
    if warn:
        print("AVISO:", warn)
    out = a.output or Path("reports") / f"informe_soc_{a.excel.stem}.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(build_pdf(classified, incidents, summary, content, a.excel.name, a.analyst))
    print(f"Motor: {content.get('_engine')}\nInforme generado: {out}")


if __name__ == "__main__":
    main()
