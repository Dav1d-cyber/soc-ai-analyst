"""Carga y normalización de archivos Excel/CSV con eventos de seguridad.

Acepta nombres de columnas en español o inglés (y variantes comunes de SIEM)
y los mapea a un esquema canónico.
"""
from __future__ import annotations

import io
import re
import unicodedata
from typing import BinaryIO

import pandas as pd

CANONICAL = [
    "id", "timestamp", "fuente", "tipo_evento", "descripcion", "host",
    "ip_origen", "ip_destino", "usuario", "severidad_original", "accion",
    "puerto", "proceso",
]

ALIASES: dict[str, list[str]] = {
    "id": ["id", "event id", "eventid", "alert id", "alertid", "id evento"],
    "timestamp": ["timestamp", "fecha", "fecha hora", "time", "datetime", "date", "event time", "hora", "_time"],
    "fuente": ["fuente", "source", "log source", "sourcetype", "sensor", "origen del log", "producto"],
    "tipo_evento": ["tipo de evento", "tipo evento", "event type", "eventtype", "category", "categoria", "alert name", "nombre alerta", "rule", "regla", "signature"],
    "descripcion": ["descripcion", "description", "message", "mensaje", "detalle", "details", "summary", "resumen"],
    "host": ["host", "hostname", "equipo", "computer", "device", "dispositivo", "asset", "activo"],
    "ip_origen": ["ip origen", "src ip", "source ip", "src_ip", "srcip", "source address", "ip_src", "source"],
    "ip_destino": ["ip destino", "dst ip", "destination ip", "dst_ip", "dstip", "destination address", "ip_dst", "dest"],
    "usuario": ["usuario", "user", "username", "account", "cuenta", "user name"],
    "severidad_original": ["severidad original", "severidad", "severity", "priority", "prioridad", "level", "nivel"],
    "accion": ["accion", "action", "outcome", "resultado", "disposition", "status"],
    "puerto": ["puerto", "port", "dst port", "destination port", "dport"],
    "proceso": ["proceso", "process", "process name", "image", "proceso nombre"],
}


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode()
    return re.sub(r"[\s_\-]+", " ", s).strip().lower()


def _build_lookup() -> dict[str, str]:
    lookup: dict[str, str] = {}
    for canon, names in ALIASES.items():
        for n in names:
            lookup.setdefault(_norm(n), canon)
    return lookup


_LOOKUP = _build_lookup()


class LoaderError(ValueError):
    """Error de validación del archivo cargado."""


def read_file(file: BinaryIO | bytes, filename: str = "data.xlsx") -> pd.DataFrame:
    """Lee un .xlsx/.xls/.csv y devuelve un DataFrame normalizado."""
    raw = file if isinstance(file, (bytes, bytearray)) else file.read()
    buf = io.BytesIO(raw)
    name = filename.lower()
    try:
        if name.endswith(".csv"):
            df = pd.read_csv(buf)
        else:
            # Usa la hoja con más filas si hay varias.
            sheets = pd.read_excel(buf, sheet_name=None)
            if not sheets:
                raise LoaderError("El Excel no contiene hojas.")
            df = max(sheets.values(), key=len)
    except LoaderError:
        raise
    except Exception as exc:  # pragma: no cover
        raise LoaderError(f"No se pudo leer el archivo: {exc}") from exc
    return normalize(df)


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        raise LoaderError("El archivo no contiene filas de datos.")

    rename: dict[str, str] = {}
    used: set[str] = set()
    for col in df.columns:
        canon = _LOOKUP.get(_norm(col))
        if canon and canon not in used:
            rename[col] = canon
            used.add(canon)
    out = df.rename(columns=rename)

    if not ({"tipo_evento", "descripcion"} & set(out.columns)):
        raise LoaderError(
            "No se encontró ninguna columna de tipo de evento ni de descripción. "
            "Columnas detectadas: " + ", ".join(map(str, df.columns))
        )

    for c in CANONICAL:
        if c not in out.columns:
            out[c] = pd.NA

    if out["id"].isna().all():
        out["id"] = [f"EVT-{i + 1:05d}" for i in range(len(out))]

    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce")
    for c in ["fuente", "tipo_evento", "descripcion", "host", "ip_origen", "ip_destino",
              "usuario", "severidad_original", "accion", "proceso"]:
        out[c] = out[c].fillna("").astype(str).str.strip()
    out["puerto"] = pd.to_numeric(out["puerto"], errors="coerce")

    extra = [c for c in out.columns if c not in CANONICAL]
    return out[CANONICAL + extra].reset_index(drop=True)
