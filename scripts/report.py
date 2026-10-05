"""Genera evidence/REPORT.md con el resultado antes/despues por categoria."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "evidence"


def main() -> None:
    runs = sorted(p for p in ROOT.iterdir() if p.is_dir()) if ROOT.exists() else []
    if not runs:
        print("No hay evidencia. Ejecuta: make evidence"); return
    latest = runs[-1]
    rows: dict[str, dict[str, dict]] = {}
    for f in sorted(latest.glob("*.json")):
        data = json.loads(f.read_text())
        rows.setdefault(data["category"], {})[data["profile"]] = data
    lines = [f"# Reporte de evidencia ({latest.name})", "",
             "| Categoria | Sin proteccion (baseline) | Con proteccion (secure) |", "| --- | --- | --- |"]
    for cat, profiles in rows.items():
        def summary(d):
            if not d:
                return "-"
            keep = {k: v for k, v in d.items() if k not in ("test", "category", "profile", "recorded_at")}
            return "<br>".join(f"`{k}`: {json.dumps(v, ensure_ascii=False)}" for k, v in keep.items())
        lines.append(f"| {cat} | {summary(profiles.get('baseline'))} | {summary(profiles.get('secure'))} |")
    out = ROOT / "REPORT.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"Reporte escrito en {out}")


if __name__ == "__main__":
    main()
