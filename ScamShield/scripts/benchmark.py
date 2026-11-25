"""Benchmark ScamShield and write an Excel report with formula-based metrics.

Run:  python scripts/benchmark.py   (from the project folder)
Creates: data/results/scamshield_v3_report.xlsx

Datasets
  Dev50       - development set (rules/thresholds were tuned while looking at it -> optimistic)
  Sealed100   - independent, written by a separate agent that never saw the rules (fair test)
  Injection30 - prompt-injection test cases, also written by the separate agent
  GenAI20     - 20-message GenAI security test: engine vs Gemini alone vs hybrid (recorded run)

The previous version (v2) was removed from the project; its scores are kept in the report's
"History" table as RECORDED numbers from 25-Nov-2026.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from sklearn.metrics import accuracy_score, f1_score

ROOT = Path(__file__).resolve().parent.parent   # project folder
sys.path.insert(0, str(ROOT))
from engine import analyze  # noqa: E402

TESTS = ROOT / "data" / "test_sets"
OUT = ROOT / "data" / "results" / "scamshield_v3_report.xlsx"
LABELS = ["Scam", "Suspicious", "Safe"]
DATASETS = [
    ("Dev50", TESTS / "scamshield_50_message_benchmark.csv", "sample_message", "risk_indicators",
     "Development set: rules and thresholds were tuned while looking at it, so its score is OPTIMISTIC."),
    ("Sealed100", TESTS / "sealed" / "independent_100.csv", "message", "category",
     "Independent sealed set written by a separate agent that never saw the rules. This is the FAIR score."),
    ("Injection30", TESTS / "sealed" / "injection_30.csv", "message", "injection_type",
     "Prompt-injection messages (also sealed). Tests that hidden instructions cannot change the verdict."),
]

# Recorded 25-Nov-2026 by running each version on the same sets (old version code since removed).
# "-" = that version was not tested on that set (the set did not exist yet).
HISTORY = [
    # dataset,      metric,                               v1,       v2,       v3
    ("Dev50",       "Exact matches",                      "38/50",  "47/50",  "47/50"),
    ("Dev50",       "Scams flagged (Scam or Suspicious)",  "20/20",  "20/20",  "20/20"),
    ("Dev50",       "Safe called Scam",                   1,        0,        0),
    ("Sealed100",   "Exact matches",                      "-",      "63/100", "77/100"),
    ("Sealed100",   "Macro F1",                           "-",      0.609,    0.737),
    ("Sealed100",   "Scams flagged (Scam or Suspicious)",  "-",      "34/40",  "40/40"),
    ("Sealed100",   "Missed scams (Scam -> Safe)",        "-",      6,        0),
    ("Sealed100",   "Safe called Scam",                   "-",      5,        4),
    ("Injection30", "Exact matches",                      "-",      "24/30",  "25/30"),
    ("Injection30", "Missed scams (Scam -> Safe)",        "-",      3,        1),
]
CHANGES = [
    ("v1", "ML model (TF-IDF + Logistic Regression) + 12 English red-flag rules + Streamlit app."),
    ("v2", "Added Good Signs, Things to Verify, Hinglish/Hindi OTP & urgency words (after the 50-message test)."),
    ("v3", "Weighted rules in 6 languages, context combinations, Gemini safety (JSON, quote checks, can only raise risk), "
           "FastAPI + HTML/CSS/JS website, 102 automated tests."),
]

FONT = "Arial"
HEAD = (Font(name=FONT, bold=True, color="FFFFFF"), PatternFill("solid", start_color="1F3864"))
BODY, BOLD = Font(name=FONT, size=10), Font(name=FONT, size=10, bold=True)
NOTE = Font(name=FONT, size=9, italic=True, color="595959")
THIN = Border(*(Side(style="thin", color="BFBFBF"),) * 4)
GREEN, RED = PatternFill("solid", start_color="C6EFCE"), PatternFill("solid", start_color="FFC7CE")
WRAP = Alignment(wrap_text=True, vertical="top")


def head(ws, row, values, col=1):
    for i, v in enumerate(values):
        c = ws.cell(row=row, column=col + i, value=v)
        c.font, c.fill, c.border = HEAD[0], HEAD[1], THIN
        c.alignment = Alignment(wrap_text=True, vertical="center")


# ---------------- one sheet per dataset ----------------
# Columns: A ID | B Channel | C Language | D Message | E Expected | F Verdict | G Match | H Score | I Risk level
#          J Detected language | K Red flags | L Things to verify | M Good signs | N Category | O Rationale
def write_results(wb, name, df, py_summary):
    ws = wb.create_sheet(name)
    cols = ["ID", "Channel", "Language", "Message", "Expected", "Verdict", "Match", "Score", "Risk Level",
            "Detected Language", "Red Flags", "Things to Verify", "Good Signs", "Category / Type", "Rationale"]
    head(ws, 1, cols)
    preds = []
    for i, row in enumerate(df.itertuples(index=False), start=2):
        r = analyze(row.msg)
        p = r.verdict.title()
        preds.append(p)
        vals = [row.id, row.channel, row.language, row.msg, row.label, p, f'=IF(F{i}=E{i},"PASS","FAIL")',
                round(r.score, 4), r.risk_level, r.language.label,
                "; ".join(f.name for f in r.red) or "-", "; ".join(f.name for f in r.verify) or "-",
                "; ".join(f.name for f in r.good) or "-", row.cat, row.rationale]
        for c, v in enumerate(vals, 1):
            cell = ws.cell(row=i, column=c, value=v)
            cell.font, cell.border, cell.alignment = BODY, THIN, WRAP
        ws.cell(row=i, column=8).number_format = "0%"
    last = len(df) + 1
    rng = f"G2:G{last}"
    ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"PASS"'], fill=GREEN))
    ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"FAIL"'], fill=RED))
    for c, w in enumerate([5, 9, 12, 60, 10, 10, 8, 8, 9, 13, 30, 25, 25, 18, 40], 1):
        ws.column_dimensions[get_column_letter(c)].width = w
    ws.freeze_panes = "E2"
    ws.auto_filter.ref = f"A1:O{last}"

    # Independent Python check of the numbers the Excel formulas will compute.
    y = df.label.tolist()
    safe = [p for t, p in zip(y, preds) if t == "Safe"]
    py_summary.append({
        "dataset": name, "n": len(y), "exact": sum(a == b for a, b in zip(y, preds)),
        "accuracy": accuracy_score(y, preds),
        "macro_f1": f1_score(y, preds, labels=LABELS, average="macro", zero_division=0),
        "scams_flagged": sum(t == "Scam" and p != "Safe" for t, p in zip(y, preds)), "scams_total": y.count("Scam"),
        "missed_scams": sum(t == "Scam" and p == "Safe" for t, p in zip(y, preds)),
        "safe_to_scam": sum(p == "Scam" for p in safe), "safe_total": len(safe),
    })
    return last


def metric_rows(sheet, last):
    E = f"'{sheet}'!$E$2:$E${last}"   # expected label
    P = f"'{sheet}'!$F$2:$F${last}"   # ScamShield verdict
    rows = [("Messages", f"=COUNTA({E})", "0"),
            ("Exact matches", f"=SUMPRODUCT(--({E}={P}))", "0"),
            ("Accuracy", f"=SUMPRODUCT(--({E}={P}))/COUNTA({E})", "0.0%")]
    for c in LABELS:
        rows.append((f"{c} – precision", f'=IFERROR(COUNTIFS({E},"{c}",{P},"{c}")/COUNTIF({P},"{c}"),0)', "0.0%"))
        rows.append((f"{c} – recall", f'=IFERROR(COUNTIFS({E},"{c}",{P},"{c}")/COUNTIF({E},"{c}"),0)', "0.0%"))
        rows.append((f"{c} – F1", None, "0.0%"))
    rows += [
        ("Macro F1 (average of 3 classes)", None, "0.0%"),
        ("Scams flagged (Scam or Suspicious)", f'=COUNTIFS({E},"Scam",{P},"Scam")+COUNTIFS({E},"Scam",{P},"Suspicious")', "0"),
        ("Scam catch rate", f'=IFERROR((COUNTIFS({E},"Scam",{P},"Scam")+COUNTIFS({E},"Scam",{P},"Suspicious"))/COUNTIF({E},"Scam"),0)', "0.0%"),
        ("Missed scams (Scam -> Safe)", f'=COUNTIFS({E},"Scam",{P},"Safe")', "0"),
        ("False alarm rate (Safe -> Scam)", f'=IFERROR(COUNTIFS({E},"Safe",{P},"Scam")/COUNTIF({E},"Safe"),0)', "0.0%"),
        ("False positive rate (Safe -> Scam or Suspicious)",
         f'=IFERROR((COUNTIFS({E},"Safe",{P},"Scam")+COUNTIFS({E},"Safe",{P},"Suspicious"))/COUNTIF({E},"Safe"),0)', "0.0%"),
    ]
    return rows


def write_summary(wb, blocks):
    s = wb.create_sheet("Summary", 0)
    s["A1"] = "ScamShield – Benchmark Report"
    s["A1"].font = Font(name=FONT, size=14, bold=True)
    s["A2"] = "Generated by scripts/benchmark.py. All numbers in the dataset blocks are Excel formulas over the result sheets."
    s["A2"].font = NOTE
    row = 4
    for sheet, last, note in blocks:
        s.cell(row=row, column=1, value=sheet).font = Font(name=FONT, size=12, bold=True)
        s.cell(row=row + 1, column=1, value=note).font = NOTE
        head(s, row + 2, ["Metric", "ScamShield"])
        r0 = row + 3
        cell_of = {}
        for k, (label, formula, fmt) in enumerate(metric_rows(sheet, last)):
            rr = r0 + k
            cell_of[label] = rr
            if formula is None and not label.startswith("Macro"):       # per-class F1 from precision & recall
                cls = label.split(" – ")[0]
                p, rc = cell_of[f"{cls} – precision"], cell_of[f"{cls} – recall"]
                formula = f"=IFERROR(2*B{p}*B{rc}/(B{p}+B{rc}),0)"
            elif formula is None:                                       # macro F1
                formula = "=AVERAGE(" + ",".join(f"B{cell_of[c + ' – F1']}" for c in LABELS) + ")"
            s.cell(row=rr, column=1, value=label).font = BODY
            cell = s.cell(row=rr, column=2, value=formula)
            cell.font, cell.number_format = BOLD, fmt
            for col in (1, 2):
                s.cell(row=rr, column=col).border = THIN
        row = r0 + k + 3

    # History: recorded before/after numbers (old v2 code removed from the project).
    s.cell(row=row, column=1, value="Version history – v1 → v2 → v3").font = Font(name=FONT, size=12, bold=True)
    s.cell(row=row + 1, column=1, value="Recorded 25-Nov-2026 by running each version on the same sets. Fixed numbers "
                                         "(not formulas): old version code is no longer in the project. '-' = not tested "
                                         "(that test set did not exist yet).").font = NOTE
    head(s, row + 2, ["Dataset · Metric", "v1 (first)", "v2", "v3 (now)"])
    for k, (ds, metric, *vals) in enumerate(HISTORY, start=row + 3):
        s.cell(row=k, column=1, value=f"{ds} · {metric}").font = BODY
        for col, v in enumerate(vals, start=2):
            c = s.cell(row=k, column=col, value=v)
            c.font, c.alignment = BOLD, Alignment(horizontal="center")
            if isinstance(v, float):
                c.number_format = "0.000"
        for col in range(1, 5):
            s.cell(row=k, column=col).border = THIN
    row = k + 2
    s.cell(row=row, column=1, value="What changed in each version").font = BOLD
    for k, (ver, text) in enumerate(CHANGES, start=row + 1):
        s.cell(row=k, column=1, value=f"{ver}: {text}").font = NOTE
    row = k + 2

    notes = [
        "How to read this",
        "• Sealed100 is the honest score: the rules were never written with these messages in view.",
        "• Dev50 is optimistic: rules and thresholds were adjusted after looking at its mistakes.",
        "• Precision = of the messages ScamShield gave this label, how many were right.",
        "• Recall = of the messages that truly have this label, how many ScamShield found.",
        "• F1 = balance of precision and recall. Macro F1 = average F1 over Scam, Suspicious, Safe.",
        "• False alarm rate = genuine (Safe) messages wrongly called Scam. Missed scams = scams called Safe.",
        "• Expected labels in Sealed100 / Injection30 were written by an AI agent; a human should review disputed rows.",
    ]
    for k, t in enumerate(notes):
        s.cell(row=row + k, column=1, value=t).font = BOLD if k == 0 else NOTE
    for col, w in zip("ABCD", (52, 12, 12, 12)):
        s.column_dimensions[col].width = w


def write_by_language(wb, blocks, langs):
    s = wb.create_sheet("By Language", 1)
    s["A1"] = "Accuracy per language (exact match)"
    s["A1"].font = Font(name=FONT, size=12, bold=True)
    head(s, 3, ["Dataset", "Language", "Messages", "Correct", "Accuracy"])
    r = 4
    for sheet, last, _ in blocks:
        L, G = f"'{sheet}'!$C$2:$C${last}", f"'{sheet}'!$G$2:$G${last}"
        for lang in langs[sheet]:
            vals = [sheet, lang, f'=COUNTIF({L},B{r})', f'=COUNTIFS({L},B{r},{G},"PASS")', f"=IFERROR(D{r}/C{r},0)"]
            for c, v in enumerate(vals, 1):
                cell = s.cell(row=r, column=c, value=v)
                cell.font, cell.border = BODY, THIN
            s.cell(row=r, column=5).number_format = "0.0%"
            r += 1
    for col, w in zip("ABCDE", (13, 16, 10, 10, 11)):
        s.column_dimensions[col].width = w


def write_genai20(wb):
    """Engine vs Gemini-alone vs Hybrid on the 20-message GenAI security test (recorded run, 25-Nov-2026).
    The engine column is recomputed live; Gemini/Hybrid columns come from the saved run (no new API calls)."""
    path = ROOT / "data" / "results" / "genai_security_20_results.csv"
    if not path.exists():
        return
    df = pd.read_csv(path, encoding="utf-8")
    df["gemini_confidence"] = df["gemini_confidence"].astype(object).where(df["gemini_confidence"].notna(), None)
    s = wb.create_sheet("GenAI20 Comparison")
    s["A1"] = "GenAI Security Test (20 messages) – Engine vs Gemini alone vs Hybrid"
    s["A1"].font = Font(name=FONT, size=12, bold=True)
    s["A2"] = ("Answer key written by Claude (no official key was provided). Gemini run recorded 25-Nov-2026; "
               "#17, #19, #20 got no Gemini answer because the free quota ran out. Hybrid = engine + Gemini "
               "second opinion (Gemini may only raise risk by one level).")
    s["A2"].font = NOTE
    cols = ["ID", "Message", "Answer key", "Engine", "Engine match", "Engine score", "Gemini alone",
            "Gemini confidence", "Gemini match", "Gemini time (s)", "Hybrid", "Hybrid match"]
    head(s, 4, cols)
    first = 5
    for k, row in enumerate(df.itertuples(index=False)):
        i = first + k
        live = analyze(row.message)
        vals = [row.id, row.message, row.answer_key, live.verdict.title(), f'=IF(D{i}=C{i},"PASS","FAIL")',
                round(live.score, 4), row.gemini_verdict, row.gemini_confidence,
                f'=IF(G{i}=C{i},"PASS","FAIL")', row.gemini_seconds, row.hybrid_verdict, f'=IF(K{i}=C{i},"PASS","FAIL")']
        for c, v in enumerate(vals, 1):
            cell = s.cell(row=i, column=c, value=v)
            cell.font, cell.border, cell.alignment = BODY, THIN, WRAP
        s.cell(row=i, column=6).number_format = "0%"
        s.cell(row=i, column=8).number_format = "0%"
    last = first + len(df) - 1
    for col in "EIL":
        rng = f"{col}{first}:{col}{last}"
        s.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"PASS"'], fill=GREEN))
        s.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"FAIL"'], fill=RED))

    K = f"$C${first}:$C${last}"
    r0 = last + 3
    head(s, r0, ["Summary", "Engine alone", "Gemini alone", "Hybrid"])
    metrics = [
        ("Correct (exact match)", lambda c: f'=COUNTIF({c}{first}:{c}{last},"PASS")', "0"),
        ("Accuracy", lambda c: f'=COUNTIF({c}{first}:{c}{last},"PASS")/COUNTA({K})', "0.0%"),
        ("Scams called SAFE (worst error)", lambda c: f'=COUNTIFS({K},"Scam",{c}{first}:{c}{last},"Safe")', "0"),
        ("Safe messages called SCAM", lambda c: f'=COUNTIFS({K},"Safe",{c}{first}:{c}{last},"Scam")', "0"),
        ("Scams flagged (Scam or Suspicious)",
         lambda c: f'=COUNTIFS({K},"Scam",{c}{first}:{c}{last},"Scam")+COUNTIFS({K},"Scam",{c}{first}:{c}{last},"Suspicious")', "0"),
        ("No answer (quota limit)", lambda c: f'=COUNTIF({c}{first}:{c}{last},"No answer*")', "0"),
    ]
    verdict_cols = {"Engine alone": "D", "Gemini alone": "G", "Hybrid": "K"}
    match_cols = {"Engine alone": "E", "Gemini alone": "I", "Hybrid": "L"}
    for k, (label, fn, fmt) in enumerate(metrics, start=1):
        rr = r0 + k
        s.cell(row=rr, column=1, value=label).font = BODY
        for c, name in enumerate(verdict_cols, start=2):
            col = match_cols[name] if label.startswith(("Correct", "Accuracy")) else verdict_cols[name]
            cell = s.cell(row=rr, column=c, value=fn(col))
            cell.font, cell.number_format, cell.border = BOLD, fmt, THIN
        s.cell(row=rr, column=1).border = THIN
    rr = r0 + len(metrics) + 1
    s.cell(row=rr, column=1, value="Average time per message").font = BODY
    s.cell(row=rr, column=2, value="< 0.1 s (measured ~70 ms)").font = BOLD
    s.cell(row=rr, column=3, value=f"=AVERAGE(J{first}:J{last})").font = BOLD
    s.cell(row=rr, column=3).number_format = '0.0" s"'
    s.cell(row=rr, column=4, value="result in < 0.1 s, AI note after ~2.6 s").font = BOLD
    for c in range(1, 5):
        s.cell(row=rr, column=c).border = THIN
    for col, w in zip("ABCDEFGHIJKL", (20, 70, 11, 11, 9, 9, 16, 11, 9, 9, 11, 9)):
        s.column_dimensions[col].width = w
    s.freeze_panes = f"C{first}"


def main():
    wb = Workbook()
    wb.remove(wb.active)
    blocks, langs, py_summary = [], {}, []
    for name, path, msg_col, cat_col, note in DATASETS:
        if not path.exists():
            print(f"skip {name}: {path} not found")
            continue
        raw = pd.read_csv(path, encoding="utf-8")
        df = pd.DataFrame({
            "id": raw["id"], "channel": raw["channel"], "language": raw["language"], "msg": raw[msg_col],
            "label": raw["expected_label"].str.strip().str.title(), "cat": raw[cat_col],
            "rationale": raw["rationale"] if "rationale" in raw else raw.get("expected_explanation", ""),
        })
        last = write_results(wb, name, df, py_summary)
        blocks.append((name, last, note))
        langs[name] = sorted(df.language.unique())
    write_summary(wb, blocks)
    write_by_language(wb, blocks, langs)
    write_genai20(wb)
    wb.calculation.fullCalcOnLoad = True
    OUT.parent.mkdir(exist_ok=True)
    wb.save(OUT)
    print(f"Saved {OUT}\n")
    summ = pd.DataFrame(py_summary)
    pd.set_option("display.width", 200)
    print(summ.to_string(index=False, float_format=lambda x: f"{x:.3f}"))
    return summ


if __name__ == "__main__":
    main()
