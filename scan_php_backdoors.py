import argparse
import os
import re
import shutil
import time
import json
from pathlib import Path

PHP_EXTS = {".php", ".phtml", ".php5", ".php7", ".inc"}

MAGIC = {
    b"\xFF\xD8\xFF": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"%PDF-": "PDF",
    b"PK\x03\x04": "ZIP",
}

PATTERNS = [
    (re.compile(r"eval\s*\(\s*base64_decode\s*\(", re.IGNORECASE), "eval(base64_decode)", 8),
    (re.compile(r"gzinflate\s*\(\s*base64_decode\s*\(", re.IGNORECASE), "gzinflate(base64_decode)", 8),
    (re.compile(r"preg_replace\s*\([^)]*?/e[^)]*,", re.IGNORECASE), "preg_replace /e modifier", 7),
    (re.compile(r"(include|require|include_once|require_once)\s*\(\s*['\"]https?://", re.IGNORECASE), "remote include", 7),
    (re.compile(r"assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*\)", re.IGNORECASE), "assert on user input", 7),
    (re.compile(r"(shell_exec|system|passthru|exec|popen|proc_open)\s*\(", re.IGNORECASE), "command execution API", 4),
    (re.compile(r"base64_decode\s*\(\s*str_rot13\s*\(", re.IGNORECASE), "base64+rot13", 7),
    (re.compile(r"str_rot13\s*\(", re.IGNORECASE), "str_rot13", 3),
    (re.compile(r"create_function\s*\(", re.IGNORECASE), "create_function", 4),
    (re.compile(r"error_reporting\s*\(\s*0\s*\)", re.IGNORECASE), "error_reporting(0)", 1),
    (re.compile(r"chr\s*\(\s*\d+\s*\)\s*(\.\s*chr\s*\(\s*\d+\s*\)\s*){4,}", re.IGNORECASE), "chr chain", 6),
    (re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]", re.IGNORECASE), "user input", 2),
    (re.compile(r"[A-Za-z0-9+/]{200,}={0,3}", re.IGNORECASE), "long base64", 3),
    (re.compile(r"\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*base64_decode\s*\([^)]*\)\s*;\s*eval\s*\(\s*\$\w+\s*\)", re.IGNORECASE), "eval(variable from base64)", 9),
]

def read_bytes_head(path: Path, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except Exception:
        return b""

def detect_magic(path: Path) -> str | None:
    head = read_bytes_head(path, 16)
    for sig, name in MAGIC.items():
        if head.startswith(sig):
            return name
    return None

def decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8", "ignore")
    except Exception:
        return ""

def compute_line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1

def extract_snippet(path: Path, lines: list[int]) -> tuple[list[dict], int]:
    focus = lines[0] if lines else 1
    try:
        with open(path, "rb") as f:
            data = f.read()
        text = decode_text(data)
        arr = text.splitlines()
    except Exception:
        arr = []
    if not arr:
        return [], focus
    idx = max(0, min(len(arr) - 1, focus - 1))
    start = max(0, idx - 6)
    end = min(len(arr), idx + 7)
    out: list[dict] = []
    for i in range(start, end):
        out.append({"n": i + 1, "t": arr[i][:1000]})
    return out, focus

def augment_results(results: list[dict]) -> list[dict]:
    out: list[dict] = []
    for r in results:
        sl, focus = extract_snippet(Path(r["path"]), r.get("lines", []))
        nr = dict(r)
        nr["snippet_lines"] = sl
        nr["snippet_focus"] = focus
        out.append(nr)
    return out

def scan_file(path: Path) -> dict | None:
    ext = path.suffix.lower()
    magic = detect_magic(path)
    score = 0
    reasons: list[str] = []
    lines: list[int] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        data = b""
    text = decode_text(data)
    has_php = "<?php" in text
    if ext in PHP_EXTS:
        if magic:
            score += 9
            reasons.append(f"Binary header {magic} in .php")
    else:
        if has_php:
            score += 8
            reasons.append("PHP code in non-PHP file")
    if text and (ext in PHP_EXTS or has_php):
        for rx, desc, weight in PATTERNS:
            matches = list(rx.finditer(text))
            if matches:
                score += weight * len(matches)
                reasons.append(desc)
                for m in matches[:5]:
                    lines.append(compute_line_number(text, m.start()))
        if ("str_rot13" in reasons and "eval(base64_decode)" in reasons) or any("base64+rot13" == r for r in reasons):
            score += 2
        if "user input" in reasons and any(r in reasons for r in ["command execution API", "eval(base64_decode)", "preg_replace /e modifier", "assert on user input"]):
            score += 2
    risk = "None"
    if score >= 10:
        risk = "High"
    elif score >= 6:
        risk = "Medium"
    elif score >= 3:
        risk = "Low"
    if risk == "None":
        return None
    seen = set()
    unique_reasons = []
    for r in reasons:
        if r not in seen:
            unique_reasons.append(r)
            seen.add(r)
    return {
        "path": str(path),
        "score": score,
        "risk": risk,
        "reasons": unique_reasons,
        "lines": sorted(set(lines))[:5],
    }

def scan_dir(root: Path) -> tuple[list[dict], int]:
    files = [p for p in root.rglob("*") if p.is_file()]
    total = len(files)
    results: list[dict] = []
    start = time.time()
    width = shutil.get_terminal_size(fallback=(120, 30)).columns
    def draw(done: int) -> None:
        pct = 0 if total == 0 else int(done * 100 / total)
        bar_w = max(10, width - 40)
        fill = int(bar_w * pct / 100)
        bar = "[" + "#" * fill + "-" * (bar_w - fill) + "]"
        elapsed = time.time() - start
        rate = (done / elapsed) if elapsed > 0 else 0.0
        eta = int(((total - done) / rate)) if rate > 0 else 0
        msg = f"{bar} {pct}% {done}/{total} ETA {eta}s"
        print("\r" + msg.ljust(width), end="", flush=True)
    for i, p in enumerate(files, 1):
        res = scan_file(p)
        if res:
            results.append(res)
        draw(i)
    if total:
        print()
    return results, total

def truncate(s: str, width: int) -> str:
    if len(s) <= width:
        return s
    if width <= 3:
        return s[:width]
    return s[: width - 3] + "..."

def print_table(results: list[dict], total_files: int) -> None:
    headers = ["Risk", "Score", "Path", "Reasons", "Lines"]
    rows = []
    for r in sorted(results, key=lambda x: (-x["score"], x["path"])):
        rows.append([
            r["risk"],
            str(r["score"]),
            r["path"],
            "; ".join(r["reasons"]),
            ",".join(str(n) for n in r["lines"]),
        ])
    width = shutil.get_terminal_size(fallback=(120, 30)).columns
    col_widths = []
    for i in range(len(headers)):
        maxlen = len(headers[i])
        for row in rows:
            if len(row[i]) > maxlen:
                maxlen = len(row[i])
        col_widths.append(maxlen)
    base_const = 4 + 3 * (len(headers) - 1)
    needed = sum(col_widths) + base_const
    if needed > width:
        idx_path = 2
        idx_reasons = 3
        fixed = sum(col_widths) - col_widths[idx_path] - col_widths[idx_reasons]
        available = width - fixed - base_const
        if available < 16:
            available = 16
        path_w = max(8, int(available * 0.5))
        reasons_w = max(8, available - path_w)
        col_widths[idx_path] = path_w
        col_widths[idx_reasons] = reasons_w
        needed = sum(col_widths) + base_const
        if needed > width:
            shrink = needed - width
            half = shrink // 2 + shrink % 2
            col_widths[idx_path] = max(8, col_widths[idx_path] - half)
            col_widths[idx_reasons] = max(8, col_widths[idx_reasons] - (shrink - half))
    def fmt_row(row: list[str]) -> str:
        return "| " + " | ".join(truncate(row[i], col_widths[i]).ljust(col_widths[i]) for i in range(len(row))) + " |"
    sep = "+-" + "-+-".join("-" * col_widths[i] for i in range(len(headers))) + "-+"
    print(sep)
    print(fmt_row(headers))
    print(sep)
    for row in rows:
        print(fmt_row(row))
    print(sep)
    print(f"Scanned {total_files} files; flagged {len(rows)}")

def build_html(results: list[dict], total_files: int, root: str, min_score: int) -> str:
    risk_counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in results:
        rc = r.get("risk")
        if rc in risk_counts:
            risk_counts[rc] += 1
    data = {
        "meta": {
            "root": root,
            "scanned": total_files,
            "flagged": len(results),
            "min_score": min_score,
            "risk_counts": risk_counts,
            "generated_at": int(time.time()),
        },
        "results": results,
    }
    payload = json.dumps(data, ensure_ascii=False)
    html = """
<!doctype html>
<html>
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>PHP Backdoor Scan Report</title>
<style>
body{{font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,'Noto Sans','Liberation Sans',sans-serif; margin:0; background:#0f1216; color:#e6edf3}}
header{{display:flex; align-items:center; justify-content:space-between; padding:16px 20px; background:#151a21; border-bottom:1px solid #232a34}}
.brand{{font-weight:600; letter-spacing:.2px}}
.badge{{display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; margin-left:8px}}
.b-high{{background:#3d0f12; color:#ff6b6b}}
.b-medium{{background:#2f2612; color:#f7b731}}
.b-low{{background:#16262f; color:#4dd0e1}}
.wrap{{padding:16px 20px}}
.controls{{display:flex; gap:12px; flex-wrap:wrap; margin-bottom:12px}}
.controls input,.controls select{{background:#0f1216; color:#e6edf3; border:1px solid #2b3440; border-radius:8px; padding:8px 10px}}
.summary{{display:flex; gap:16px; flex-wrap:wrap; margin-bottom:12px; font-size:14px}}
.card{{background:#151a21; border:1px solid #232a34; border-radius:10px; padding:10px 12px}}
table{{width:100%%; border-collapse:collapse; background:#0f1216; border:1px solid #232a34; border-radius:10px; overflow:hidden}}
thead th{{position:sticky; top:0; background:#151a21; color:#9fb7d0; font-weight:600; text-align:left; padding:10px; border-bottom:1px solid #232a34; cursor:pointer}}
tbody td{{padding:10px; border-bottom:1px solid #1b2129; vertical-align:top;}}
tbody tr:hover{{background:#12171e}}
.risk-high{{color:#ff6b6b}}
.risk-medium{{color:#f7b731}}
.risk-low{{color:#4dd0e1}}
.path{{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; font-size:13px}}
.reasons{{font-size:13px; color:#c7d1db}}
.lines{{font-size:12px; color:#9fb7d0}}
.footer{{margin-top:12px; font-size:12px; color:#9fb7d0}}
.empty{{padding:24px; text-align:center; color:#9fb7d0}}
.sort-ind{{margin-left:6px; font-size:12px; color:#9fb7d0}}
.modal{{position:fixed; inset:0; display:flex; align-items:center; justify-content:center}}
.hidden{{display:none}}
.overlay{{position:absolute; inset:0; background:rgba(0,0,0,.55)}}
.box{{position:relative; background:#151a21; border:1px solid #232a34; border-radius:10px; width:min(900px,90vw); max-height:80vh; overflow:auto; padding:16px}}
.head{{display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:8px}}
.actions{{display:flex; gap:8px}}
.btn{{background:#0f1216; color:#e6edf3; border:1px solid #2b3440; border-radius:8px; padding:6px 10px}}
.code-view{{margin-top:8px; background:#0f1216; border:1px solid #232a34; border-radius:8px; padding:8px}}
.code-row{{display:flex; gap:10px; padding:2px 0}}
.ln{{width:50px; text-align:right; color:#9fb7d0}}
.code{{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; white-space:pre-wrap; word-break:break-word}}
.hl{{background:#1b222b}}
</style>
</head>
<body>
<header>
  <div class=\"brand\">PHP Backdoor Scan Report</div>
  <div>
    <span class=\"badge b-high\">High: %s</span>
    <span class=\"badge b-medium\">Medium: %s</span>
    <span class=\"badge b-low\">Low: %s</span>
  </div>
</header>
<div class=\"wrap\">
  <div class=\"summary\">
    <div class=\"card\">Root: <span class=\"path\">%s</span></div>
    <div class=\"card\">Scanned: %s</div>
    <div class=\"card\">Flagged: %s</div>
    <div class=\"card\">Min score: %s</div>
    <div class=\"card\">Generated: <span id=\"gen\"></span></div>
  </div>
  <div class=\"controls\">
    <input id=\"search\" type=\"search\" placeholder=\"Filter by path or reasons\" />
    <select id=\"risk\">
      <option>All</option>
      <option>High</option>
      <option>Medium</option>
      <option>Low</option>
    </select>
  </div>
  <table>
    <thead>
      <tr>
        <th data-key=\"risk\">Risk<span class=\"sort-ind\" id=\"si-risk\"></span></th>
        <th data-key=\"score\">Score<span class=\"sort-ind\" id=\"si-score\"></span></th>
        <th data-key=\"path\">Path<span class=\"sort-ind\" id=\"si-path\"></span></th>
        <th data-key=\"reasons\">Reasons<span class=\"sort-ind\" id=\"si-reasons\"></span></th>
        <th data-key=\"lines\">Lines<span class=\"sort-ind\" id=\"si-lines\"></span></th>
      </tr>
    </thead>
    <tbody id=\"rows\"></tbody>
  </table>
  <div class=\"footer\">Click headers to sort. Use filters to narrow results.</div>
</div>
<div id=\"modal\" class=\"modal hidden\">
  <div id=\"overlay\" class=\"overlay\"></div>
  <div class=\"box\">
    <div class=\"head\">
      <div class=\"path\" id=\"modal-path\"></div>
      <div class=\"actions\">
        <button id=\"copy\" class=\"btn\">Copy</button>
        <button id=\"close\" class=\"btn\">Close</button>
      </div>
    </div>
    <div class=\"meta\">Reasons: <span id=\"modal-reasons\"></span></div>
    <div id=\"code\" class=\"code-view\"></div>
  </div>
  </div>
<script>
const report = %s;
let sortKey = 'score';
let sortDir = 'desc';
let filterRisk = 'All';
let query = '';
const riskOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escapeAttr(s){ return String(s).replace(/"/g,'&quot;'); }
function fmtDate(ts){ const d=new Date(ts*1000); return d.toLocaleString(); }
function setSortInd(){ const keys=['risk','score','path','reasons','lines']; keys.forEach(k=>{ const el=document.getElementById('si-'+k); if(!el)return; el.textContent = sortKey===k ? (sortDir==='asc'?'▲':'▼') : ''; }); }
function render(){ const rowsEl=document.getElementById('rows'); const q=query.trim().toLowerCase(); let items=report.results.slice(); if(filterRisk!=='All'){ items=items.filter(x=>x.risk===filterRisk); } if(q){ items=items.filter(x=> (x.path||'').toLowerCase().includes(q) || (x.reasons||[]).join('; ').toLowerCase().includes(q)); } items.sort((a,b)=>{ let va=a[sortKey], vb=b[sortKey]; if(sortKey==='risk'){ va=riskOrder[va]||0; vb=riskOrder[vb]||0; } if(sortKey==='reasons'){ va=(a.reasons||[]).join('; '); vb=(b.reasons||[]).join('; '); } if(sortKey==='lines'){ va=(a.lines||[]).join(','); vb=(b.lines||[]).join(','); } if(typeof va==='string'&&typeof vb==='string'){ const r=va.localeCompare(vb); return sortDir==='asc'?r:-r; } const r=(va>vb)-(va<vb); return sortDir==='asc'?r:-r; }); let html=''; if(items.length===0){ html = '<tr><td colspan="5" class="empty">No matching results</td></tr>'; } else { for(const it of items){ const rc = it.risk==='High'?'risk-high':(it.risk==='Medium'?'risk-medium':'risk-low'); const reasons = (it.reasons||[]).join('; '); const lines = (it.lines||[]).join(','); html += '<tr data-path="'+escapeAttr(it.path)+'">' + '<td class="'+rc+'">'+it.risk+'</td>' + '<td>'+it.score+'</td>' + '<td class="path">'+escapeHtml(it.path)+'</td>' + '<td class="reasons">'+escapeHtml(reasons)+'</td>' + '<td class="lines">'+escapeHtml(lines)+'</td>' + '</tr>'; } }
 rowsEl.innerHTML=html; setSortInd(); }
document.getElementById('gen').textContent = fmtDate(report.meta.generated_at);
document.getElementById('risk').value='All';
document.getElementById('risk').addEventListener('change', e=>{ filterRisk=e.target.value; render(); });
document.getElementById('search').addEventListener('input', e=>{ query=e.target.value; render(); });
document.querySelectorAll('thead th').forEach(th=>{ th.addEventListener('click', ()=>{ const k=th.getAttribute('data-key'); if(sortKey===k){ sortDir = sortDir==='asc'?'desc':'asc'; } else { sortKey=k; sortDir='asc'; } render(); }); });
function openModal(it){ const lines = it.snippet_lines || []; let c=''; for(const l of lines){ const h = l.n===it.snippet_focus ? ' hl' : ''; c += '<div class="code-row'+h+'"><span class="ln">'+l.n+'</span><span class="code">'+escapeHtml(l.t)+'</span></div>'; } document.getElementById('code').innerHTML=c; document.getElementById('modal-path').textContent = it.path; document.getElementById('modal-reasons').textContent = (it.reasons||[]).join('; '); document.getElementById('modal').classList.remove('hidden'); }
function closeModal(){ document.getElementById('modal').classList.add('hidden'); }
document.getElementById('rows').addEventListener('click', e=>{ const tr=e.target.closest('tr'); if(!tr) return; const p=tr.getAttribute('data-path'); const it = report.results.find(x=>x.path===p); if(!it) return; openModal(it); });
document.getElementById('close').addEventListener('click', closeModal);
document.getElementById('overlay').addEventListener('click', closeModal);
document.getElementById('copy').addEventListener('click', ()=>{ const txt = Array.from(document.querySelectorAll('.code-row .code')).map(el=>el.textContent).join('\\\\n'); navigator.clipboard && navigator.clipboard.writeText(txt); });
render();
</script>
</body>
</html>
"""
    html = html % (
        risk_counts["High"],
        risk_counts["Medium"],
        risk_counts["Low"],
        root,
        total_files,
        len(results),
        min_score,
        payload,
    )
    html = html.replace("{{", "{").replace("}}", "}")
    return html

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Root directory to scan")
    parser.add_argument("--min-score", type=int, default=3)
    parser.add_argument("--html", type=str, default="report.html")
    parser.add_argument("--write-json", action="store_true")
    parser.add_argument("--open", action="store_true")
    args = parser.parse_args()
    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print("Invalid path")
        return
    results, total = scan_dir(root)
    results = [r for r in results if r["score"] >= args.min_score]
    aug_results = augment_results(results)
    if results:
        print_table(results, total)
    else:
        print(f"Scanned {total} files; no suspicious files found with score >= {args.min_score}")
    html = build_html(aug_results, total, str(root), args.min_score)
    out_html = Path(args.html).resolve()
    try:
        out_html.write_text(html, encoding="utf-8")
        print(f"Wrote HTML report to {out_html}")
    except Exception as e:
        print(f"Failed to write HTML report: {e}")
    if args.write_json:
        json_path = out_html.with_suffix(".json")
        try:
            payload = {
                "meta": {
                    "root": str(root),
                    "scanned": total,
                    "flagged": len(results),
                    "min_score": args.min_score,
                    "generated_at": int(time.time()),
                },
                "results": aug_results,
            }
            json_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            print(f"Wrote JSON report to {json_path}")
        except Exception as e:
            print(f"Failed to write JSON report: {e}")
    if args.open:
        try:
            os.startfile(str(out_html))
        except Exception:
            pass

if __name__ == "__main__":
    main()
