//! Self-contained interactive HTML dashboard report.

use crate::findings::Finding;
use crate::scanner::ScanStats;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn render(findings: &[Finding], stats: &ScanStats) -> String {
    let c = super::count_by_severity(findings);
    let total = findings.len().max(1);
    let generated = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut rule_rows = String::new();
    for (rule, count) in super::count_by_rule(findings) {
        let pct = count * 100 / total;
        rule_rows.push_str(&format!(
            r#"<div class="rulebar"><span class="rulename">{}</span><div class="track"><div class="fill" style="width:{}%"></div></div><span class="rulecount">{}</span></div>"#,
            esc(&rule),
            pct.max(2),
            count
        ));
    }

    let mut rows = String::new();
    for (i, f) in findings.iter().enumerate() {
        let sev = f.severity.as_str();
        rows.push_str(&format!(
            r#"<tr class="finding" data-sev="{sev}" data-text="{search}" onclick="toggle({i})">
<td><span class="badge {sev}">{sev}</span></td>
<td class="mono">{id}</td>
<td>{name}</td>
<td class="mono file">{file}:{line}</td>
<td class="mono conf">{conf}</td>
</tr>
<tr class="detail" id="d{i}" data-sev="{sev}"><td colspan="5">
<div class="detailbox">
<p>{msg}</p>
<pre>{snippet}</pre>
<p class="meta"><b>{cwe}</b> · {owasp} · input source <b>{source}</b> · fingerprint <span class="mono">{fp}</span></p>
<p class="fix"><b>Fix:</b> {fix}</p>
</div></td></tr>"#,
            sev = sev,
            source = f.source.as_str(),
            search = esc(&format!("{} {} {} {}", f.rule_id, f.rule_name, f.file, f.message).to_lowercase()),
            i = i,
            id = esc(&f.rule_id),
            name = esc(&f.rule_name),
            file = esc(&f.file),
            line = f.line,
            conf = f.confidence.as_str(),
            msg = esc(&f.message),
            snippet = esc(&f.snippet),
            cwe = esc(&f.cwe),
            owasp = esc(&f.owasp),
            fp = esc(&f.fingerprint),
            fix = esc(&f.remediation),
        ));
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>javscan report</title>
<style>
:root {{ --bg:#0f1117; --panel:#171a23; --border:#262b38; --text:#e2e6ef; --dim:#8b93a7;
  --critical:#ff4d5e; --high:#ff8a3d; --medium:#ffd23d; --low:#3dc9ff; --info:#9aa4b8; --accent:#7c6cff; }}
* {{ box-sizing:border-box; margin:0; }}
body {{ background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",system-ui,sans-serif; padding:32px; }}
h1 {{ font-size:22px; }} h1 span {{ color:var(--accent); }}
.sub {{ color:var(--dim); margin:4px 0 24px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:24px; }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }}
.card .num {{ font-size:28px; font-weight:700; }}
.card .lbl {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
.card.critical .num {{ color:var(--critical); }} .card.high .num {{ color:var(--high); }}
.card.medium .num {{ color:var(--medium); }} .card.low .num {{ color:var(--low); }}
.panel {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:20px; margin-bottom:24px; }}
.panel h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.08em; color:var(--dim); margin-bottom:14px; }}
.rulebar {{ display:flex; align-items:center; gap:10px; margin:6px 0; }}
.rulename {{ width:280px; font-size:13px; color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.track {{ flex:1; height:8px; background:var(--border); border-radius:4px; overflow:hidden; }}
.fill {{ height:100%; background:linear-gradient(90deg,var(--accent),#b18cff); border-radius:4px; }}
.rulecount {{ width:40px; text-align:right; color:var(--dim); font-size:13px; }}
.controls {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px; }}
.controls button {{ background:var(--panel); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:6px 14px; cursor:pointer; font-size:13px; }}
.controls button.active {{ border-color:var(--accent); background:rgba(124,108,255,.15); }}
.controls input {{ flex:1; min-width:220px; background:var(--panel); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:6px 12px; }}
table {{ width:100%; border-collapse:collapse; }}
th {{ text-align:left; color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.06em; padding:8px 10px; border-bottom:1px solid var(--border); }}
td {{ padding:9px 10px; border-bottom:1px solid var(--border); vertical-align:top; }}
tr.finding {{ cursor:pointer; }} tr.finding:hover {{ background:rgba(124,108,255,.06); }}
.badge {{ font-size:11px; font-weight:700; padding:2px 8px; border-radius:20px; }}
.badge.CRITICAL {{ background:rgba(255,77,94,.15); color:var(--critical); }}
.badge.HIGH {{ background:rgba(255,138,61,.15); color:var(--high); }}
.badge.MEDIUM {{ background:rgba(255,210,61,.15); color:var(--medium); }}
.badge.LOW {{ background:rgba(61,201,255,.15); color:var(--low); }}
.badge.INFO {{ background:rgba(154,164,184,.15); color:var(--info); }}
.mono {{ font-family:Consolas,monospace; font-size:12.5px; }}
.file {{ color:var(--dim); }} .conf {{ color:var(--dim); }}
tr.detail {{ display:none; }} tr.detail.open {{ display:table-row; }}
.detailbox {{ background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:14px; }}
.detailbox pre {{ background:#0a0c10; border-radius:6px; padding:10px; margin:10px 0; overflow-x:auto; font-size:12.5px; color:#c8d1e0; }}
.detailbox .meta {{ color:var(--dim); font-size:12.5px; }}
.detailbox .fix {{ margin-top:8px; color:#a8e6b0; font-size:13px; }}
.empty {{ text-align:center; padding:40px; color:var(--dim); }}
</style></head><body>
<h1>jav<span>scan</span> security report</h1>
<p class="sub">Generated {generated} · {files} files · {lines} lines · {ms} ms · javscan v{version}</p>
<div class="cards">
<div class="card"><div class="num">{count_total}</div><div class="lbl">Total</div></div>
<div class="card critical"><div class="num">{crit}</div><div class="lbl">Critical</div></div>
<div class="card high"><div class="num">{high}</div><div class="lbl">High</div></div>
<div class="card medium"><div class="num">{med}</div><div class="lbl">Medium</div></div>
<div class="card low"><div class="num">{low}</div><div class="lbl">Low / Info</div></div>
</div>
<div class="panel"><h2>Findings by rule</h2>{rule_rows}</div>
<div class="panel">
<h2>Findings</h2>
<div class="controls">
<button class="active" data-f="ALL" onclick="filt(this)">All</button>
<button data-f="CRITICAL" onclick="filt(this)">Critical</button>
<button data-f="HIGH" onclick="filt(this)">High</button>
<button data-f="MEDIUM" onclick="filt(this)">Medium</button>
<button data-f="LOW" onclick="filt(this)">Low</button>
<input id="q" placeholder="Search rule, file, message..." oninput="search()">
</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Name</th><th>Location</th><th>Confidence</th></tr></thead>
<tbody id="tb">{rows}</tbody></table>
<div class="empty" id="empty" style="display:none">No findings match the current filter.</div>
</div>
<script>
let sevFilter = "ALL";
function toggle(i) {{ document.getElementById("d"+i).classList.toggle("open"); }}
function filt(btn) {{
  sevFilter = btn.dataset.f;
  document.querySelectorAll(".controls button").forEach(b => b.classList.toggle("active", b===btn));
  apply();
}}
function search() {{ apply(); }}
function apply() {{
  const q = document.getElementById("q").value.toLowerCase();
  let visible = 0;
  document.querySelectorAll("tr.finding").forEach(tr => {{
    const okSev = sevFilter === "ALL" || tr.dataset.sev === sevFilter || (sevFilter==="LOW" && tr.dataset.sev==="INFO");
    const okQ = !q || tr.dataset.text.includes(q);
    const show = okSev && okQ;
    tr.style.display = show ? "" : "none";
    if (!show) tr.nextElementSibling.classList.remove("open");
    if (show) visible++;
  }});
  document.getElementById("empty").style.display = visible ? "none" : "block";
}}
</script>
</body></html>"##,
        generated = generated,
        files = stats.files_scanned,
        lines = stats.lines_scanned,
        ms = stats.duration_ms,
        version = env!("CARGO_PKG_VERSION"),
        count_total = findings.len(),
        crit = c.critical,
        high = c.high,
        med = c.medium,
        low = c.low + c.info,
        rule_rows = rule_rows,
        rows = rows,
    )
}
