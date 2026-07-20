use crate::findings::Finding;
use crate::scanner::ScanStats;
use serde_json::json;

pub fn render(findings: &[Finding], stats: &ScanStats) -> String {
    let c = super::count_by_severity(findings);
    let doc = json!({
        "tool": {
            "name": "javscan",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "generated": chrono::Local::now().to_rfc3339(),
        "stats": {
            "files_scanned": stats.files_scanned,
            "lines_scanned": stats.lines_scanned,
            "parse_failures": stats.parse_failures,
            "suppressed_inline": stats.suppressed,
            "duration_ms": stats.duration_ms,
        },
        "summary": {
            "total": findings.len(),
            "critical": c.critical,
            "high": c.high,
            "medium": c.medium,
            "low": c.low,
            "info": c.info,
        },
        "findings": findings,
    });
    serde_json::to_string_pretty(&doc).unwrap()
}
