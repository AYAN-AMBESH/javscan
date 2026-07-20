//! SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers.

use crate::findings::Finding;
use serde_json::{json, Value};

pub fn render(findings: &[Finding]) -> String {
    let rules: Vec<Value> = crate::rules::all_rules()
        .iter()
        .map(|r| {
            json!({
                "id": r.meta.id,
                "name": r.meta.name,
                "shortDescription": { "text": r.meta.description },
                "fullDescription": { "text": r.meta.description },
                "help": { "text": r.meta.remediation },
                "defaultConfiguration": { "level": r.meta.severity.sarif_level() },
                "properties": {
                    "tags": ["security", r.meta.cwe, r.meta.owasp],
                    "cwe": r.meta.cwe,
                    "owasp": r.meta.owasp,
                    "security-severity": match r.meta.severity {
                        crate::findings::Severity::Critical => "9.5",
                        crate::findings::Severity::High => "8.0",
                        crate::findings::Severity::Medium => "5.5",
                        crate::findings::Severity::Low => "3.0",
                        crate::findings::Severity::Info => "1.0",
                    },
                }
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level(),
                "message": { "text": format!("{} Remediation: {}", f.message, f.remediation) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file, "uriBaseId": "%SRCROOT%" },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column,
                            "endLine": f.end_line,
                            "snippet": { "text": f.snippet }
                        }
                    }
                }],
                "partialFingerprints": { "javscan/v1": f.fingerprint },
                "properties": {
                    "confidence": f.confidence.as_str(),
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                }
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "javscan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/AYAN-AMBESH/javscan",
                    "rules": rules,
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap()
}
