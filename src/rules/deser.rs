//! Deserialization and XML parsing rules: insecure Java/XML/YAML
//! deserialization and XXE.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_name, creation_type, receiver_text};

pub fn register(rules: &mut Vec<RuleDef>) {
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS501",
            name: "insecure-deserialization",
            severity: Severity::Critical,
            cwe: "CWE-502",
            owasp: "A08:2021-Software and Data Integrity Failures",
            description: "Deserialization of untrusted data (Java native, XMLDecoder, XStream, Jackson default typing, SnakeYAML)",
            remediation: "Never deserialize untrusted bytes. Use an ObjectInputFilter allow-list, SnakeYAML SafeConstructor, XStream allow-list security framework, and avoid Jackson default typing.",
        },
        check: check_deserialization,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS502",
            name: "xxe",
            severity: Severity::High,
            cwe: "CWE-611",
            owasp: "A05:2021-Security Misconfiguration",
            description: "XML parser created without XXE protections",
            remediation: "Set factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) and disable external entities/DTDs before parsing untrusted XML.",
        },
        check: check_xxe,
    });
}

fn check_deserialization(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    let src = &ctx.file.source;
    let has_ois = src.contains("ObjectInputStream");
    let has_xstream = src.contains("XStream");
    let has_yaml = src.contains("Yaml");
    let yaml_safe = src.contains("SafeConstructor");
    let has_filter = src.contains("ObjectInputFilter") || src.contains("setObjectInputFilter");

    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        match name {
            "readObject" | "readUnshared" if has_ois => {
                let recv = receiver_text(ctx.file, *call);
                let from_network = src.contains("getInputStream")
                    || src.contains("Socket")
                    || ctx.taint.expr_tainted(*call);
                let (sev, conf) = if has_filter {
                    (Some(Severity::Medium), Confidence::Low)
                } else if from_network {
                    (None, Confidence::High)
                } else {
                    (Some(Severity::High), Confidence::Medium)
                };
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!(
                        "`{recv}.{name}()` deserializes Java objects{}; crafted streams can execute arbitrary code (gadget chains).",
                        if from_network { " from an untrusted stream" } else { "" }
                    ),
                    conf,
                    sev,
                ));
            }
            "fromXML" if has_xstream => {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "`XStream.fromXML()` without an allow-list deserializes arbitrary classes (RCE).".into(),
                    Confidence::High,
                    None,
                ));
            }
            "enableDefaultTyping" | "activateDefaultTyping" => {
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!("Jackson `{name}()` enables polymorphic deserialization of arbitrary classes (RCE via gadget types)."),
                    Confidence::High,
                    None,
                ));
            }
            "load" | "loadAs" if has_yaml && !yaml_safe => {
                let recv = receiver_text(ctx.file, *call).to_lowercase();
                if recv.contains("yaml") {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        "SnakeYAML `load()` without SafeConstructor can instantiate arbitrary classes (RCE).".into(),
                        Confidence::High,
                        None,
                    ));
                }
            }
            _ => {}
        }
    }
    for creation in &ctx.index.object_creations {
        if creation_type(ctx.file, *creation) == "XMLDecoder" {
            out.push(ctx.finding(
                meta,
                *creation,
                "`XMLDecoder` executes method calls described in the XML; never use it on untrusted input.".into(),
                Confidence::High,
                None,
            ));
        }
    }
    out
}

const XXE_PROTECTIONS: &[&str] = &[
    "disallow-doctype-decl",
    "ACCESS_EXTERNAL_DTD",
    "ACCESS_EXTERNAL_SCHEMA",
    "ACCESS_EXTERNAL_STYLESHEET",
    "FEATURE_SECURE_PROCESSING",
    "SUPPORT_DTD",
    "IS_SUPPORTING_EXTERNAL_ENTITIES",
    "setExpandEntityReferences(false)",
    "external-general-entities",
    "external-parameter-entities",
];

const XML_FACTORIES: &[&str] = &[
    "DocumentBuilderFactory",
    "SAXParserFactory",
    "XMLInputFactory",
    "TransformerFactory",
    "SchemaFactory",
    "XMLReaderFactory",
    "SAXTransformerFactory",
];

fn check_xxe(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    let protected = XXE_PROTECTIONS
        .iter()
        .any(|p| ctx.file.source.contains(p));
    if protected {
        return out;
    }
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if name != "newInstance" && name != "newDefaultInstance" && name != "createXMLReader" {
            continue;
        }
        let recv = receiver_text(ctx.file, *call);
        let recv_last = recv.rsplit('.').next().unwrap_or(recv);
        if XML_FACTORIES.contains(&recv_last) {
            out.push(ctx.finding(
                meta,
                *call,
                format!("`{recv_last}.{name}()` created without disabling DTDs/external entities — XXE possible when parsing untrusted XML."),
                Confidence::Medium,
                None,
            ));
        }
    }
    for creation in &ctx.index.object_creations {
        let ty = creation_type(ctx.file, *creation);
        if ty == "SAXReader" || ty == "SAXBuilder" {
            out.push(ctx.finding(
                meta,
                *creation,
                format!("`new {ty}()` without XXE hardening — disable DTDs/external entities before parsing untrusted XML."),
                Confidence::Medium,
                None,
            ));
        }
    }
    out
}
