//! Deserialization and XML parsing rules: insecure Java/XML/YAML
//! deserialization and XXE.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity, TrustSource};
use crate::parser::{call_args, call_name, creation_type, receiver_text};
use crate::trust;
use crate::types::simple_name;
use tree_sitter::Node;

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

/// Wrappers around SnakeYAML that construct their `Yaml` with a
/// `SafeConstructor`. A `.load()` on one of these can never instantiate an
/// arbitrary class, because global type tags are rejected at compose time.
const SAFE_YAML_WRAPPERS: &[&str] = &[
    "org.springframework.beans.factory.config.YamlProcessor",
    "YamlProcessor",
    "org.springframework.boot.env.YamlPropertySourceLoader",
    "YamlPropertySourceLoader",
    "org.springframework.beans.factory.config.YamlMapFactoryBean",
    "YamlMapFactoryBean",
    "org.springframework.beans.factory.config.YamlPropertiesFactoryBean",
    "YamlPropertiesFactoryBean",
];

/// The one type whose `.load()` is actually SnakeYAML's dangerous entry point.
const SNAKEYAML_YAML: &[&str] = &["org.yaml.snakeyaml.Yaml", "Yaml"];

/// SnakeYAML constructors that restrict which types the parser may build.
const SAFE_YAML_CONSTRUCTORS: &[&str] = &["SafeConstructor", "CustomClassLoaderConstructor"];

/// Wrappers of `enableDefaultTyping` that install an allow-list
/// `PolymorphicTypeValidator` rather than accepting any type.
const SAFE_DEFAULT_TYPING_OWNERS: &[&str] = &[
    "org.springframework.security.jackson2.SecurityJackson2Modules",
    "SecurityJackson2Modules",
];

/// Jackson mapper types whose own `enableDefaultTyping` is the RCE footgun.
const JACKSON_MAPPERS: &[&str] = &[
    "com.fasterxml.jackson.databind.ObjectMapper",
    "ObjectMapper",
    "XmlMapper",
    "YAMLMapper",
    "CBORMapper",
    "SmileMapper",
    "JsonMapper",
];

/// The permissive validator — passing it is equivalent to no validator at all.
const UNSAFE_TYPE_VALIDATORS: &[&str] = &["LaissezFaireSubTypeValidator"];

fn check_deserialization(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    let src = &ctx.file.source;
    let has_ois = src.contains("ObjectInputStream");
    let has_xstream = src.contains("XStream");
    let has_filter = src.contains("ObjectInputFilter") || src.contains("setObjectInputFilter");

    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        match name {
            "readObject" | "readUnshared" if has_ois => {
                if let Some(f) = check_native_read(ctx, meta, *call, name, has_filter) {
                    out.push(f);
                }
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
                if let Some(f) = check_default_typing(ctx, meta, *call, name) {
                    out.push(f);
                }
            }
            "load" | "loadAs" | "loadAll" => {
                if let Some(f) = check_yaml_load(ctx, meta, *call, name) {
                    out.push(f);
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

/// Java native deserialization. The API is always dangerous, so this always
/// reports — but the rank depends on who controls the bytes.
fn check_native_read(
    ctx: &RuleCtx,
    meta: &RuleMeta,
    call: Node,
    name: &str,
    has_filter: bool,
) -> Option<crate::findings::Finding> {
    let recv = receiver_text(ctx.file, call);
    let recv_node = call.child_by_field_name("object");

    // A stream this class serialized itself (an on-disk cache or index) can
    // only be poisoned by someone who already has write access to the file.
    if trust::is_self_serialized_roundtrip(ctx) {
        return Some(ctx.finding_from(
            meta,
            call,
            format!(
                "`{recv}.{name}()` reads back objects this class serialized itself; the stream is only attacker-controlled if the underlying file is writable."
            ),
            Confidence::Low,
            Some(Severity::Low),
            TrustSource::LocalFs,
        ));
    }

    let source = recv_node
        .map(|n| trust::classify(ctx, n))
        .unwrap_or(TrustSource::Unknown);
    let from_network = source == TrustSource::Network
        || ctx.file.source.contains("getInputStream")
        || ctx.file.source.contains("Socket");

    let (severity, confidence) = if has_filter {
        (Some(Severity::Medium), Confidence::Low)
    } else if from_network {
        (None, Confidence::High)
    } else {
        (Some(Severity::High), Confidence::Medium)
    };
    // A network source is already the maximum; don't let the tag also penalise.
    let source = if from_network { TrustSource::Network } else { source };

    Some(ctx.finding_from(
        meta,
        call,
        format!(
            "`{recv}.{name}()` deserializes Java objects{}; crafted streams can execute arbitrary code (gadget chains).",
            if from_network { " from an untrusted stream" } else { "" }
        ),
        confidence,
        severity,
        source,
    ))
}

/// Jackson polymorphic typing. Matching the bare method name is what produced
/// the `SecurityJackson2Modules.enableDefaultTyping` false positive: that is a
/// different symbol from `ObjectMapper#enableDefaultTyping`, and it installs
/// an allow-list validator.
fn check_default_typing(
    ctx: &RuleCtx,
    meta: &RuleMeta,
    call: Node,
    name: &str,
) -> Option<crate::findings::Finding> {
    let recv_text = receiver_text(ctx.file, call);
    let recv_node = call.child_by_field_name("object");

    // Resolve the owner: the declared type of the receiver when it is a value,
    // or the receiver text itself when it is a static call on a class name.
    let owner = recv_node
        .and_then(|n| ctx.types.type_of(ctx.file, n))
        .unwrap_or_else(|| recv_text.to_string());
    let owner_fqn = ctx.types.fqn(&owner);

    if SAFE_DEFAULT_TYPING_OWNERS
        .iter()
        .any(|s| *s == owner_fqn || *s == simple_name(&owner))
    {
        return None;
    }

    // `activateDefaultTyping(validator, ...)` with a real allow-list validator
    // is the recommended API, not the footgun.
    let args = call_args(call);
    if name == "activateDefaultTyping" && !args.is_empty() {
        let validator = ctx.file.text(args[0]);
        let permissive = UNSAFE_TYPE_VALIDATORS.iter().any(|v| validator.contains(v));
        if !permissive {
            return Some(ctx.finding(
                meta,
                call,
                format!(
                    "Jackson `{name}()` is called with a `PolymorphicTypeValidator` (`{}`); confirm its allow-list is narrow enough that no gadget type is reachable.",
                    validator.chars().take(60).collect::<String>()
                ),
                Confidence::Low,
                Some(Severity::Info),
            ));
        }
    }

    // Only fire when the owner really is a Jackson mapper, or could not be
    // resolved at all (in which case report at reduced confidence).
    let is_mapper = ctx.types.is_a(&owner, JACKSON_MAPPERS);
    let resolved = ctx.types.type_of(ctx.file, recv_node?).is_some();
    if !is_mapper && resolved {
        return None;
    }
    let confidence = if is_mapper { Confidence::High } else { Confidence::Medium };

    Some(ctx.finding(
        meta,
        call,
        format!(
            "Jackson `{recv_text}.{name}()` enables polymorphic deserialization of arbitrary classes (RCE via gadget types)."
        ),
        confidence,
        None,
    ))
}

/// SnakeYAML `.load()`.
///
/// The old rule matched any `.load()` whose receiver *name* contained "yaml",
/// which flags every hardened wrapper in the ecosystem. This resolves the
/// receiver's declared type instead, and checks how the `Yaml` was built.
fn check_yaml_load(
    ctx: &RuleCtx,
    meta: &RuleMeta,
    call: Node,
    name: &str,
) -> Option<crate::findings::Finding> {
    let recv_node = call.child_by_field_name("object")?;
    let recv_type = ctx.types.type_of(ctx.file, recv_node);

    match &recv_type {
        Some(ty) => {
            // A wrapper that builds its Yaml with a SafeConstructor.
            if ctx.types.is_a(ty, SAFE_YAML_WRAPPERS) {
                return None;
            }
            // Anything that is not SnakeYAML's `Yaml` is not this rule's sink.
            if !ctx.types.is_a(ty, SNAKEYAML_YAML) {
                return None;
            }
        }
        // Receiver type unresolvable (e.g. a call chain). Only proceed when the
        // file actually imports SnakeYAML — otherwise there is no evidence at all.
        None => {
            if !ctx.types.imports_fqn("org.yaml.snakeyaml.Yaml") {
                return None;
            }
            // A bare identifier that is not a declared variable is a *class*
            // name: this is a static call such as `ServiceLoader.load(...)`.
            // Importing SnakeYAML elsewhere in the file is not evidence that
            // this particular call is a Yaml load.
            if recv_node.kind() == "identifier" {
                let recv = ctx.file.text(recv_node);
                let starts_upper = recv.chars().next().is_some_and(|c| c.is_uppercase());
                if starts_upper && crate::types::simple_name(recv) != "Yaml" {
                    return None;
                }
            }
        }
    }

    // How was this particular `Yaml` constructed? Prefer the construction site
    // over the old file-wide `source.contains("SafeConstructor")` check.
    let construction = ctx.types.construction_of(ctx.file, recv_node);
    let safe_ctor = match construction {
        Some(node) => call_args(node)
            .iter()
            .any(|a| SAFE_YAML_CONSTRUCTORS.iter().any(|c| ctx.file.text(*a).contains(c))),
        // No visible construction site — fall back to the file-wide signal.
        None => SAFE_YAML_CONSTRUCTORS
            .iter()
            .any(|c| ctx.file.source.contains(c)),
    };
    if safe_ctor {
        return None;
    }

    let explicit_unsafe_ctor = construction
        .map(|node| {
            call_args(node).iter().any(|a| {
                let t = ctx.file.text(*a);
                t.contains("new Constructor(") || t.contains("BaseConstructor")
            })
        })
        .unwrap_or(false);

    // SnakeYAML >= 2.0 rejects global tags by default, so a bare `new Yaml()`
    // is no longer an RCE primitive there.
    if !explicit_unsafe_ctor && ctx.project.at_least("snakeyaml", 2, 0) {
        // Only call it "default" when we actually saw a no-argument
        // construction; a custom (but unrecognised) constructor is not default.
        let shape = match construction {
            Some(node) if !call_args(node).is_empty() => "a custom-constructor `Yaml`",
            _ => "a default `Yaml`",
        };
        return Some(ctx.finding(
            meta,
            call,
            format!(
                "SnakeYAML `{name}()` on {shape}. SnakeYAML {} rejects global type tags by default, so this is informational — it becomes exploitable only if a permissive `Constructor` is introduced.",
                ctx.project
                    .version_of("snakeyaml")
                    .map(|(a, b)| format!("{a}.{b}"))
                    .unwrap_or_else(|| ">= 2.0".into())
            ),
            Confidence::Low,
            Some(Severity::Info),
        ));
    }

    let confidence = if explicit_unsafe_ctor || recv_type.is_some() {
        Confidence::High
    } else {
        Confidence::Medium
    };
    Some(ctx.finding(
        meta,
        call,
        format!(
            "SnakeYAML `{name}()` on a `Yaml` built without a `SafeConstructor` can instantiate arbitrary classes (RCE)."
        ),
        confidence,
        None,
    ))
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
