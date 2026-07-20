//! Cryptography rules: weak hashes, weak ciphers, weak randomness, hardcoded
//! keys/IVs, trust-all TLS, weak key sizes.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_args, call_name, creation_type, descendants, enclosing_method, receiver_text};

pub fn register(rules: &mut Vec<RuleDef>) {
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS301",
            name: "weak-hash",
            severity: Severity::High,
            cwe: "CWE-328",
            owasp: "A02:2021-Cryptographic Failures",
            description: "Broken or weak cryptographic hash (MD5/SHA-1)",
            remediation: "Use SHA-256 or stronger for integrity; use bcrypt/scrypt/Argon2 (e.g. Spring Security PasswordEncoder) for passwords.",
        },
        check: check_weak_hash,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS302",
            name: "weak-cipher",
            severity: Severity::High,
            cwe: "CWE-327",
            owasp: "A02:2021-Cryptographic Failures",
            description: "Weak cipher or insecure mode (DES/RC4/Blowfish/ECB)",
            remediation: "Use AES/GCM/NoPadding with a random 12-byte nonce per encryption (or ChaCha20-Poly1305).",
        },
        check: check_weak_cipher,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS303",
            name: "weak-random",
            severity: Severity::Low,
            cwe: "CWE-330",
            owasp: "A02:2021-Cryptographic Failures",
            description: "java.util.Random / Math.random used where unpredictability may matter",
            remediation: "Use java.security.SecureRandom for tokens, session IDs, keys, salts, OTPs, or any security decision.",
        },
        check: check_weak_random,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS304",
            name: "hardcoded-crypto-material",
            severity: Severity::High,
            cwe: "CWE-321",
            owasp: "A02:2021-Cryptographic Failures",
            description: "Hardcoded cryptographic key, IV, or PBE password",
            remediation: "Load keys from a secrets manager or KeyStore; generate IVs randomly per operation (SecureRandom).",
        },
        check: check_hardcoded_key,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS305",
            name: "trust-all-tls",
            severity: Severity::Critical,
            cwe: "CWE-295",
            owasp: "A07:2021-Identification and Authentication Failures",
            description: "TLS certificate or hostname verification disabled",
            remediation: "Never install trust-all TrustManagers or hostname verifiers. Use the platform trust store, or pin the specific certificate.",
        },
        check: check_trust_all_tls,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS306",
            name: "weak-key-size",
            severity: Severity::Medium,
            cwe: "CWE-326",
            owasp: "A02:2021-Cryptographic Failures",
            description: "Cryptographic key size below current recommendations",
            remediation: "Use RSA >= 2048 bits (3072+ preferred), EC >= 256 bits, AES >= 128 bits.",
        },
        check: check_weak_key_size,
    });
}

fn first_string_arg<'t>(ctx: &RuleCtx<'_, 't>, call: tree_sitter::Node<'t>) -> Option<String> {
    let arg = call_args(call).into_iter().next()?;
    if arg.kind() == "string_literal" {
        Some(ctx.file.text(arg).trim_matches('"').to_string())
    } else {
        None
    }
}

fn check_weak_hash(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        let recv = receiver_text(ctx.file, *call);
        if name == "getInstance" && recv.ends_with("MessageDigest") {
            if let Some(alg) = first_string_arg(ctx, *call) {
                let alg_up = alg.to_uppercase().replace('-', "");
                if matches!(alg_up.as_str(), "MD5" | "MD4" | "MD2" | "SHA1") {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        format!("Weak hash algorithm `{alg}` — collision attacks are practical."),
                        Confidence::High,
                        None,
                    ));
                }
            }
        } else if recv.ends_with("DigestUtils")
            && matches!(name, "md5" | "md5Hex" | "sha1" | "sha1Hex" | "getMd5Digest" | "getSha1Digest")
        {
            out.push(ctx.finding(
                meta,
                *call,
                format!("Weak hash via `DigestUtils.{name}()` (MD5/SHA-1)."),
                Confidence::High,
                None,
            ));
        } else if recv.ends_with("Hashing") && matches!(name, "md5" | "sha1") {
            out.push(ctx.finding(
                meta,
                *call,
                format!("Weak hash via Guava `Hashing.{name}()`."),
                Confidence::High,
                None,
            ));
        }
    }
    out
}

fn check_weak_cipher(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        if call_name(ctx.file, *call) != "getInstance"
            || !receiver_text(ctx.file, *call).ends_with("Cipher")
        {
            continue;
        }
        let Some(transform) = first_string_arg(ctx, *call) else {
            continue;
        };
        let up = transform.to_uppercase();
        let algo = up.split('/').next().unwrap_or("");
        if matches!(algo, "DES" | "DESEDE" | "RC4" | "ARCFOUR" | "RC2" | "BLOWFISH") {
            out.push(ctx.finding(
                meta,
                *call,
                format!("Weak cipher `{transform}` — algorithm is broken or has inadequate key/block size."),
                Confidence::High,
                None,
            ));
        } else if up.contains("/ECB") {
            out.push(ctx.finding(
                meta,
                *call,
                format!("ECB mode in `{transform}` leaks plaintext patterns; use GCM."),
                Confidence::High,
                None,
            ));
        } else if up == "AES" {
            out.push(ctx.finding(
                meta,
                *call,
                "`Cipher.getInstance(\"AES\")` defaults to ECB mode on most providers; specify AES/GCM/NoPadding.".into(),
                Confidence::High,
                None,
            ));
        } else if up.contains("/CBC") && up.contains("PKCS5") {
            out.push(ctx.finding(
                meta,
                *call,
                format!("`{transform}` (CBC + PKCS5) is vulnerable to padding-oracle attacks without a MAC; prefer AES/GCM."),
                Confidence::Medium,
                Some(Severity::Medium),
            ));
        }
    }
    out
}

const SECURITY_HINTS: &[&str] = &[
    "token", "secret", "password", "passwd", "otp", "session", "key", "salt",
    "nonce", "iv", "auth", "csrf", "reset", "captcha", "verif",
];

fn check_weak_random(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut flag = |node: tree_sitter::Node, what: &str| {
        let context_text = enclosing_method(node)
            .map(|m| {
                let name = m
                    .child_by_field_name("name")
                    .map(|n| ctx.file.text(n))
                    .unwrap_or("");
                format!("{name} {}", ctx.file.text(m))
            })
            .unwrap_or_default()
            .to_lowercase();
        let security_context = SECURITY_HINTS.iter().any(|h| context_text.contains(h));
        let (sev, conf, extra) = if security_context {
            (
                Some(Severity::High),
                Confidence::High,
                " in a security-sensitive context (token/secret/session generation)",
            )
        } else {
            (None, Confidence::Low, "")
        };
        out.push(ctx.finding(
            meta,
            node,
            format!("`{what}` is predictable{extra}; use SecureRandom for anything security-relevant."),
            conf,
            sev,
        ));
    };
    for creation in &ctx.index.object_creations {
        if creation_type(ctx.file, *creation) == "Random" {
            flag(*creation, "new Random()");
        }
    }
    for call in &ctx.index.method_invocations {
        if call_name(ctx.file, *call) == "random" && receiver_text(ctx.file, *call) == "Math" {
            flag(*call, "Math.random()");
        }
    }
    out
}

fn check_hardcoded_key(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for creation in &ctx.index.object_creations {
        let ty = creation_type(ctx.file, *creation);
        if !matches!(ty, "SecretKeySpec" | "IvParameterSpec" | "PBEKeySpec" | "GCMParameterSpec") {
            continue;
        }
        let args = call_args(*creation);
        let has_literal = args.iter().any(|a| {
            !descendants(*a, &|n| n.kind() == "string_literal").is_empty()
                || matches!(a.kind(), "array_initializer" | "array_creation_expression")
        });
        if has_literal {
            let what = match ty {
                "IvParameterSpec" | "GCMParameterSpec" => "IV/nonce",
                "PBEKeySpec" => "PBE password",
                _ => "key",
            };
            out.push(ctx.finding(
                meta,
                *creation,
                format!("Hardcoded {what} passed to `new {ty}(...)`; anyone with the binary can decrypt."),
                Confidence::High,
                None,
            ));
        }
    }
    out
}

fn check_trust_all_tls(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in &ctx.index.method_declarations {
        let name = m
            .child_by_field_name("name")
            .map(|n| ctx.file.text(n))
            .unwrap_or("");
        let Some(body) = m.child_by_field_name("body") else {
            continue;
        };
        if name == "checkServerTrusted" || name == "checkClientTrusted" {
            if body.named_child_count() == 0 {
                out.push(ctx.finding(
                    meta,
                    *m,
                    format!("`{name}` has an empty body — every certificate is accepted (TLS MITM possible)."),
                    Confidence::High,
                    None,
                ));
            }
        } else if name == "verify" {
            let body_text: String = ctx.file.text(body).split_whitespace().collect();
            if body_text == "{returntrue;}" {
                out.push(ctx.finding(
                    meta,
                    *m,
                    "HostnameVerifier.verify() always returns true — hostname verification disabled.".into(),
                    Confidence::High,
                    None,
                ));
            }
        }
    }
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if !matches!(name, "setHostnameVerifier" | "setDefaultHostnameVerifier") {
            continue;
        }
        for arg in call_args(*call) {
            let text: String = ctx.file.text(arg).split_whitespace().collect();
            if text.contains("->true") || text.contains("returntrue") || text.contains("ALLOW_ALL") {
                out.push(ctx.finding(
                    meta,
                    *call,
                    "Hostname verification disabled via a trust-all HostnameVerifier.".into(),
                    Confidence::High,
                    None,
                ));
                break;
            }
        }
    }
    // Legacy Apache constant
    if let Some(pos) = ctx.file.source.find("ALLOW_ALL_HOSTNAME_VERIFIER") {
        let line = ctx.file.source[..pos].matches('\n').count();
        if let Some(node) = ctx
            .file
            .tree
            .root_node()
            .descendant_for_byte_range(pos, pos + 10)
        {
            let _ = line;
            out.push(ctx.finding(
                meta,
                node,
                "`ALLOW_ALL_HOSTNAME_VERIFIER` disables hostname verification.".into(),
                Confidence::High,
                None,
            ));
        }
    }
    out
}

fn check_weak_key_size(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        if name != "initialize" && name != "init" {
            continue;
        }
        let recv = receiver_text(ctx.file, *call).to_lowercase();
        if !(recv.contains("gen") || recv.contains("kpg") || recv.contains("keygen")) {
            continue;
        }
        let Some(arg) = call_args(*call).into_iter().next() else {
            continue;
        };
        if arg.kind() == "decimal_integer_literal" {
            if let Ok(bits) = ctx.file.text(arg).parse::<u32>() {
                if matches!(bits, 512 | 768 | 1024) {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        format!("{bits}-bit asymmetric key is below modern minimums (RSA >= 2048)."),
                        Confidence::High,
                        None,
                    ));
                } else if bits == 64 || bits == 56 {
                    out.push(ctx.finding(
                        meta,
                        *call,
                        format!("{bits}-bit symmetric key is trivially brute-forceable."),
                        Confidence::High,
                        None,
                    ));
                }
            }
        }
    }
    out
}
