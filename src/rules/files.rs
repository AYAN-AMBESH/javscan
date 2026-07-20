//! Filesystem rules: path traversal and zip-slip.

use super::{RuleCtx, RuleDef, RuleMeta};
use crate::findings::{Confidence, Finding, Severity};
use crate::parser::{call_args, call_name, creation_type, receiver_text};

pub fn register(rules: &mut Vec<RuleDef>) {
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS601",
            name: "path-traversal",
            severity: Severity::High,
            cwe: "CWE-22",
            owasp: "A01:2021-Broken Access Control",
            description: "Filesystem path built from untrusted input",
            remediation: "Canonicalize with path.normalize()/getCanonicalPath() and verify the result stays under the intended base directory; or map user input to server-chosen file names.",
        },
        check: check_path_traversal,
    });
    rules.push(RuleDef {
        meta: RuleMeta {
            id: "JS602",
            name: "zip-slip",
            severity: Severity::High,
            cwe: "CWE-22",
            owasp: "A01:2021-Broken Access Control",
            description: "Archive entry name used to build an extraction path (Zip Slip)",
            remediation: "After resolving entry paths, verify destPath.normalize().startsWith(targetDir) before writing each entry.",
        },
        check: check_zip_slip,
    });
}

const FILE_TYPES: &[&str] = &[
    "File",
    "FileInputStream",
    "FileOutputStream",
    "FileReader",
    "FileWriter",
    "RandomAccessFile",
    "PrintWriter",
];

const FILES_METHODS: &[&str] = &[
    "readAllBytes",
    "readAllLines",
    "readString",
    "write",
    "writeString",
    "newInputStream",
    "newOutputStream",
    "newBufferedReader",
    "newBufferedWriter",
    "copy",
    "move",
    "delete",
    "deleteIfExists",
    "createFile",
    "createDirectories",
];

fn zip_context(ctx: &RuleCtx) -> bool {
    ctx.file.source.contains("ZipEntry")
        || ctx.file.source.contains("ZipInputStream")
        || ctx.file.source.contains("TarArchiveEntry")
        || ctx.file.source.contains("ArchiveEntry")
}

fn arg_uses_entry_name(ctx: &RuleCtx, arg: tree_sitter::Node) -> bool {
    ctx.file.text(arg).contains(".getName()")
}

fn check_path_traversal(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    let in_zip = zip_context(ctx);
    for creation in &ctx.index.object_creations {
        let ty = creation_type(ctx.file, *creation);
        if !FILE_TYPES.contains(&ty) {
            continue;
        }
        for arg in call_args(*creation) {
            // zip-slip rule owns entry.getName() flows
            if in_zip && arg_uses_entry_name(ctx, arg) {
                continue;
            }
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *creation,
                    format!("User-controlled data flows into `new {ty}(...)`; attacker can reach arbitrary paths (../ traversal)."),
                    Confidence::High,
                    None,
                ));
                break;
            }
        }
    }
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        let recv = receiver_text(ctx.file, *call);
        let recv_last = recv.rsplit('.').next().unwrap_or(recv);
        let is_sink = (name == "get" && recv_last == "Paths")
            || (name == "of" && recv_last == "Path")
            || (FILES_METHODS.contains(&name) && recv_last == "Files");
        if !is_sink {
            continue;
        }
        for arg in call_args(*call) {
            if in_zip && arg_uses_entry_name(ctx, arg) {
                continue;
            }
            if ctx.taint.expr_tainted(arg) {
                out.push(ctx.finding(
                    meta,
                    *call,
                    format!("User-controlled data flows into `{recv_last}.{name}(...)`; attacker can reach arbitrary paths."),
                    Confidence::High,
                    None,
                ));
                break;
            }
        }
    }
    out
}

fn check_zip_slip(ctx: &RuleCtx, meta: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    if !zip_context(ctx) {
        return out;
    }
    // startsWith / normalize checks anywhere in the file suggest the pattern is guarded
    let guarded = ctx.file.source.contains(".startsWith(")
        && (ctx.file.source.contains(".normalize()")
            || ctx.file.source.contains("getCanonicalPath"));
    if guarded {
        return out;
    }
    for creation in &ctx.index.object_creations {
        let ty = creation_type(ctx.file, *creation);
        if !FILE_TYPES.contains(&ty) {
            continue;
        }
        if call_args(*creation).iter().any(|a| arg_uses_entry_name(ctx, *a)) {
            out.push(ctx.finding(
                meta,
                *creation,
                format!("Archive entry name used in `new {ty}(...)` without a containment check — entries named `../../evil` escape the target directory."),
                Confidence::High,
                None,
            ));
        }
    }
    for call in &ctx.index.method_invocations {
        let name = call_name(ctx.file, *call);
        let recv = receiver_text(ctx.file, *call);
        let is_path_build = (name == "get" && recv.ends_with("Paths"))
            || name == "resolve"
            || (name == "of" && recv.ends_with("Path"));
        if !is_path_build {
            continue;
        }
        if call_args(*call).iter().any(|a| arg_uses_entry_name(ctx, *a)) {
            out.push(ctx.finding(
                meta,
                *call,
                "Archive entry name used to build an extraction path without a containment check (Zip Slip).".into(),
                Confidence::High,
                Some(Severity::High),
            ));
        }
    }
    out
}
