//! Lightweight per-file type resolution.
//!
//! javscan is a single-file analyser, so this is deliberately not a full
//! symbol table: it resolves what is visible *within one compilation unit* —
//! imports, declared variable/field/parameter types, the construction site of
//! a local, and the `extends`/`implements` clauses of classes declared in the
//! same file.
//!
//! That is enough to answer the question most name-based rules get wrong:
//! *"is the receiver of this dangerous-looking call actually the dangerous
//! type?"* When a type cannot be resolved the API returns `None`, and callers
//! decide whether an unresolved receiver should be reported (with lower
//! confidence) or suppressed.

use crate::parser::{declarator_type, AstIndex, ParsedFile};
use std::collections::HashMap;
use tree_sitter::Node;

pub struct TypeIndex<'t> {
    /// Simple name -> fully-qualified name, from single-type imports.
    imports: HashMap<String, String>,
    /// Package prefixes from `import a.b.*;` (without the trailing `*`).
    star_imports: Vec<String>,
    /// The file's own `package a.b.c;` declaration.
    package: Option<String>,
    /// Variable / field / parameter name -> declared type, generics stripped.
    var_types: HashMap<String, String>,
    /// Variable / field name -> its initializer expression node.
    var_inits: HashMap<String, Node<'t>>,
    /// Class simple name -> its `extends` + `implements` type names.
    supertypes: HashMap<String, Vec<String>>,
}

/// Strip generic arguments and array brackets: `List<Foo>[]` -> `List`.
pub fn base_type(ty: &str) -> &str {
    let ty = ty.trim();
    let end = ty.find(['<', '[']).unwrap_or(ty.len());
    ty[..end].trim()
}

/// Last dotted segment: `org.yaml.snakeyaml.Yaml` -> `Yaml`.
pub fn simple_name(ty: &str) -> &str {
    ty.rsplit('.').next().unwrap_or(ty)
}

impl<'t> TypeIndex<'t> {
    pub fn build(file: &'t ParsedFile, index: &AstIndex<'t>) -> TypeIndex<'t> {
        let mut ti = TypeIndex {
            imports: HashMap::new(),
            star_imports: Vec::new(),
            package: None,
            var_types: HashMap::new(),
            var_inits: HashMap::new(),
            supertypes: HashMap::new(),
        };

        // package declaration
        let root = file.tree.root_node();
        for i in 0..root.named_child_count() {
            let Some(c) = root.named_child(i) else { continue };
            if c.kind() == "package_declaration" {
                if let Some(name) = c.named_child(0) {
                    ti.package = Some(file.text(name).to_string());
                }
                break;
            }
        }

        for imp in &index.imports {
            // `import [static] a.b.C;` / `import a.b.*;`
            let text = file.text(*imp);
            let body = text
                .trim_start_matches("import")
                .trim()
                .trim_start_matches("static")
                .trim()
                .trim_end_matches(';')
                .trim();
            if let Some(prefix) = body.strip_suffix(".*") {
                ti.star_imports.push(prefix.to_string());
            } else if let Some(last) = body.rsplit('.').next() {
                ti.imports.insert(last.to_string(), body.to_string());
            }
        }

        for decl in &index.variable_declarators {
            let Some(name) = decl.child_by_field_name("name") else {
                continue;
            };
            let vname = file.text(name).to_string();
            if let Some(ty) = declarator_type(file, *decl) {
                ti.var_types
                    .insert(vname.clone(), base_type(ty).to_string());
            }
            if let Some(value) = decl.child_by_field_name("value") {
                ti.var_inits.insert(vname, value);
            }
        }

        for param in &index.formal_parameters {
            if let (Some(name), Some(ty)) = (
                param.child_by_field_name("name"),
                param.child_by_field_name("type"),
            ) {
                ti.var_types
                    .insert(file.text(name).to_string(), base_type(file.text(ty)).to_string());
            }
        }

        for class in &index.class_declarations {
            let Some(name) = class.child_by_field_name("name") else {
                continue;
            };
            let mut supers = Vec::new();
            for i in 0..class.named_child_count() {
                let Some(c) = class.named_child(i) else { continue };
                match c.kind() {
                    "superclass" | "extends_interfaces" | "super_interfaces" => {
                        for j in 0..c.named_child_count() {
                            if let Some(t) = c.named_child(j) {
                                collect_type_names(file, t, &mut supers);
                            }
                        }
                    }
                    _ => {}
                }
            }
            ti.supertypes.insert(file.text(name).to_string(), supers);
        }

        ti
    }

    /// Fully-qualified name for a simple type name, resolved through imports.
    /// Falls back to the input when the name cannot be resolved.
    pub fn fqn(&self, ty: &str) -> String {
        let base = base_type(ty);
        if base.contains('.') {
            return base.to_string();
        }
        if let Some(fq) = self.imports.get(base) {
            return fq.clone();
        }
        // A star import can supply it, but we cannot know which one; only
        // resolve when exactly one star import exists, otherwise stay unqualified.
        if self.star_imports.len() == 1 {
            return format!("{}.{}", self.star_imports[0], base);
        }
        base.to_string()
    }

    /// Does this file import the given fully-qualified type (exactly, or via a
    /// star import of its package)?
    pub fn imports_fqn(&self, fqn: &str) -> bool {
        if self.imports.values().any(|v| v == fqn) {
            return true;
        }
        match fqn.rsplit_once('.') {
            Some((pkg, _)) => self.star_imports.iter().any(|p| p == pkg),
            None => false,
        }
    }

    pub fn package(&self) -> Option<&str> {
        self.package.as_deref()
    }

    /// Declared type (simple name, generics stripped) of an expression, when
    /// it is resolvable from this file alone.
    pub fn type_of(&self, file: &ParsedFile, expr: Node) -> Option<String> {
        match expr.kind() {
            "object_creation_expression" => expr
                .child_by_field_name("type")
                .map(|t| base_type(file.text(t)).to_string()),
            "identifier" => self.var_types.get(file.text(expr)).cloned(),
            "field_access" => {
                let field = expr.child_by_field_name("field")?;
                let object = expr.child_by_field_name("object");
                // only `this.x` / bare field reads resolve to a declared field
                if object.map(|o| file.text(o)) == Some("this") {
                    self.var_types.get(file.text(field)).cloned()
                } else {
                    None
                }
            }
            "cast_expression" => expr
                .child_by_field_name("type")
                .map(|t| base_type(file.text(t)).to_string()),
            "parenthesized_expression" => {
                let inner = expr.named_child(0)?;
                self.type_of(file, inner)
            }
            _ => None,
        }
    }

    /// The initializer expression of a local/field, when the name is declared
    /// in this file. Unlike `construction_of` this returns any initializer,
    /// not just `new X(...)`.
    pub fn init_of(&self, file: &ParsedFile, expr: Node) -> Option<Node<'t>> {
        match expr.kind() {
            "identifier" => self.var_inits.get(file.text(expr)).copied(),
            _ => None,
        }
    }

    /// The `new X(...)` expression that produced this value, when the value is
    /// an inline construction or a local initialised with one.
    pub fn construction_of(&self, file: &ParsedFile, expr: Node<'t>) -> Option<Node<'t>> {
        match expr.kind() {
            "object_creation_expression" => Some(expr),
            "identifier" => {
                let init = self.var_inits.get(file.text(expr))?;
                if init.kind() == "object_creation_expression" {
                    Some(*init)
                } else {
                    None
                }
            }
            "parenthesized_expression" => {
                let inner = expr.named_child(0)?;
                self.construction_of(file, inner)
            }
            _ => None,
        }
    }

    /// Is `ty` — or, for classes declared in this file, any of its transitive
    /// supertypes — among `candidates`? Candidates may be simple names or FQNs.
    pub fn is_a(&self, ty: &str, candidates: &[&str]) -> bool {
        let mut seen = Vec::new();
        let mut queue = vec![base_type(ty).to_string()];
        while let Some(cur) = queue.pop() {
            if seen.iter().any(|s: &String| s == &cur) {
                continue;
            }
            seen.push(cur.clone());
            let cur_simple = simple_name(&cur);
            let cur_fqn = self.fqn(&cur);
            if candidates
                .iter()
                .any(|c| *c == cur_fqn || (!c.contains('.') && *c == cur_simple))
            {
                return true;
            }
            // Also match a candidate FQN whose simple name matches and which the
            // file actually imports — avoids matching an unrelated same-named class.
            if candidates.iter().any(|c| {
                c.contains('.') && simple_name(c) == cur_simple && self.imports_fqn(c)
            }) {
                return true;
            }
            if let Some(supers) = self.supertypes.get(cur_simple) {
                queue.extend(supers.iter().cloned());
            }
        }
        false
    }
}

fn collect_type_names(file: &ParsedFile, node: Node, out: &mut Vec<String>) {
    match node.kind() {
        "type_list" => {
            for i in 0..node.named_child_count() {
                if let Some(c) = node.named_child(i) {
                    collect_type_names(file, c, out);
                }
            }
        }
        _ => {
            let text = base_type(file.text(node));
            if !text.is_empty() {
                out.push(text.to_string());
            }
        }
    }
}
