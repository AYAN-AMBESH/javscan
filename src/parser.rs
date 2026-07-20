use tree_sitter::{Node, Parser, Tree};

/// A parsed Java source file plus the raw source it was parsed from.
pub struct ParsedFile {
    pub path: String,
    pub source: String,
    pub tree: Tree,
}

impl ParsedFile {
    pub fn parse(path: String, source: String) -> Option<ParsedFile> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("failed to load Java grammar");
        let tree = parser.parse(source.as_bytes(), None)?;
        Some(ParsedFile { path, source, tree })
    }

    pub fn text(&self, node: Node) -> &str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }

    /// The full source line containing this node (trimmed), for snippets.
    pub fn line_snippet(&self, node: Node) -> String {
        let row = node.start_position().row;
        self.source
            .lines()
            .nth(row)
            .unwrap_or("")
            .trim()
            .chars()
            .take(200)
            .collect()
    }
}

/// Flat index of interesting nodes collected in a single tree walk, so each
/// rule doesn't need to re-traverse the whole AST.
pub struct AstIndex<'t> {
    pub method_invocations: Vec<Node<'t>>,
    pub object_creations: Vec<Node<'t>>,
    pub variable_declarators: Vec<Node<'t>>,
    pub assignments: Vec<Node<'t>>,
    pub string_literals: Vec<Node<'t>>,
    pub method_declarations: Vec<Node<'t>>,
    pub class_declarations: Vec<Node<'t>>,
    pub line_comments: Vec<Node<'t>>,
}

impl<'t> AstIndex<'t> {
    pub fn build(file: &'t ParsedFile) -> AstIndex<'t> {
        let mut idx = AstIndex {
            method_invocations: Vec::new(),
            object_creations: Vec::new(),
            variable_declarators: Vec::new(),
            assignments: Vec::new(),
            string_literals: Vec::new(),
            method_declarations: Vec::new(),
            class_declarations: Vec::new(),
            line_comments: Vec::new(),
        };
        let mut stack = vec![file.tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "method_invocation" => idx.method_invocations.push(node),
                "object_creation_expression" => idx.object_creations.push(node),
                "variable_declarator" => idx.variable_declarators.push(node),
                "assignment_expression" => idx.assignments.push(node),
                "string_literal" => idx.string_literals.push(node),
                "method_declaration" | "constructor_declaration" => {
                    idx.method_declarations.push(node)
                }
                "class_declaration" => idx.class_declarations.push(node),
                "line_comment" | "block_comment" => idx.line_comments.push(node),
                _ => {}
            }
            for i in (0..node.child_count()).rev() {
                if let Some(c) = node.child(i) {
                    stack.push(c);
                }
            }
        }
        idx
    }
}

/// Name of the method being invoked, e.g. `exec` for `runtime.exec(cmd)`.
pub fn call_name<'f>(file: &'f ParsedFile, call: Node<'_>) -> &'f str {
    call.child_by_field_name("name")
        .map(|n| file.text(n))
        .unwrap_or("")
}

/// Source text of the receiver, e.g. `Runtime.getRuntime()` for `.exec(...)`.
pub fn receiver_text<'t>(file: &'t ParsedFile, call: Node<'t>) -> &'t str {
    call.child_by_field_name("object")
        .map(|n| file.text(n))
        .unwrap_or("")
}

/// Argument expression nodes of a call or constructor.
pub fn call_args<'t>(call: Node<'t>) -> Vec<Node<'t>> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor).collect()
}

/// Type name text of an object creation expression.
pub fn creation_type<'t>(file: &'t ParsedFile, node: Node<'t>) -> &'t str {
    node.child_by_field_name("type")
        .map(|n| file.text(n))
        .unwrap_or("")
}

/// Walk up to the enclosing method or constructor declaration.
pub fn enclosing_method<'t>(node: Node<'t>) -> Option<Node<'t>> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "method_declaration" || n.kind() == "constructor_declaration" {
            return Some(n);
        }
        cur = n.parent();
    }
    None
}

/// True if the expression is a compile-time constant (string/number literals,
/// possibly concatenated together).
pub fn is_constant_expr(file: &ParsedFile, node: Node) -> bool {
    match node.kind() {
        "string_literal" | "decimal_integer_literal" | "hex_integer_literal"
        | "decimal_floating_point_literal" | "character_literal" | "true" | "false"
        | "null_literal" => true,
        "binary_expression" => {
            let l = node.child_by_field_name("left");
            let r = node.child_by_field_name("right");
            matches!((l, r), (Some(l), Some(r)) if is_constant_expr(file, l) && is_constant_expr(file, r))
        }
        "parenthesized_expression" => node
            .named_child(0)
            .map(|c| is_constant_expr(file, c))
            .unwrap_or(false),
        _ => false,
    }
}

/// True if the expression involves string concatenation with at least one
/// non-constant part (`"SELECT * FROM t WHERE id=" + id`).
pub fn is_dynamic_concat(file: &ParsedFile, node: Node) -> bool {
    match node.kind() {
        "binary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|o| file.text(o))
                .unwrap_or("");
            if op != "+" {
                return false;
            }
            !is_constant_expr(file, node)
        }
        "parenthesized_expression" => node
            .named_child(0)
            .map(|c| is_dynamic_concat(file, c))
            .unwrap_or(false),
        _ => false,
    }
}

/// Collect every descendant node (including `node` itself) matching `pred`.
pub fn descendants<'t>(node: Node<'t>, pred: &dyn Fn(&Node<'t>) -> bool) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if pred(&n) {
            out.push(n);
        }
        for i in (0..n.child_count()).rev() {
            if let Some(c) = n.child(i) {
                stack.push(c);
            }
        }
    }
    out
}
