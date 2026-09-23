use oxc_ast::ast::{
    Argument, ArrowFunctionExpression, CallExpression, ComputedMemberExpression, Expression,
    Function, ImportDeclaration, ImportDeclarationSpecifier, ImportExpression, NewExpression,
    Program, StaticMemberExpression, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{ScopeFlags, Scoping, SemanticBuilder, SymbolId};
use oxc_span::Span;
use std::collections::BTreeMap;

const MAX_FACTS: usize = 50_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    DynamicCode,
    Process,
    Network,
    Secret,
    FileRead,
    FileWrite,
    Chmod,
}

#[derive(Clone, Debug)]
pub struct CallFact {
    pub name: String,
    pub line: u64,
    pub evidence: String,
    pub capability: Option<Capability>,
    pub function: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ImportFact {
    pub specifier: String,
    pub line: u64,
}

#[derive(Clone, Debug)]
pub struct ModuleFacts {
    pub path: String,
    pub imports: Vec<ImportFact>,
    pub calls: Vec<CallFact>,
    pub flow: super::flow::ModuleFlow,
}

pub struct Collected {
    pub module: Option<ModuleFacts>,
    pub incomplete_reasons: Vec<String>,
}

pub fn collect(path: &str, source: &str, program: &Program<'_>) -> Collected {
    let result = SemanticBuilder::new_compiler()
        .with_build_nodes(true)
        .with_check_syntax_error(true)
        .build(program);
    if !result.diagnostics.is_empty() {
        return Collected {
            module: None,
            incomplete_reasons: vec![format!(
                "JS/TS semantic analysis could not fully inspect {path}: {} diagnostic(s)",
                result.diagnostics.len()
            )],
        };
    }
    let lines = std::iter::once(0)
        .chain(source.match_indices('\n').map(|(offset, _)| offset + 1))
        .collect();
    let mut collector = Collector {
        module: ModuleFacts {
            path: path.to_owned(),
            imports: Vec::new(),
            calls: Vec::new(),
            flow: super::flow::lower(program, source),
        },
        source,
        lines,
        scoping: result.semantic.scoping(),
        aliases: BTreeMap::new(),
        exceeded: false,
        current_function: None,
        named_arrow_pending: false,
    };
    collector.visit_program(program);
    Collected {
        module: Some(collector.module),
        incomplete_reasons: if collector.exceeded {
            vec![format!("JS/TS fact limit of {MAX_FACTS} reached: {path}")]
        } else {
            Vec::new()
        },
    }
}

struct Collector<'s> {
    module: ModuleFacts,
    source: &'s str,
    lines: Vec<usize>,
    scoping: &'s Scoping,
    aliases: BTreeMap<SymbolId, String>,
    exceeded: bool,
    current_function: Option<String>,
    named_arrow_pending: bool,
}

impl Collector<'_> {
    fn line(&self, span: Span) -> u64 {
        self.lines
            .partition_point(|offset| *offset <= span.start as usize) as u64
    }

    fn snippet(&self, span: Span) -> String {
        self.source
            .get(span.start as usize..span.end as usize)
            .unwrap_or_default()
            .chars()
            .take(160)
            .collect()
    }

    fn push_import(&mut self, specifier: &str, span: Span) {
        if self.module.imports.len() + self.module.calls.len() >= MAX_FACTS {
            self.exceeded = true;
            return;
        }
        self.module.imports.push(ImportFact {
            specifier: specifier.to_owned(),
            line: self.line(span),
        });
    }

    fn push_call(&mut self, name: String, span: Span) {
        if self.module.imports.len() + self.module.calls.len() >= MAX_FACTS {
            self.exceeded = true;
            return;
        }
        self.module.calls.push(CallFact {
            capability: capability(&name),
            name,
            line: self.line(span),
            evidence: self.snippet(span),
            function: self.current_function.clone(),
        });
    }

    fn name(&self, expression: &Expression<'_>) -> Option<String> {
        match expression {
            Expression::Identifier(identifier) => {
                let name = identifier.name.as_str();
                let symbol = identifier
                    .reference_id
                    .get()
                    .and_then(|id| self.scoping.get_reference(id).symbol_id());
                match symbol {
                    Some(symbol) => Some(
                        self.aliases
                            .get(&symbol)
                            .cloned()
                            .unwrap_or_else(|| format!("local:{name}")),
                    ),
                    None => Some(name.to_owned()),
                }
            }
            Expression::StaticMemberExpression(member) => Some(format!(
                "{}.{}",
                self.name(&member.object)?,
                member.property.name
            )),
            Expression::ComputedMemberExpression(member) => Some(format!(
                "{}.{}",
                self.name(&member.object)?,
                static_string(&member.expression)?
            )),
            Expression::ParenthesizedExpression(expression) => self.name(&expression.expression),
            Expression::CallExpression(call)
                if self.name(&call.callee).as_deref() == Some("require") =>
            {
                call.arguments.first().and_then(argument_string)
            }
            Expression::ChainExpression(expression) => match &expression.expression {
                oxc_ast::ast::ChainElement::CallExpression(call) => self.name(&call.callee),
                _ => None,
            },
            _ => None,
        }
    }

    fn imported_binding(&mut self, symbol: Option<SymbolId>, name: String) {
        if let Some(symbol) = symbol {
            self.aliases.insert(symbol, name);
        }
    }
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_import_declaration(&mut self, import: &ImportDeclaration<'a>) {
        let specifier = import.source.value.as_str();
        self.push_import(specifier, import.span);
        if let Some(bindings) = &import.specifiers {
            for binding in bindings {
                match binding {
                    ImportDeclarationSpecifier::ImportSpecifier(named) => {
                        let imported = match &named.imported {
                            oxc_ast::ast::ModuleExportName::IdentifierName(name) => {
                                name.name.as_str()
                            }
                            oxc_ast::ast::ModuleExportName::IdentifierReference(name) => {
                                name.name.as_str()
                            }
                            oxc_ast::ast::ModuleExportName::StringLiteral(name) => {
                                name.value.as_str()
                            }
                        };
                        self.imported_binding(
                            named.local.symbol_id.get(),
                            format!("{specifier}.{imported}"),
                        );
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
                        self.imported_binding(default.local.symbol_id.get(), specifier.to_owned());
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
                        self.imported_binding(
                            namespace.local.symbol_id.get(),
                            specifier.to_owned(),
                        );
                    }
                }
            }
        }
        walk::walk_import_declaration(self, import);
    }

    fn visit_variable_declarator(&mut self, variable: &VariableDeclarator<'a>) {
        if let (Some(initializer), oxc_ast::ast::BindingPattern::BindingIdentifier(binding)) =
            (&variable.init, &variable.id)
        {
            let alias = if let Expression::CallExpression(call) = initializer {
                if self.name(&call.callee).as_deref() == Some("require") {
                    call.arguments.first().and_then(argument_string)
                } else {
                    self.name(initializer)
                }
            } else {
                self.name(initializer)
            };
            if let Some(alias) = alias {
                self.imported_binding(binding.symbol_id.get(), alias);
            }
        }
        if let (
            Some(Expression::CallExpression(call)),
            oxc_ast::ast::BindingPattern::ObjectPattern(pattern),
        ) = (&variable.init, &variable.id)
            && self.name(&call.callee).as_deref() == Some("require")
            && let Some(specifier) = call.arguments.first().and_then(argument_string)
        {
            for property in &pattern.properties {
                if let oxc_ast::ast::BindingPattern::BindingIdentifier(binding) = &property.value {
                    let name = match &property.key {
                        oxc_ast::ast::PropertyKey::StaticIdentifier(name) => {
                            Some(name.name.as_str())
                        }
                        oxc_ast::ast::PropertyKey::StringLiteral(name) => Some(name.value.as_str()),
                        _ => None,
                    };
                    if let Some(name) = name {
                        self.imported_binding(
                            binding.symbol_id.get(),
                            format!("{specifier}.{name}"),
                        );
                    }
                }
            }
        }
        let previous = self.current_function.clone();
        let previous_pending = self.named_arrow_pending;
        if matches!(variable.init, Some(Expression::ArrowFunctionExpression(_))) {
            self.current_function = match &variable.id {
                oxc_ast::ast::BindingPattern::BindingIdentifier(binding) => {
                    Some(binding.name.to_string())
                }
                _ => Some("<anonymous>".to_owned()),
            };
            self.named_arrow_pending = true;
        }
        walk::walk_variable_declarator(self, variable);
        self.current_function = previous;
        self.named_arrow_pending = previous_pending;
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let previous = self.current_function.clone();
        self.current_function = Some(
            function
                .id
                .as_ref()
                .map(|id| id.name.to_string())
                .unwrap_or_else(|| "<anonymous>".to_owned()),
        );
        walk::walk_function(self, function, flags);
        self.current_function = previous;
    }

    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        let previous = self.current_function.clone();
        if !self.named_arrow_pending {
            self.current_function = Some("<anonymous>".to_owned());
        }
        self.named_arrow_pending = false;
        walk::walk_arrow_function_expression(self, function);
        self.current_function = previous;
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(name) = self.name(&call.callee) {
            if name == "require"
                && let Some(specifier) = call.arguments.first().and_then(argument_string)
            {
                self.push_import(&specifier, call.span);
            }
            self.push_call(name, call.span);
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, call: &NewExpression<'a>) {
        if let Some(name) = self.name(&call.callee) {
            self.push_call(name, call.span);
        }
        walk::walk_new_expression(self, call);
    }

    fn visit_import_expression(&mut self, import: &ImportExpression<'a>) {
        if let Some(specifier) = static_string(&import.source) {
            self.push_import(&specifier, import.span);
        }
        self.push_call("import".to_owned(), import.span);
        walk::walk_import_expression(self, import);
    }

    fn visit_static_member_expression(&mut self, member: &StaticMemberExpression<'a>) {
        if let Some(name) = self.name(&member.object) {
            let name = format!("{name}.{}", member.property.name);
            if capability(&name) == Some(Capability::Secret) || name == "process.env" {
                self.push_call(name, member.span);
            }
        }
        walk::walk_static_member_expression(self, member);
    }

    fn visit_computed_member_expression(&mut self, member: &ComputedMemberExpression<'a>) {
        walk::walk_computed_member_expression(self, member);
    }
}

fn argument_string(argument: &Argument<'_>) -> Option<String> {
    match argument {
        Argument::StringLiteral(value) => Some(value.value.to_string()),
        _ => None,
    }
}

pub(super) fn static_string(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::StringLiteral(value) => Some(value.value.to_string()),
        Expression::BinaryExpression(binary)
            if binary.operator == oxc_ast::ast::BinaryOperator::Addition =>
        {
            Some(format!(
                "{}{}",
                static_string(&binary.left)?,
                static_string(&binary.right)?
            ))
        }
        _ => None,
    }
}

fn capability(name: &str) -> Option<Capability> {
    match name {
        "eval"
        | "Function"
        | "global.Function"
        | "globalThis.Function"
        | "global.eval"
        | "vm.runInThisContext"
        | "vm.runInNewContext"
        | "vm.runInContext"
        | "vm.Script"
        | "node:vm.runInThisContext"
        | "node:vm.runInNewContext"
        | "node:vm.runInContext"
        | "node:vm.Script"
        | "process.dlopen"
        | "import" => Some(Capability::DynamicCode),
        "child_process.exec"
        | "child_process.execSync"
        | "child_process.spawn"
        | "child_process.spawnSync"
        | "child_process.fork"
        | "node:child_process.exec"
        | "node:child_process.execSync"
        | "node:child_process.spawn"
        | "node:child_process.spawnSync"
        | "node:child_process.fork"
        | "Bun.spawn"
        | "Deno.Command" => Some(Capability::Process),
        "fetch" | "axios" | "axios.get" | "axios.post" | "http.request" | "https.request"
        | "node:http.request" | "node:https.request" | "got" | "request" | "undici.request"
        | "WebSocket" | "ws" | "net.Socket" | "tls.connect" => Some(Capability::Network),
        "fs.readFile" | "fs.readFileSync" | "node:fs.readFile" | "node:fs.readFileSync" => {
            Some(Capability::FileRead)
        }
        "process.env" | "os.homedir" | "node:os.homedir" => Some(Capability::Secret),
        "fs.writeFile" | "fs.writeFileSync" | "node:fs.writeFile" | "node:fs.writeFileSync" => {
            Some(Capability::FileWrite)
        }
        "fs.chmod" | "fs.chmodSync" | "node:fs.chmod" | "node:fs.chmodSync" => {
            Some(Capability::Chmod)
        }
        _ => None,
    }
}
