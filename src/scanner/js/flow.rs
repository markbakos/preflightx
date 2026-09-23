use super::{ModuleFacts, semantic::static_string};
use crate::model::{Confidence, Finding, Severity};
use crate::scanner::graph::resolve_import;
use oxc_ast::ast::{
    Argument, BindingPattern, Declaration, Expression, ImportDeclarationSpecifier,
    ObjectPropertyKind, Program, PropertyKey, Statement,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct ModuleFlow {
    pub imports: BTreeMap<String, (String, String)>,
    pub functions: BTreeMap<String, Function>,
    pub body: Vec<Stmt>,
}

#[derive(Clone, Debug)]
pub struct Function {
    params: Vec<Binding>,
    body: Vec<Stmt>,
}

#[derive(Clone, Debug)]
pub enum Binding {
    Name(String),
    Object(Vec<(String, Binding)>),
    Array(Vec<Binding>),
    Ignore,
}

#[derive(Clone, Debug)]
pub enum Stmt {
    Bind(Binding, Expr),
    Expr(Expr),
    Return(Expr),
    Branch(Vec<Stmt>, Vec<Stmt>),
}

#[derive(Clone, Debug)]
pub enum Expr {
    Name(String),
    String(String),
    Member(Box<Expr>, String),
    Call(Box<Expr>, Vec<Expr>, u64),
    Object(Vec<(String, Expr)>),
    Combine(Vec<Expr>),
    Assign(String, Box<Expr>),
    Unknown,
}

struct Lower<'a> {
    source: &'a str,
}

impl Lower<'_> {
    fn line(&self, offset: u32) -> u64 {
        self.source
            .get(..offset as usize)
            .unwrap_or_default()
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count() as u64
            + 1
    }

    fn binding(&self, pattern: &BindingPattern<'_>) -> Binding {
        match pattern {
            BindingPattern::BindingIdentifier(name) => Binding::Name(name.name.to_string()),
            BindingPattern::ObjectPattern(object) => Binding::Object(
                object
                    .properties
                    .iter()
                    .filter_map(|property| {
                        Some((self.key(&property.key)?, self.binding(&property.value)))
                    })
                    .collect(),
            ),
            BindingPattern::ArrayPattern(array) => Binding::Array(
                array
                    .elements
                    .iter()
                    .map(|element| {
                        element
                            .as_ref()
                            .map(|item| self.binding(item))
                            .unwrap_or(Binding::Ignore)
                    })
                    .collect(),
            ),
            BindingPattern::AssignmentPattern(assignment) => self.binding(&assignment.left),
        }
    }

    fn key(&self, key: &PropertyKey<'_>) -> Option<String> {
        match key {
            PropertyKey::StaticIdentifier(name) => Some(name.name.to_string()),
            PropertyKey::StringLiteral(value) => Some(value.value.to_string()),
            _ => None,
        }
    }

    fn expr(&self, expression: &Expression<'_>) -> Expr {
        match expression {
            Expression::Identifier(value) => Expr::Name(value.name.to_string()),
            Expression::StringLiteral(value) => Expr::String(value.value.to_string()),
            Expression::TemplateLiteral(value) if value.expressions.is_empty() => Expr::String(
                value
                    .quasis
                    .iter()
                    .map(|part| part.value.raw.as_str())
                    .collect(),
            ),
            Expression::StaticMemberExpression(member) => Expr::Member(
                Box::new(self.expr(&member.object)),
                member.property.name.to_string(),
            ),
            Expression::ComputedMemberExpression(member) => {
                if let Some(property) = static_string(&member.expression) {
                    Expr::Member(Box::new(self.expr(&member.object)), property)
                } else {
                    Expr::Unknown
                }
            }
            Expression::CallExpression(call) => Expr::Call(
                Box::new(self.expr(&call.callee)),
                call.arguments
                    .iter()
                    .map(|argument| self.argument(argument))
                    .collect(),
                self.line(call.span.start),
            ),
            Expression::NewExpression(call) => Expr::Call(
                Box::new(self.expr(&call.callee)),
                call.arguments
                    .iter()
                    .map(|argument| self.argument(argument))
                    .collect(),
                self.line(call.span.start),
            ),
            Expression::ImportExpression(import) => Expr::Call(
                Box::new(Expr::Name("import".to_owned())),
                vec![self.expr(&import.source)],
                self.line(import.span.start),
            ),
            Expression::AwaitExpression(awaited) => self.expr(&awaited.argument),
            Expression::ParenthesizedExpression(paren) => self.expr(&paren.expression),
            Expression::TSAsExpression(cast) => self.expr(&cast.expression),
            Expression::TSSatisfiesExpression(cast) => self.expr(&cast.expression),
            Expression::TSNonNullExpression(cast) => self.expr(&cast.expression),
            Expression::ObjectExpression(object) => Expr::Object(
                object
                    .properties
                    .iter()
                    .filter_map(|property| match property {
                        ObjectPropertyKind::ObjectProperty(property) => {
                            Some((self.key(&property.key)?, self.expr(&property.value)))
                        }
                        _ => None,
                    })
                    .collect(),
            ),
            Expression::BinaryExpression(binary) => {
                Expr::Combine(vec![self.expr(&binary.left), self.expr(&binary.right)])
            }
            Expression::LogicalExpression(binary) => {
                Expr::Combine(vec![self.expr(&binary.left), self.expr(&binary.right)])
            }
            Expression::ConditionalExpression(conditional) => Expr::Combine(vec![
                self.expr(&conditional.consequent),
                self.expr(&conditional.alternate),
            ]),
            Expression::SequenceExpression(sequence) => Expr::Combine(
                sequence
                    .expressions
                    .iter()
                    .map(|item| self.expr(item))
                    .collect(),
            ),
            Expression::AssignmentExpression(assignment) => {
                match assignment.left.get_identifier_name() {
                    Some(name) => {
                        Expr::Assign(name.to_owned(), Box::new(self.expr(&assignment.right)))
                    }
                    None => self.expr(&assignment.right),
                }
            }
            _ => Expr::Unknown,
        }
    }

    fn argument(&self, argument: &Argument<'_>) -> Expr {
        match argument.as_expression() {
            Some(expression) => self.expr(expression),
            None => Expr::Unknown,
        }
    }

    fn statements(
        &self,
        statements: &[Statement<'_>],
        functions: &mut BTreeMap<String, Function>,
    ) -> Vec<Stmt> {
        statements
            .iter()
            .flat_map(|statement| self.statement(statement, functions))
            .collect()
    }

    fn declaration(
        &self,
        declaration: &Declaration<'_>,
        functions: &mut BTreeMap<String, Function>,
    ) -> Vec<Stmt> {
        match declaration {
            Declaration::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    let params = function
                        .params
                        .items
                        .iter()
                        .map(|item| self.binding(&item.pattern))
                        .collect();
                    let body = function
                        .body
                        .as_ref()
                        .map(|body| self.statements(&body.statements, functions))
                        .unwrap_or_default();
                    functions.insert(id.name.to_string(), Function { params, body });
                }
                Vec::new()
            }
            Declaration::VariableDeclaration(variable) => variable
                .declarations
                .iter()
                .map(|item| {
                    let binding = self.binding(&item.id);
                    if let (Binding::Name(name), Some(Expression::ArrowFunctionExpression(arrow))) =
                        (&binding, &item.init)
                    {
                        let params = arrow
                            .params
                            .items
                            .iter()
                            .map(|item| self.binding(&item.pattern))
                            .collect();
                        let body = match &arrow.body {
                            oxc_ast::ast::ArrowFunctionBody::FunctionBody(body) => {
                                self.statements(&body.statements, functions)
                            }
                            _ => arrow
                                .body
                                .as_expression()
                                .map(|body| vec![Stmt::Return(self.expr(body))])
                                .unwrap_or_default(),
                        };
                        functions.insert(name.clone(), Function { params, body });
                    }
                    Stmt::Bind(
                        binding,
                        item.init
                            .as_ref()
                            .map(|expr| self.expr(expr))
                            .unwrap_or(Expr::Unknown),
                    )
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn statement(
        &self,
        statement: &Statement<'_>,
        functions: &mut BTreeMap<String, Function>,
    ) -> Vec<Stmt> {
        match statement {
            Statement::FunctionDeclaration(_) | Statement::VariableDeclaration(_) => statement
                .as_declaration()
                .map(|declaration| self.declaration(declaration, functions))
                .unwrap_or_default(),
            Statement::ExportDeclaration(export) => {
                self.declaration(&export.declaration, functions)
            }
            Statement::ExpressionStatement(expression) => {
                vec![Stmt::Expr(self.expr(&expression.expression))]
            }
            Statement::ReturnStatement(ret) => ret
                .argument
                .as_ref()
                .map(|expression| vec![Stmt::Return(self.expr(expression))])
                .unwrap_or_default(),
            Statement::BlockStatement(block) => self.statements(&block.body, functions),
            Statement::IfStatement(branch) => vec![Stmt::Branch(
                self.statement(&branch.consequent, functions),
                branch
                    .alternate
                    .as_ref()
                    .map(|alternate| self.statement(alternate, functions))
                    .unwrap_or_default(),
            )],
            _ => Vec::new(),
        }
    }
}

pub fn lower(program: &Program<'_>, source: &str) -> ModuleFlow {
    let lower = Lower { source };
    let mut imports = BTreeMap::new();
    for statement in &program.body {
        if let Statement::ImportDeclaration(import) = statement {
            let specifier = import.source.value.to_string();
            if let Some(bindings) = &import.specifiers {
                for binding in bindings {
                    match binding {
                        ImportDeclarationSpecifier::ImportSpecifier(named) => {
                            let imported = match &named.imported {
                                oxc_ast::ast::ModuleExportName::IdentifierName(name) => {
                                    name.name.to_string()
                                }
                                oxc_ast::ast::ModuleExportName::IdentifierReference(name) => {
                                    name.name.to_string()
                                }
                                oxc_ast::ast::ModuleExportName::StringLiteral(name) => {
                                    name.value.to_string()
                                }
                            };
                            imports.insert(
                                named.local.name.to_string(),
                                (specifier.clone(), imported),
                            );
                        }
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
                            imports.insert(
                                default.local.name.to_string(),
                                (specifier.clone(), "default".to_owned()),
                            );
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
                            imports.insert(
                                namespace.local.name.to_string(),
                                (specifier.clone(), "*".to_owned()),
                            );
                        }
                    }
                }
            }
        }
    }
    let mut functions = BTreeMap::new();
    let body = lower.statements(&program.body, &mut functions);
    ModuleFlow {
        imports,
        functions,
        body,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Label {
    Remote,
    DecodedRemote,
    EnvSecret,
    FileSecret,
    Clipboard,
    UserHome,
}

#[derive(Clone, Copy)]
enum ChainRule {
    RemoteCode,
    RemoteProcess,
    DownloadExecute,
    SecretExfiltration,
}

impl ChainRule {
    fn details(self) -> (&'static str, &'static str, u8) {
        match self {
            Self::RemoteCode => (
                "JS-REMOTE-CODE-EXECUTION",
                "Remote data reaches dynamic execution",
                98,
            ),
            Self::RemoteProcess => (
                "JS-REMOTE-PROCESS-EXECUTION",
                "Remote data reaches process execution",
                97,
            ),
            Self::DownloadExecute => (
                "JS-DOWNLOAD-WRITE-EXECUTE",
                "Downloaded bytes are written and executed",
                98,
            ),
            Self::SecretExfiltration => (
                "JS-SECRET-EXFILTRATION",
                "Sensitive data reaches an outbound request",
                97,
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Value {
    name: Option<String>,
    literal: Option<String>,
    labels: BTreeMap<Label, Vec<String>>,
    fields: BTreeMap<String, Value>,
}

impl Value {
    fn named(name: String) -> Self {
        Self {
            name: Some(name),
            ..Self::default()
        }
    }

    fn literal(text: String) -> Self {
        Self {
            literal: Some(text),
            ..Self::default()
        }
    }

    fn labeled(label: Label, source: String) -> Self {
        Self {
            labels: BTreeMap::from([(label, vec![source])]),
            ..Self::default()
        }
    }

    fn merge(&mut self, other: Self) {
        for (label, route) in other.labels {
            self.labels.entry(label).or_insert(route);
        }
        if self.literal.is_none() {
            self.literal = other.literal;
        }
        if self.name.is_none() {
            self.name = other.name;
        }
        for (key, value) in other.fields {
            self.fields.entry(key).or_insert(value);
        }
    }

    fn propagate(mut self, step: String) -> Self {
        for route in self.labels.values_mut() {
            if route.len() < 16 {
                route.push(step.clone());
            }
        }
        self
    }

    fn label(&self, labels: &[Label]) -> Option<&Vec<String>> {
        labels.iter().find_map(|label| self.labels.get(label))
    }
}

pub struct FlowResult {
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
}

struct Evaluator<'a> {
    modules: BTreeMap<&'a str, &'a ModuleFacts>,
    reachable: &'a BTreeMap<String, Vec<String>>,
    findings: Vec<Finding>,
    seen: std::collections::BTreeSet<(String, String, u64)>,
    steps: usize,
    limited: bool,
    written: BTreeMap<String, Value>,
}

const MAX_FLOW_STEPS: usize = 100_000;
const MAX_CALL_DEPTH: usize = 32;

pub fn analyze_flows(
    modules: &[ModuleFacts],
    reachable: &BTreeMap<String, Vec<String>>,
) -> FlowResult {
    let mut evaluator = Evaluator {
        modules: modules
            .iter()
            .map(|module| (module.path.as_str(), module))
            .collect(),
        reachable,
        findings: Vec::new(),
        seen: std::collections::BTreeSet::new(),
        steps: 0,
        limited: false,
        written: BTreeMap::new(),
    };
    for module in modules {
        evaluator.written.clear();
        let mut environment = evaluator.imports(module);
        evaluator.run(&module.path, &module.flow.body, &mut environment, 0);
    }
    FlowResult {
        findings: evaluator.findings,
        incomplete_reasons: if evaluator.limited {
            vec![format!(
                "JS/TS data-flow work limit of {MAX_FLOW_STEPS} steps or call depth {MAX_CALL_DEPTH} reached"
            )]
        } else {
            Vec::new()
        },
    }
}

impl Evaluator<'_> {
    fn imports(&self, module: &ModuleFacts) -> BTreeMap<String, Value> {
        module
            .flow
            .imports
            .iter()
            .map(|(local, (specifier, exported))| {
                (
                    local.clone(),
                    Value::named(format!("import:{specifier}#{exported}")),
                )
            })
            .collect()
    }

    fn run(
        &mut self,
        path: &str,
        body: &[Stmt],
        environment: &mut BTreeMap<String, Value>,
        depth: usize,
    ) -> Option<Value> {
        if depth >= MAX_CALL_DEPTH {
            self.limited = true;
            return None;
        }
        let mut pending_return: Option<Value> = None;
        for statement in body {
            self.steps += 1;
            if self.steps > MAX_FLOW_STEPS {
                self.limited = true;
                return None;
            }
            match statement {
                Stmt::Bind(binding, expression) => {
                    let value = self.eval(path, expression, environment, depth);
                    self.bind(binding, value, environment);
                }
                Stmt::Expr(expression) => {
                    self.eval(path, expression, environment, depth);
                }
                Stmt::Return(expression) => {
                    let value = self.eval(path, expression, environment, depth);
                    if let Some(pending) = &mut pending_return {
                        pending.merge(value);
                        return pending_return;
                    }
                    return Some(value);
                }
                Stmt::Branch(yes, no) => {
                    let mut left = environment.clone();
                    let mut right = environment.clone();
                    let a = self.run(path, yes, &mut left, depth + 1);
                    let b = self.run(path, no, &mut right, depth + 1);
                    let mut merged = left;
                    for (name, value) in right {
                        merged.entry(name).or_default().merge(value);
                    }
                    *environment = merged;
                    if let Some(a) = a {
                        pending_return.get_or_insert_with(Value::default).merge(a);
                    }
                    if let Some(b) = b {
                        pending_return.get_or_insert_with(Value::default).merge(b);
                    }
                    if yes.iter().any(|item| matches!(item, Stmt::Return(_)))
                        && no.iter().any(|item| matches!(item, Stmt::Return(_)))
                    {
                        return pending_return;
                    }
                }
            }
        }
        pending_return
    }

    fn bind(&self, binding: &Binding, value: Value, environment: &mut BTreeMap<String, Value>) {
        match binding {
            Binding::Name(name) => {
                environment.insert(name.clone(), value);
            }
            Binding::Object(properties) => {
                for (property, nested) in properties {
                    let selected = value.fields.get(property).cloned().unwrap_or_else(|| {
                        let mut selected = value.clone();
                        selected.name =
                            value.name.as_ref().map(|name| format!("{name}.{property}"));
                        selected
                    });
                    self.bind(nested, selected, environment);
                }
            }
            Binding::Array(items) => {
                for nested in items {
                    self.bind(nested, value.clone(), environment);
                }
            }
            Binding::Ignore => {}
        }
    }

    fn eval(
        &mut self,
        path: &str,
        expression: &Expr,
        environment: &mut BTreeMap<String, Value>,
        depth: usize,
    ) -> Value {
        if self.limited {
            return Value::default();
        }
        match expression {
            Expr::Name(name) => environment
                .get(name)
                .cloned()
                .unwrap_or_else(|| Value::named(name.clone())),
            Expr::String(text) => Value::literal(text.clone()),
            Expr::Member(object, property) => {
                let base = self.eval(path, object, environment, depth);
                let full_name = Some(
                    base.name
                        .as_ref()
                        .map(|name| format!("{name}.{property}"))
                        .unwrap_or_else(|| format!(".{property}")),
                );
                if full_name.as_deref() == Some("process.env") {
                    return Value::labeled(Label::EnvSecret, format!("source: {path} process.env"));
                }
                let mut value = base.fields.get(property).cloned().unwrap_or(base);
                value.name = full_name;
                value
            }
            Expr::Object(properties) => {
                let mut value = Value::default();
                for (name, expression) in properties {
                    let field = self.eval(path, expression, environment, depth);
                    value.merge(field.clone());
                    value.fields.insert(name.clone(), field);
                }
                value
            }
            Expr::Combine(parts) => {
                let mut combined = Value::default();
                let mut literal = Some(String::new());
                for part in parts {
                    let part = self.eval(path, part, environment, depth);
                    if let (Some(buffer), Some(text)) = (&mut literal, &part.literal) {
                        buffer.push_str(text);
                    } else {
                        literal = None;
                    }
                    combined.merge(part);
                }
                combined.literal = literal;
                combined
            }
            Expr::Assign(name, right) => {
                let value = self.eval(path, right, environment, depth);
                environment.insert(name.clone(), value.clone());
                value
            }
            Expr::Call(callee, arguments, line) => {
                let function = self.eval(path, callee, environment, depth);
                let mut args = arguments
                    .iter()
                    .map(|arg| self.eval(path, arg, environment, depth))
                    .collect::<Vec<_>>();
                if matches!(callee.as_ref(), Expr::Member(_, _)) && !function.labels.is_empty() {
                    args.insert(0, function.clone());
                }
                self.invoke(
                    path,
                    function.name.as_deref().unwrap_or(""),
                    args,
                    *line,
                    environment,
                    depth,
                )
            }
            Expr::Unknown => Value::default(),
        }
    }

    fn invoke(
        &mut self,
        path: &str,
        name: &str,
        args: Vec<Value>,
        line: u64,
        environment: &BTreeMap<String, Value>,
        depth: usize,
    ) -> Value {
        let module = self.modules.get(path).copied();
        if let Some(module) = module {
            if let Some(function) = module.flow.functions.get(name).cloned() {
                return self.call_function(path, &function, args, environment.clone(), depth + 1);
            }
            if let Some(import) = name.strip_prefix("import:")
                && let Some((specifier, exported)) = import.rsplit_once('#')
                && specifier.starts_with('.')
                && let Some(target) = resolve_import(path, specifier, &self.modules)
                && let Some(function) = self.modules[target].flow.functions.get(exported).cloned()
            {
                let target = target.to_owned();
                let scope = self.imports(self.modules[target.as_str()]);
                return self.call_function(&target, &function, args, scope, depth + 1);
            }
        }
        let name = name
            .strip_prefix("import:")
            .and_then(|value| value.rsplit_once('#'))
            .map(|(module, exported)| {
                if exported == "*" || exported == "default" {
                    module.to_owned()
                } else if let Some(member) = exported
                    .strip_prefix("*.")
                    .or_else(|| exported.strip_prefix("default."))
                {
                    format!("{module}.{member}")
                } else {
                    format!("{module}.{exported}")
                }
            })
            .unwrap_or_else(|| name.to_owned());
        let name = name.as_str();
        let normalized = name.strip_prefix("node:").unwrap_or(name);
        let source = format!("source: {path}:{line} {name}");
        if matches!(
            normalized,
            "axios"
                | "axios.get"
                | "fetch"
                | "got"
                | "request"
                | "undici.request"
                | "http.request"
                | "https.request"
                | "WebSocket"
                | "ws"
                | "net.Socket"
                | "tls.connect"
        ) {
            if matches!(
                normalized,
                "fetch"
                    | "axios"
                    | "axios.post"
                    | "http.request"
                    | "https.request"
                    | "request"
                    | "undici.request"
            ) {
                self.exfiltration(path, line, name, &args);
            }
            return Value::labeled(Label::Remote, source);
        }
        if normalized == "axios.post" {
            self.exfiltration(path, line, name, &args);
            return Value::labeled(Label::Remote, source);
        }
        if matches!(normalized, "fs.readFile" | "fs.readFileSync") {
            let target = args
                .first()
                .and_then(|value| value.literal.as_deref())
                .unwrap_or("");
            if sensitive_path(target) {
                return Value::labeled(Label::FileSecret, source);
            }
        }
        if matches!(normalized, "os.homedir") {
            let mut value = Value::labeled(Label::UserHome, source);
            value.literal = Some("$HOME".to_owned());
            return value;
        }
        if matches!(
            normalized,
            "clipboard.readText" | "clipboard.read" | "electron.clipboard.readText"
        ) {
            return Value::labeled(Label::Clipboard, source);
        }
        if matches!(normalized, "Buffer.from" | "atob") {
            let mut output = args.first().cloned().unwrap_or_default();
            if output.labels.contains_key(&Label::Remote) {
                let route = output.labels.remove(&Label::Remote).unwrap();
                output.labels.insert(Label::DecodedRemote, route);
            }
            return output.propagate(format!("decode: {path}:{line} {name}"));
        }
        if matches!(
            normalized,
            "JSON.parse" | "JSON.stringify" | "String" | "Buffer.toString"
        ) || normalized.ends_with(".toString")
            || normalized.ends_with(".json")
            || normalized.ends_with(".text")
        {
            return args
                .first()
                .cloned()
                .unwrap_or_default()
                .propagate(format!("transform: {path}:{line} {name}"));
        }
        if matches!(normalized, "fs.writeFile" | "fs.writeFileSync")
            && let (Some(target), Some(contents)) = (
                args.first().and_then(|value| value.literal.clone()),
                args.get(1),
            )
            && contents
                .label(&[Label::Remote, Label::DecodedRemote])
                .is_some()
        {
            self.written.insert(
                target,
                contents
                    .clone()
                    .propagate(format!("write: {path}:{line} {name}")),
            );
        }
        if matches!(
            normalized,
            "eval"
                | "Function"
                | "global.eval"
                | "global.Function"
                | "globalThis.Function"
                | "vm.runInThisContext"
                | "vm.runInNewContext"
                | "vm.runInContext"
                | "vm.Script"
                | "process.dlopen"
                | "import"
        ) && let Some(route) = args
            .iter()
            .find_map(|arg| arg.label(&[Label::DecodedRemote, Label::Remote]))
        {
            self.emit(ChainRule::RemoteCode, path, line, name, route);
        }
        if matches!(
            normalized,
            "child_process.exec"
                | "child_process.execSync"
                | "child_process.spawn"
                | "child_process.spawnSync"
                | "child_process.fork"
                | "Bun.spawn"
                | "Deno.Command"
        ) {
            if let Some(route) = args
                .iter()
                .find_map(|arg| arg.label(&[Label::DecodedRemote, Label::Remote]))
            {
                self.emit(ChainRule::RemoteProcess, path, line, name, route);
            }
            if let Some(target) = args.first().and_then(|arg| arg.literal.as_deref())
                && let Some(written) = self.written.get(target)
                && let Some(route) = written
                    .label(&[Label::DecodedRemote, Label::Remote])
                    .cloned()
            {
                self.emit(ChainRule::DownloadExecute, path, line, name, &route);
            }
        }
        if normalized == "require" {
            return args
                .first()
                .and_then(|arg| arg.literal.clone())
                .map(Value::named)
                .unwrap_or_default();
        }
        Value::default()
    }

    fn call_function(
        &mut self,
        path: &str,
        function: &Function,
        args: Vec<Value>,
        mut scope: BTreeMap<String, Value>,
        depth: usize,
    ) -> Value {
        for (index, parameter) in function.params.iter().enumerate() {
            self.bind(
                parameter,
                args.get(index).cloned().unwrap_or_default(),
                &mut scope,
            );
        }
        self.run(path, &function.body, &mut scope, depth)
            .unwrap_or_default()
            .propagate(format!("return: {path}"))
    }

    fn exfiltration(&mut self, path: &str, line: u64, sink: &str, args: &[Value]) {
        if let Some(route) = args
            .iter()
            .find_map(|arg| arg.label(&[Label::EnvSecret, Label::FileSecret, Label::Clipboard]))
        {
            self.emit(ChainRule::SecretExfiltration, path, line, sink, route);
        }
    }

    fn emit(&mut self, rule: ChainRule, path: &str, line: u64, sink: &str, route: &[String]) {
        let (id, title, score) = rule.details();
        if !self.seen.insert((id.to_owned(), path.to_owned(), line)) {
            return;
        }
        let mut evidence = self
            .reachable
            .get(path)
            .cloned()
            .unwrap_or_else(|| vec!["trigger: unresolved".to_owned()]);
        evidence.extend(route.iter().cloned());
        evidence.push(format!("sink: {path}:{line} {sink}"));
        self.findings.push(Finding {
            id: id.to_owned(), severity: Severity::Critical,
            confidence: if self.reachable.contains_key(path) { Confidence::VeryHigh } else { Confidence::High },
            score, title: title.to_owned(),
            message: "A source-to-sink path connects attacker-controlled or sensitive data to a high-impact capability.".to_owned(),
            file: Some(path.to_owned()), line: Some(line), evidence,
        });
    }
}

fn sensitive_path(path: &str) -> bool {
    [
        ".ssh",
        ".aws",
        ".azure",
        "gcloud",
        ".npmrc",
        ".gitconfig",
        ".kube",
        ".docker",
        "wallet",
        "password",
    ]
    .iter()
    .any(|marker| path.to_ascii_lowercase().contains(marker))
}
