use super::{ModuleFacts, semantic::capability, semantic::static_string};
use crate::model::{Confidence, Finding, Severity};
use crate::scanner::graph::resolve_import;
use oxc_ast::ast::{
    Argument, AssignmentOperator, AssignmentTarget, BindingPattern, Declaration,
    ExportDefaultDeclarationKind, Expression, ForStatementInit, ForStatementLeft,
    ImportDeclarationSpecifier, MethodDefinitionKind, MethodDefinitionType, ModuleExportName,
    ObjectPropertyKind, Program, PropertyKey, Statement, VariableDeclaration,
};
use std::collections::BTreeMap;

fn indirect_api_target(name: &str) -> Option<String> {
    let target = name
        .strip_suffix(".call")
        .or_else(|| name.strip_suffix(".apply"))?;
    let target = if let Some(import) = target.strip_prefix("import:") {
        let (specifier, exported) = import.rsplit_once('#')?;
        let exported = exported
            .strip_prefix("*.")
            .or_else(|| exported.strip_prefix("default."))
            .unwrap_or(exported);
        if matches!(exported, "*" | "default") {
            specifier.to_owned()
        } else {
            format!("{specifier}.{exported}")
        }
    } else {
        target.to_owned()
    };
    capability(&target).map(|_| target)
}

#[derive(Clone, Debug)]
pub struct ModuleFlow {
    pub imports: BTreeMap<String, (String, String)>,
    pub exports: BTreeMap<String, String>,
    pub reexports: BTreeMap<String, (String, String)>,
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
    Branch(Expr, Vec<Stmt>, Vec<Stmt>),
    Iterate(Binding, Expr, Vec<Stmt>),
}

#[derive(Clone, Debug)]
pub enum Expr {
    Name(String),
    String(String),
    Bool(bool),
    Member(Box<Expr>, String),
    Call(Box<Expr>, Vec<Expr>, u64),
    Construct(Box<Expr>, Vec<Expr>, u64),
    Then(Box<Expr>, Binding, Vec<Stmt>),
    Message(Box<Expr>, Binding, Vec<Stmt>, String),
    Object(Vec<(String, Expr)>),
    Array(Vec<Expr>),
    Combine(Vec<Expr>),
    Sequence(Vec<Expr>),
    Assign(String, Box<Expr>),
    Unknown,
}

struct Lower<'a> {
    source: &'a str,
    line_offset: u64,
}

impl Lower<'_> {
    fn line(&self, offset: u32) -> u64 {
        self.line_offset
            + self
                .source
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
            BindingPattern::ObjectPattern(object) => {
                let mut properties = object
                    .properties
                    .iter()
                    .filter_map(|property| {
                        Some((self.key(&property.key)?, self.binding(&property.value)))
                    })
                    .collect::<Vec<_>>();
                if let Some(rest) = &object.rest {
                    properties.push(("*".to_owned(), self.binding(&rest.argument)));
                }
                Binding::Object(properties)
            }
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
            Expression::BooleanLiteral(value) => Expr::Bool(value.value),
            Expression::TemplateLiteral(value) => {
                let mut parts = Vec::new();
                for (index, quasi) in value.quasis.iter().enumerate() {
                    parts.push(Expr::String(
                        quasi
                            .value
                            .cooked
                            .as_ref()
                            .unwrap_or(&quasi.value.raw)
                            .to_string(),
                    ));
                    if let Some(expression) = value.expressions.get(index) {
                        parts.push(self.expr(expression));
                    }
                }
                Expr::Combine(parts)
            }
            Expression::StaticMemberExpression(member) => Expr::Member(
                Box::new(self.expr(&member.object)),
                member.property.name.to_string(),
            ),
            Expression::ComputedMemberExpression(member) => Expr::Member(
                Box::new(self.expr(&member.object)),
                static_string(&member.expression).unwrap_or_else(|| "*".to_owned()),
            ),
            Expression::CallExpression(call) => {
                if let Expression::StaticMemberExpression(member) = &call.callee
                    && member.property.name == "then"
                    && let Some((parameter, body)) = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(|callback| self.callback_expression(callback))
                {
                    return Expr::Then(Box::new(self.expr(&member.object)), parameter, body);
                }
                if let Expression::StaticMemberExpression(member) = &call.callee
                    && matches!(member.property.name.as_str(), "on" | "addEventListener")
                    && matches!(
                        call.arguments.first().and_then(argument_text),
                        Some("message" | "data" | "end" | "response")
                    )
                    && let Some((parameter, body)) = call
                        .arguments
                        .get(1)
                        .and_then(Argument::as_expression)
                        .and_then(|callback| self.callback_expression(callback))
                {
                    return Expr::Message(
                        Box::new(self.expr(&member.object)),
                        parameter,
                        body,
                        call.arguments
                            .first()
                            .and_then(argument_text)
                            .unwrap_or_default()
                            .to_owned(),
                    );
                }
                if let Expression::StaticMemberExpression(member) = &call.callee
                    && matches!(member.property.name.as_str(), "get" | "request")
                    && let Some((parameter, body)) = call
                        .arguments
                        .last()
                        .and_then(Argument::as_expression)
                        .and_then(|callback| self.callback_expression(callback))
                {
                    let request = Expr::Call(
                        Box::new(self.expr(&call.callee)),
                        call.arguments
                            .iter()
                            .map(|argument| self.argument(argument))
                            .collect(),
                        self.line(call.span.start),
                    );
                    return Expr::Then(Box::new(request), parameter, body);
                }
                if let Some((parameter, body)) = call
                    .arguments
                    .last()
                    .and_then(Argument::as_expression)
                    .and_then(|callback| self.callback_expression(callback))
                {
                    let request = Expr::Call(
                        Box::new(self.expr(&call.callee)),
                        call.arguments
                            .iter()
                            .map(|argument| self.argument(argument))
                            .collect(),
                        self.line(call.span.start),
                    );
                    return Expr::Then(Box::new(request), parameter, body);
                }
                Expr::Call(
                    Box::new(self.expr(&call.callee)),
                    call.arguments
                        .iter()
                        .map(|argument| self.argument(argument))
                        .collect(),
                    self.line(call.span.start),
                )
            }
            Expression::NewExpression(call) => Expr::Construct(
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
            Expression::ChainExpression(chain) => match &chain.expression {
                oxc_ast::ast::ChainElement::CallExpression(call) => Expr::Call(
                    Box::new(self.expr(&call.callee)),
                    call.arguments
                        .iter()
                        .map(|argument| self.argument(argument))
                        .collect(),
                    self.line(call.span.start),
                ),
                oxc_ast::ast::ChainElement::StaticMemberExpression(member) => Expr::Member(
                    Box::new(self.expr(&member.object)),
                    member.property.name.to_string(),
                ),
                oxc_ast::ast::ChainElement::ComputedMemberExpression(member) => Expr::Member(
                    Box::new(self.expr(&member.object)),
                    static_string(&member.expression).unwrap_or_else(|| "*".to_owned()),
                ),
                oxc_ast::ast::ChainElement::TSNonNullExpression(expression) => {
                    self.expr(&expression.expression)
                }
                _ => Expr::Unknown,
            },
            Expression::AwaitExpression(awaited) => self.expr(&awaited.argument),
            Expression::ParenthesizedExpression(paren) => self.expr(&paren.expression),
            Expression::UnaryExpression(unary) => Expr::Combine(vec![self.expr(&unary.argument)]),
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
                        ObjectPropertyKind::SpreadProperty(property) => {
                            Some(("*".to_owned(), self.expr(&property.argument)))
                        }
                    })
                    .collect(),
            ),
            Expression::ArrayExpression(array) => Expr::Array(
                array
                    .elements
                    .iter()
                    .map(|element| {
                        element
                            .as_expression()
                            .map(|item| self.expr(item))
                            .unwrap_or(Expr::Unknown)
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
            Expression::SequenceExpression(sequence) => Expr::Sequence(
                sequence
                    .expressions
                    .iter()
                    .map(|item| self.expr(item))
                    .collect(),
            ),
            Expression::AssignmentExpression(assignment) => {
                match assignment.left.get_identifier_name() {
                    Some(name) => {
                        let right = self.expr(&assignment.right);
                        let value = if assignment.operator == AssignmentOperator::Assign {
                            right
                        } else {
                            Expr::Combine(vec![Expr::Name(name.to_owned()), right])
                        };
                        Expr::Assign(name.to_owned(), Box::new(value))
                    }
                    None => self.expr(&assignment.right),
                }
            }
            _ => Expr::Unknown,
        }
    }

    fn argument(&self, argument: &Argument<'_>) -> Expr {
        match argument {
            Argument::SpreadElement(spread) => self.expr(&spread.argument),
            _ => argument
                .as_expression()
                .map(|expression| self.expr(expression))
                .unwrap_or(Expr::Unknown),
        }
    }

    fn callback_expression(&self, expression: &Expression<'_>) -> Option<(Binding, Vec<Stmt>)> {
        let function = self.function_expression(expression, &mut BTreeMap::new())?;
        let index = usize::from(
            function.params.len() > 1
                && matches!(
                    function.params.first(),
                    Some(Binding::Name(name)) if matches!(name.as_str(), "err" | "error")
                ),
        );
        let parameter = function
            .params
            .into_iter()
            .nth(index)
            .unwrap_or(Binding::Ignore);
        Some((parameter, function.body))
    }

    fn function_expression(
        &self,
        expression: &Expression<'_>,
        functions: &mut BTreeMap<String, Function>,
    ) -> Option<Function> {
        let (params, body) = match expression {
            Expression::ArrowFunctionExpression(arrow) => {
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
                (params, body)
            }
            Expression::FunctionExpression(function) => {
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
                (params, body)
            }
            _ => return None,
        };
        Some(Function { params, body })
    }

    fn class_functions(
        &self,
        class: &oxc_ast::ast::Class<'_>,
        functions: &mut BTreeMap<String, Function>,
    ) {
        let Some(class_name) = class.id.as_ref().map(|id| id.name.to_string()) else {
            return;
        };
        for element in &class.body.body {
            let oxc_ast::ast::ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if method.r#type != MethodDefinitionType::MethodDefinition {
                continue;
            }
            let Some(method_name) = self.key(&method.key) else {
                continue;
            };
            let name = if method.kind == MethodDefinitionKind::Constructor {
                class_name.clone()
            } else {
                format!("{class_name}.{method_name}")
            };
            let params = method
                .value
                .params
                .items
                .iter()
                .map(|item| self.binding(&item.pattern))
                .collect();
            let body = method
                .value
                .body
                .as_ref()
                .map(|body| self.statements(&body.statements, functions))
                .unwrap_or_default();
            functions.insert(name, Function { params, body });
        }
    }

    fn object_functions(
        &self,
        name: &str,
        object: &oxc_ast::ast::ObjectExpression<'_>,
        functions: &mut BTreeMap<String, Function>,
    ) {
        for property in &object.properties {
            let ObjectPropertyKind::ObjectProperty(property) = property else {
                continue;
            };
            let Some(method) = self.key(&property.key) else {
                continue;
            };
            if let Some(function) = self.function_expression(&property.value, functions) {
                functions.insert(format!("{name}.{method}"), function);
            }
        }
    }

    fn export_assignment(
        &self,
        left: &AssignmentTarget<'_>,
        right: &Expression<'_>,
        exports: &mut BTreeMap<String, String>,
        functions: &mut BTreeMap<String, Function>,
    ) {
        let AssignmentTarget::StaticMemberExpression(target) = left else {
            return;
        };
        let exported = if matches!(&target.object, Expression::Identifier(id) if id.name == "exports")
        {
            Some(target.property.name.to_string())
        } else if let Expression::StaticMemberExpression(module_exports) = &target.object
            && matches!(&module_exports.object, Expression::Identifier(id) if id.name == "module")
            && module_exports.property.name == "exports"
        {
            Some(target.property.name.to_string())
        } else if matches!(&target.object, Expression::Identifier(id) if id.name == "module")
            && target.property.name == "exports"
        {
            Some("default".to_owned())
        } else {
            None
        };
        let Some(exported) = exported else {
            return;
        };
        if exported == "default"
            && let Expression::ObjectExpression(object) = right
        {
            for property in &object.properties {
                if let ObjectPropertyKind::ObjectProperty(property) = property
                    && let Some(name) = self.key(&property.key)
                {
                    self.export_value(&name, &property.value, exports, functions);
                }
            }
        } else {
            self.export_value(&exported, right, exports, functions);
        }
    }

    fn export_value(
        &self,
        exported: &str,
        value: &Expression<'_>,
        exports: &mut BTreeMap<String, String>,
        functions: &mut BTreeMap<String, Function>,
    ) {
        if let Expression::Identifier(local) = value {
            exports.insert(exported.to_owned(), local.name.to_string());
        }
        if let Some(function) = self.function_expression(value, functions) {
            exports.insert(exported.to_owned(), exported.to_owned());
            functions.insert(exported.to_owned(), function);
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
            Declaration::VariableDeclaration(variable) => self.variables(variable, functions),
            Declaration::ClassDeclaration(class) => {
                self.class_functions(class, functions);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn variables(
        &self,
        variable: &VariableDeclaration<'_>,
        functions: &mut BTreeMap<String, Function>,
    ) -> Vec<Stmt> {
        variable
            .declarations
            .iter()
            .map(|item| {
                let binding = self.binding(&item.id);
                if let (Binding::Name(name), Some(initializer)) = (&binding, &item.init)
                    && let Some(function) = self.function_expression(initializer, functions)
                {
                    functions.insert(name.clone(), function);
                }
                if let (Binding::Name(name), Some(Expression::ObjectExpression(object))) =
                    (&binding, &item.init)
                {
                    self.object_functions(name, object, functions);
                }
                Stmt::Bind(
                    binding,
                    item.init
                        .as_ref()
                        .map(|expr| self.expr(expr))
                        .unwrap_or(Expr::Unknown),
                )
            })
            .collect()
    }

    fn loop_binding(&self, left: &ForStatementLeft<'_>) -> Binding {
        match left {
            ForStatementLeft::VariableDeclaration(variable) => variable
                .declarations
                .first()
                .map(|declaration| self.binding(&declaration.id))
                .unwrap_or(Binding::Ignore),
            _ => left
                .as_assignment_target()
                .and_then(AssignmentTarget::get_identifier_name)
                .map(|name| Binding::Name(name.to_owned()))
                .unwrap_or(Binding::Ignore),
        }
    }

    fn statement(
        &self,
        statement: &Statement<'_>,
        functions: &mut BTreeMap<String, Function>,
    ) -> Vec<Stmt> {
        match statement {
            Statement::FunctionDeclaration(_)
            | Statement::VariableDeclaration(_)
            | Statement::ClassDeclaration(_) => statement
                .as_declaration()
                .map(|declaration| self.declaration(declaration, functions))
                .unwrap_or_default(),
            Statement::ExportDeclaration(export) => {
                self.declaration(&export.declaration, functions)
            }
            Statement::ExportDefaultDeclaration(export) => {
                match &export.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
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
                        functions.insert("default".to_owned(), Function { params, body });
                    }
                    ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => {
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
                        functions.insert("default".to_owned(), Function { params, body });
                    }
                    ExportDefaultDeclarationKind::FunctionExpression(function) => {
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
                        functions.insert("default".to_owned(), Function { params, body });
                    }
                    _ => {}
                }
                export
                    .declaration
                    .as_expression()
                    .map(|expression| vec![Stmt::Expr(self.expr(expression))])
                    .unwrap_or_default()
            }
            Statement::ExpressionStatement(expression) => {
                vec![Stmt::Expr(self.expr(&expression.expression))]
            }
            Statement::ReturnStatement(ret) => ret
                .argument
                .as_ref()
                .map(|expression| vec![Stmt::Return(self.expr(expression))])
                .unwrap_or_default(),
            Statement::ThrowStatement(throw) => vec![Stmt::Expr(self.expr(&throw.argument))],
            Statement::LabeledStatement(labeled) => self.statement(&labeled.body, functions),
            Statement::BlockStatement(block) => self.statements(&block.body, functions),
            Statement::IfStatement(branch) => vec![Stmt::Branch(
                self.expr(&branch.test),
                self.statement(&branch.consequent, functions),
                branch
                    .alternate
                    .as_ref()
                    .map(|alternate| self.statement(alternate, functions))
                    .unwrap_or_default(),
            )],
            // ponytail: One pass catches direct loop sinks; loop-carried fixpoints remain the known ceiling.
            Statement::WhileStatement(loop_) => vec![Stmt::Branch(
                self.expr(&loop_.test),
                self.statement(&loop_.body, functions),
                Vec::new(),
            )],
            Statement::DoWhileStatement(loop_) => self.statement(&loop_.body, functions),
            Statement::ForStatement(loop_) => {
                let mut statements = loop_
                    .init
                    .as_ref()
                    .map(|init| match init {
                        ForStatementInit::VariableDeclaration(variable) => {
                            self.variables(variable, functions)
                        }
                        _ => init
                            .as_expression()
                            .map(|expression| vec![Stmt::Expr(self.expr(expression))])
                            .unwrap_or_default(),
                    })
                    .unwrap_or_default();
                let mut body = self.statement(&loop_.body, functions);
                if let Some(update) = &loop_.update {
                    body.push(Stmt::Expr(self.expr(update)));
                }
                statements.push(Stmt::Branch(
                    loop_
                        .test
                        .as_ref()
                        .map(|test| self.expr(test))
                        .unwrap_or(Expr::Bool(true)),
                    body,
                    Vec::new(),
                ));
                statements
            }
            Statement::ForInStatement(loop_) => vec![Stmt::Iterate(
                self.loop_binding(&loop_.left),
                self.expr(&loop_.right),
                self.statement(&loop_.body, functions),
            )],
            Statement::ForOfStatement(loop_) => vec![Stmt::Iterate(
                self.loop_binding(&loop_.left),
                self.expr(&loop_.right),
                self.statement(&loop_.body, functions),
            )],
            Statement::SwitchStatement(switch_) => {
                let mut cases = switch_
                    .cases
                    .iter()
                    .map(|case| self.statements(&case.consequent, functions));
                let Some(mut combined) = cases.next() else {
                    return Vec::new();
                };
                for case in cases {
                    combined = vec![Stmt::Branch(Expr::Unknown, combined, case)];
                }
                vec![Stmt::Branch(
                    Expr::Unknown,
                    combined,
                    vec![Stmt::Expr(self.expr(&switch_.discriminant))],
                )]
            }
            Statement::TryStatement(try_) => {
                let mut body = vec![Stmt::Branch(
                    Expr::Unknown,
                    self.statements(&try_.block.body, functions),
                    try_.handler
                        .as_ref()
                        .map(|handler| self.statements(&handler.body.body, functions))
                        .unwrap_or_default(),
                )];
                if let Some(finalizer) = &try_.finalizer {
                    body.extend(self.statements(&finalizer.body, functions));
                }
                body
            }
            _ => Vec::new(),
        }
    }
}

fn argument_text<'a>(argument: &'a Argument<'_>) -> Option<&'a str> {
    match argument {
        Argument::StringLiteral(value) => Some(value.value.as_str()),
        _ => None,
    }
}

fn non_secret_environment_key(key: &str) -> bool {
    matches!(key, "NODE_ENV" | "CI" | "DEBUG" | "TERM")
}

pub fn lower(program: &Program<'_>, source: &str, line_offset: u64) -> ModuleFlow {
    let lower = Lower {
        source,
        line_offset,
    };
    let mut imports = BTreeMap::new();
    let mut exports = BTreeMap::new();
    let mut reexports = BTreeMap::new();
    let mut functions = BTreeMap::new();
    for statement in &program.body {
        if let Statement::ExportDeclaration(export) = statement {
            match &export.declaration {
                Declaration::FunctionDeclaration(function) => {
                    if let Some(id) = &function.id {
                        exports.insert(id.name.to_string(), id.name.to_string());
                    }
                }
                Declaration::VariableDeclaration(variable) => {
                    for item in &variable.declarations {
                        if let BindingPattern::BindingIdentifier(binding) = &item.id {
                            exports.insert(binding.name.to_string(), binding.name.to_string());
                        }
                    }
                }
                Declaration::ClassDeclaration(class) => {
                    if let Some(id) = &class.id {
                        exports.insert(id.name.to_string(), id.name.to_string());
                        lower.class_functions(class, &mut functions);
                    }
                }
                _ => {}
            }
        } else if let Statement::ExportNamedDeclaration(export) = statement {
            for specifier in &export.specifiers {
                if let (Some(local), Some(exported)) = (
                    module_export_name(&specifier.local),
                    module_export_name(&specifier.exported),
                ) {
                    exports.insert(exported.to_owned(), local.to_owned());
                }
            }
        } else if let Statement::ExportDefaultDeclaration(export) = statement {
            if let ExportDefaultDeclarationKind::ClassDeclaration(class) = &export.declaration {
                lower.class_functions(class, &mut functions);
                exports.insert(
                    "default".to_owned(),
                    class
                        .id
                        .as_ref()
                        .map_or_else(|| "default".to_owned(), |id| id.name.to_string()),
                );
            } else {
                exports.insert("default".to_owned(), "default".to_owned());
            }
        } else if let Statement::ExportFromDeclaration(export) = statement {
            for specifier in &export.specifiers {
                if let (Some(local), Some(exported)) = (
                    module_export_name(&specifier.local),
                    module_export_name(&specifier.exported),
                ) {
                    reexports.insert(
                        exported.to_owned(),
                        (export.source.value.to_string(), local.to_owned()),
                    );
                }
            }
        } else if let Statement::ExportAllDeclaration(export) = statement {
            reexports.insert(
                "*".to_owned(),
                (export.source.value.to_string(), "*".to_owned()),
            );
        } else if let Statement::ExpressionStatement(statement) = statement
            && let Expression::AssignmentExpression(assignment) = &statement.expression
        {
            lower.export_assignment(
                &assignment.left,
                &assignment.right,
                &mut exports,
                &mut functions,
            );
        }
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
    let body = lower.statements(&program.body, &mut functions);
    ModuleFlow {
        imports,
        exports,
        reexports,
        functions,
        body,
    }
}

fn module_export_name<'a>(name: &'a ModuleExportName<'_>) -> Option<&'a str> {
    match name {
        ModuleExportName::IdentifierName(value) => Some(value.name.as_str()),
        ModuleExportName::IdentifierReference(value) => Some(value.name.as_str()),
        ModuleExportName::StringLiteral(value) => Some(value.value.as_str()),
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
    fn details(self) -> (&'static str, &'static str, &'static str, u8) {
        match self {
            Self::RemoteCode => (
                "JS-REMOTE-CODE-EXECUTION",
                "Remote data reaches dynamic execution",
                "Remote input can become JavaScript executed by this program.",
                98,
            ),
            Self::RemoteProcess => (
                "JS-REMOTE-PROCESS-EXECUTION",
                "Remote data reaches process execution",
                "Remote input can influence a process or shell command.",
                97,
            ),
            Self::DownloadExecute => (
                "JS-DOWNLOAD-WRITE-EXECUTE",
                "Downloaded bytes are written and executed",
                "Remote content can be saved and launched as a local program.",
                98,
            ),
            Self::SecretExfiltration => (
                "JS-SECRET-EXFILTRATION",
                "Sensitive data reaches an outbound request",
                "Sensitive local data can leave through a network request.",
                97,
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Value {
    name: Option<String>,
    literal: Option<String>,
    path_hint: Option<String>,
    path_key: Option<String>,
    stream_reader: bool,
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
        if self.path_hint.is_none() {
            self.path_hint = other.path_hint;
        }
        if self.path_key.is_none() {
            self.path_key = other.path_key;
        }
        self.stream_reader |= other.stream_reader;
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

    fn file_target(&self) -> Option<String> {
        self.literal.clone().or_else(|| self.path_key.clone())
    }
}

pub struct FlowResult {
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
}

struct Evaluator<'a> {
    modules: BTreeMap<&'a str, &'a ModuleFacts>,
    by_path: BTreeMap<&'a str, &'a ModuleFacts>,
    reachable: &'a BTreeMap<String, Vec<String>>,
    findings: Vec<Finding>,
    seen: std::collections::BTreeSet<(String, String, u64)>,
    steps: usize,
    limited: bool,
    written: BTreeMap<String, Value>,
    stream_data: BTreeMap<(String, String), BTreeMap<String, Value>>,
}

const MAX_FLOW_STEPS: usize = 100_000;
const MAX_CALL_DEPTH: usize = 32;

pub fn analyze_flows(
    modules: &[ModuleFacts],
    reachable: &BTreeMap<String, Vec<String>>,
) -> FlowResult {
    let mut by_path = BTreeMap::new();
    for module in modules {
        by_path.entry(module.path.as_str()).or_insert(module);
    }
    let mut evaluator = Evaluator {
        modules: modules
            .iter()
            .map(|module| (module.id.as_str(), module))
            .collect(),
        by_path,
        reachable,
        findings: Vec::new(),
        seen: std::collections::BTreeSet::new(),
        steps: 0,
        limited: false,
        written: BTreeMap::new(),
        stream_data: BTreeMap::new(),
    };
    for module in modules {
        if evaluator.limited {
            break;
        }
        if !module.flow_enabled
            || (!reachable.is_empty() && !reachable.contains_key(module.id.as_str()))
        {
            continue;
        }
        evaluator.written.clear();
        let mut environment = evaluator.imports(module);
        evaluator.run(&module.id, &module.flow.body, &mut environment, 0);
    }
    let remote = evaluator
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.id.as_str(),
                "JS-REMOTE-CODE-EXECUTION" | "JS-REMOTE-PROCESS-EXECUTION"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let secrets = evaluator
        .findings
        .iter()
        .filter(|finding| finding.id == "JS-SECRET-EXFILTRATION")
        .cloned()
        .collect::<Vec<_>>();
    for execution in remote {
        let trigger = execution
            .evidence
            .iter()
            .find(|item| item.starts_with("trigger:") && *item != "trigger: unresolved");
        let same_route = secrets.iter().find(|secret| {
            trigger.is_some_and(|trigger| secret.evidence.iter().any(|item| item == trigger))
        });
        if let Some(secret) = same_route {
            evaluator.findings.push(Finding {
                id: "JS-COMBINED-ATTACK-CHAIN".to_owned(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                score: 99,
                title: "One execution route can exfiltrate secrets and execute remote input".to_owned(),
                message: "Separate source-to-sink findings share a file or evidenced execution trigger. This correlation does not establish a malware family.".to_owned(),
                file: execution.file.clone(),
                line: execution.line,
                evidence: vec![format!("component: {} at {}:{}", execution.id, execution.file.as_deref().unwrap_or("unknown"), execution.line.unwrap_or(0)), format!("component: {} at {}:{}", secret.id, secret.file.as_deref().unwrap_or("unknown"), secret.line.unwrap_or(0))],
            });
        }
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
    fn file_path<'a>(&'a self, id: &'a str) -> &'a str {
        self.modules
            .get(id)
            .map_or(id, |module| module.path.as_str())
    }

    fn route(&self, id: &str) -> Vec<String> {
        self.reachable
            .get(id)
            .cloned()
            .unwrap_or_else(|| vec!["trigger: unresolved".to_owned()])
    }

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
                Stmt::Branch(condition, yes, no) => {
                    if let Expr::Bool(value) = condition {
                        let branch = if *value { yes } else { no };
                        if let Some(value) = self.run(path, branch, environment, depth + 1) {
                            return Some(value);
                        }
                        continue;
                    }
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
                Stmt::Iterate(binding, iterable, body) => {
                    let mut iteration = environment.clone();
                    let value = self.eval(path, iterable, environment, depth);
                    self.bind(binding, value, &mut iteration);
                    if let Some(value) = self.run(path, body, &mut iteration, depth + 1) {
                        pending_return
                            .get_or_insert_with(Value::default)
                            .merge(value);
                    }
                    for (name, value) in iteration {
                        environment.entry(name).or_default().merge(value);
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
                    let selected = if property == "*" {
                        value.clone()
                    } else if value.name.as_deref() == Some("process.env")
                        && non_secret_environment_key(property)
                    {
                        Value::named(format!("process.env.{property}"))
                    } else {
                        value.fields.get(property).cloned().unwrap_or_else(|| {
                            let mut selected = value.clone();
                            selected.name =
                                value.name.as_ref().map(|name| format!("{name}.{property}"));
                            selected
                        })
                    };
                    self.bind(nested, selected, environment);
                }
            }
            Binding::Array(items) => {
                for (index, nested) in items.iter().enumerate() {
                    let selected = value
                        .fields
                        .get(&index.to_string())
                        .cloned()
                        .unwrap_or_else(|| value.clone());
                    self.bind(nested, selected, environment);
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
        let file_path = self.file_path(path).to_owned();
        match expression {
            Expr::Name(name) => environment
                .get(name)
                .cloned()
                .unwrap_or_else(|| Value::named(name.clone())),
            Expr::String(text) => Value::literal(text.clone()),
            Expr::Bool(_) => Value::default(),
            Expr::Member(object, property) => {
                let base = self.eval(path, object, environment, depth);
                let receiver = base
                    .name
                    .as_ref()
                    .cloned()
                    .or_else(|| match object.as_ref() {
                        Expr::Name(name) => Some(name.clone()),
                        _ => None,
                    });
                let full_name = receiver
                    .map(|name| format!("{name}.{property}"))
                    .or_else(|| (!base.labels.is_empty()).then(|| format!("remote.{property}")));
                if full_name.as_deref() == Some("process.env") {
                    let mut value = Value::labeled(
                        Label::EnvSecret,
                        format!("source: {file_path} process.env"),
                    );
                    value.name = full_name;
                    return value;
                }
                if base.name.as_deref() == Some("process.env")
                    && non_secret_environment_key(property)
                {
                    return Value::named(format!("process.env.{property}"));
                }
                let mut value = base.fields.get(property).cloned().unwrap_or(base);
                if !value.labels.is_empty() {
                    value = value.propagate(format!(
                        "property: {file_path} {}",
                        full_name.as_deref().unwrap_or(property)
                    ));
                }
                value.name = full_name;
                value
            }
            Expr::Object(properties) => {
                let mut object = Value::default();
                for (name, expression) in properties {
                    let field = self.eval(path, expression, environment, depth);
                    if name == "*" {
                        for (property, spread_value) in &field.fields {
                            object.fields.insert(property.clone(), spread_value.clone());
                        }
                    } else {
                        object.fields.insert(name.clone(), field.clone());
                    }
                    object.merge(field);
                }
                object
            }
            Expr::Array(items) => {
                let mut value = Value::default();
                for (index, expression) in items.iter().enumerate() {
                    let item = self.eval(path, expression, environment, depth);
                    value.merge(item.clone());
                    value.fields.insert(index.to_string(), item);
                }
                value.name = None;
                value.literal = None;
                value.path_hint = None;
                value.path_key = None;
                value
            }
            Expr::Combine(parts) => {
                let mut combined = Value::default();
                let mut literal = Some(String::new());
                let mut path_hint = String::new();
                for part in parts {
                    let part = self.eval(path, part, environment, depth);
                    if let (Some(buffer), Some(text)) = (&mut literal, &part.literal) {
                        buffer.push_str(text);
                    } else {
                        literal = None;
                    }
                    if let Some(text) = part.literal.as_ref().or(part.path_hint.as_ref()) {
                        path_hint.push_str(text);
                    }
                    combined.merge(part);
                }
                combined.literal = literal;
                if combined.literal.is_none() && !path_hint.is_empty() {
                    combined.path_hint = Some(path_hint);
                }
                combined
            }
            Expr::Sequence(parts) => {
                let mut value = Value::default();
                for part in parts {
                    value = self.eval(path, part, environment, depth);
                }
                value
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
                let indirect_api = function
                    .name
                    .as_deref()
                    .and_then(indirect_api_target)
                    .is_some();
                if !indirect_api
                    && matches!(callee.as_ref(), Expr::Member(_, _))
                    && !function.labels.is_empty()
                {
                    args.insert(0, function.clone());
                }
                if indirect_api && !args.is_empty() {
                    args.remove(0);
                }
                if function.name.as_deref() == Some("Object.assign")
                    && let Some(Expr::Name(target_name)) = arguments.first()
                {
                    let mut target = environment
                        .get(target_name)
                        .cloned()
                        .or_else(|| args.first().cloned())
                        .unwrap_or_default();
                    for source in args.iter().skip(1) {
                        target.merge(source.clone());
                    }
                    target.literal = None;
                    target.path_hint = None;
                    target.path_key = None;
                    target =
                        target.propagate(format!("transform: {file_path}:{line} Object.assign"));
                    environment.insert(target_name.clone(), target.clone());
                    return target;
                }
                if let Expr::Member(object, method) = callee.as_ref()
                    && matches!(method.as_str(), "push" | "unshift")
                    && let Expr::Name(name) = object.as_ref()
                {
                    let mut array = environment.get(name).cloned().unwrap_or_default();
                    let inserted_receiver = usize::from(!function.labels.is_empty());
                    let values = args.into_iter().skip(inserted_receiver).collect::<Vec<_>>();
                    if method == "unshift" {
                        let offset = values.len();
                        array.fields = std::mem::take(&mut array.fields)
                            .into_iter()
                            .map(|(key, value)| {
                                let key = key
                                    .parse::<usize>()
                                    .map_or(key.clone(), |index| (index + offset).to_string());
                                (key, value)
                            })
                            .collect();
                    }
                    let start = if method == "push" {
                        array
                            .fields
                            .keys()
                            .filter_map(|key| key.parse::<usize>().ok())
                            .max()
                            .map_or(0, |index| index + 1)
                    } else {
                        0
                    };
                    for (offset, value) in values.into_iter().enumerate() {
                        array.merge(value.clone());
                        let index = if method == "push" {
                            start + offset
                        } else {
                            offset
                        };
                        array.fields.insert(index.to_string(), value);
                    }
                    array.name = None;
                    array.literal = None;
                    array.path_hint = None;
                    array.path_key = None;
                    array.stream_reader = false;
                    environment.insert(name.clone(), array);
                    return Value::default();
                }
                if let Expr::Member(object, method) = callee.as_ref()
                    && matches!(method.as_str(), "append" | "set" | "add")
                    && let Expr::Name(name) = object.as_ref()
                {
                    let mut value = environment.get(name).cloned().unwrap_or_default();
                    for argument in args {
                        value.merge(argument);
                    }
                    value.literal = None;
                    value.path_hint = None;
                    value.path_key = None;
                    value = value.propagate(format!(
                        "container update: {file_path}:{line} {}",
                        function.name.as_deref().unwrap_or(method)
                    ));
                    environment.insert(name.clone(), value);
                    return Value::default();
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
            Expr::Construct(callee, arguments, line) => {
                let constructor = self.eval(path, callee, environment, depth);
                let args = arguments
                    .iter()
                    .map(|arg| self.eval(path, arg, environment, depth))
                    .collect();
                let name = constructor.name.as_deref().unwrap_or("");
                let value = self.invoke(path, name, args, *line, environment, depth);
                if value.name.is_none() && value.labels.is_empty() && value.fields.is_empty() {
                    Value::named(name.to_owned())
                } else {
                    value
                }
            }
            Expr::Then(receiver, parameter, body) => {
                let value = self.eval(path, receiver, environment, depth);
                let mut scope = environment.clone();
                self.bind(parameter, value, &mut scope);
                self.run(path, body, &mut scope, depth + 1)
                    .unwrap_or_default()
            }
            Expr::Message(receiver, parameter, body, event) => {
                let value = self.eval(path, receiver, environment, depth);
                if !matches!(
                    value.name.as_deref(),
                    Some(
                        "WebSocket"
                            | "globalThis.WebSocket"
                            | "window.WebSocket"
                            | "EventSource"
                            | "globalThis.EventSource"
                            | "window.EventSource"
                            | "ws"
                            | "http.response"
                            | "network.socket"
                            | "socket.io"
                    )
                ) {
                    return Value::default();
                }
                let stream = matches!(
                    value.name.as_deref(),
                    Some("http.response" | "network.socket")
                );
                let stream_key = (
                    path.to_owned(),
                    match receiver.as_ref() {
                        Expr::Name(name) => name.clone(),
                        _ => value.name.clone().unwrap_or_default(),
                    },
                );
                let stream_data = stream && event == "data";
                let stream_end = stream && event == "end";
                let mut scope = environment.clone();
                if stream_end && let Some(previous_chunks) = self.stream_data.get(&stream_key) {
                    for (name, value) in previous_chunks {
                        if let Some(existing) = scope.get_mut(name) {
                            existing.merge(value.clone());
                        }
                    }
                }
                self.bind(parameter, value, &mut scope);
                let result = self.run(path, body, &mut scope, depth + 1);
                if stream_data {
                    // Stream data callbacks run before `end`; other async callback effects stay scoped.
                    let chunks = self.stream_data.entry(stream_key).or_default();
                    for (name, value) in scope {
                        if environment.contains_key(&name) {
                            chunks.entry(name).or_default().merge(value);
                        }
                    }
                }
                result.unwrap_or_default()
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
                return self.call_function(
                    path,
                    name,
                    &function,
                    args,
                    environment.clone(),
                    depth + 1,
                );
            }
            if let Some(import) = name.strip_prefix("import:")
                && let Some((specifier, exported)) = import.rsplit_once('#')
                && specifier.starts_with('.')
                && let Some(target_path) = resolve_import(&module.path, specifier, &self.by_path)
                && let Some(target_module) = self.by_path.get(target_path)
                && let Some((target, local, function)) = self.exported_function(
                    &target_module.id,
                    exported.strip_prefix("*.").unwrap_or(exported),
                )
            {
                let scope = self.imports(self.modules[target.as_str()]);
                return self.call_function(&target, &local, &function, args, scope, depth + 1);
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
        let indirect_name = indirect_api_target(name);
        let name = indirect_name.as_deref().unwrap_or(name);
        let normalized = name.strip_prefix("node:").unwrap_or(name);
        let file_path = self.file_path(path).to_owned();
        let source = format!("source: {file_path}:{line} {name}");
        if normalized == "Object.assign" {
            let mut value = Value::default();
            for argument in args {
                value.merge(argument);
            }
            return value.propagate(format!("transform: {file_path}:{line} {name}"));
        }
        if normalized == "Object.fromEntries" {
            return args
                .first()
                .cloned()
                .unwrap_or_default()
                .propagate(format!("transform: {file_path}:{line} {name}"));
        }
        if normalized == "Object.keys" {
            return Value::default();
        }
        if matches!(
            normalized,
            "Blob" | "FormData" | "Headers" | "URLSearchParams"
        ) {
            return args
                .first()
                .cloned()
                .unwrap_or_default()
                .propagate(format!("container: {file_path}:{line} {name}"));
        }
        if matches!(normalized, "Promise.all" | "Promise.race" | "Promise.any") {
            return args
                .first()
                .cloned()
                .unwrap_or_default()
                .propagate(format!("promise aggregation: {file_path}:{line} {name}"));
        }
        if normalized == "Object.entries" {
            let mut entries = Value::default();
            if let Some(value) = args.first() {
                entries.merge(value.clone());
                let mut key = Value::named("object key".to_owned());
                if value
                    .label(&[Label::Remote, Label::DecodedRemote])
                    .is_some()
                {
                    key.merge(value.clone());
                }
                entries.fields.insert("0".to_owned(), key);
                entries.fields.insert("1".to_owned(), value.clone());
            }
            return entries.propagate(format!("transform: {file_path}:{line} {name}"));
        }
        if matches!(
            normalized,
            "axios"
                | "axios.get"
                | "axios.post"
                | "axios.put"
                | "axios.patch"
                | "axios.delete"
                | "axios.head"
                | "axios.request"
                | "fetch"
                | "globalThis.fetch"
                | "window.fetch"
                | "got"
                | "got.get"
                | "got.post"
                | "request"
                | "request.get"
                | "request.post"
                | "undici.fetch"
                | "undici.request"
                | "node-fetch"
                | "http.get"
                | "https.get"
                | "http.request"
                | "https.request"
                | "WebSocket"
                | "globalThis.WebSocket"
                | "window.WebSocket"
                | "EventSource"
                | "globalThis.EventSource"
                | "window.EventSource"
                | "ws"
                | "socket.io"
                | "socket.io-client"
                | "socket.io-client.io"
                | "net.Socket"
                | "net.connect"
                | "tls.connect"
                | "dns.lookup"
                | "dns.resolve"
                | "dns.resolveTxt"
                | "dns.resolve4"
                | "dns.resolve6"
                | "dns.promises.lookup"
                | "dns.promises.resolve"
                | "dns.promises.resolveTxt"
                | "dns.promises.resolve4"
                | "dns.promises.resolve6"
                | "dgram.createSocket"
        ) {
            self.exfiltration(path, line, name, &args);
            let mut value = Value::labeled(Label::Remote, source);
            if matches!(
                normalized,
                "WebSocket" | "globalThis.WebSocket" | "window.WebSocket" | "ws"
            ) {
                value.name = Some("WebSocket".to_owned());
            } else if matches!(
                normalized,
                "EventSource" | "globalThis.EventSource" | "window.EventSource"
            ) {
                value.name = Some("EventSource".to_owned());
            } else if matches!(
                normalized,
                "socket.io" | "socket.io-client" | "socket.io-client.io"
            ) {
                value.name = Some("socket.io".to_owned());
            } else if matches!(
                normalized,
                "net.Socket" | "net.connect" | "tls.connect" | "dgram.createSocket"
            ) {
                value.name = Some("network.socket".to_owned());
            } else if matches!(
                normalized,
                "http.get"
                    | "https.get"
                    | "http.request"
                    | "https.request"
                    | "request"
                    | "request.get"
                    | "request.post"
            ) {
                value.name = Some("http.response".to_owned());
            }
            return value;
        }
        if matches!(
            normalized,
            "WebSocket.send"
                | "ws.send"
                | "WebSocket.write"
                | "network.socket.send"
                | "network.socket.write"
                | "network.socket.end"
                | "socket.io.emit"
                | "http.response.write"
                | "http.response.end"
        ) {
            self.exfiltration(path, line, name, &args);
            return Value::default();
        }
        if matches!(
            normalized,
            "navigator.sendBeacon"
                | "globalThis.navigator.sendBeacon"
                | "window.navigator.sendBeacon"
        ) {
            self.exfiltration(path, line, name, &args);
            return Value::default();
        }
        if matches!(
            normalized,
            "fs.readFile"
                | "fs.readFileSync"
                | "fs.promises.readFile"
                | "fs/promises.readFile"
                | "fs.createReadStream"
        ) {
            let target = args
                .first()
                .and_then(|value| value.literal.as_deref().or(value.path_hint.as_deref()))
                .unwrap_or("");
            if sensitive_path(target) {
                return Value::labeled(
                    Label::FileSecret,
                    format!("{source} (path evidence: {target})"),
                );
            }
        }
        if matches!(normalized, "os.homedir") {
            let mut value = Value::labeled(Label::UserHome, source);
            value.literal = Some("$HOME".to_owned());
            return value;
        }
        if matches!(normalized, "os.tmpdir") {
            return Value::named("os.tmpdir()".to_owned());
        }
        if matches!(normalized, "path.join" | "path.resolve") {
            let mut value = Value::default();
            let mut segments = Vec::new();
            let mut complete = true;
            let mut key_parts = Vec::new();
            for arg in &args {
                value.merge(arg.clone());
                if let Some(segment) = &arg.literal {
                    segments.push(segment.trim_matches('/'));
                    key_parts.push(format!("literal:{segment}"));
                } else if let Some(segment) = &arg.path_hint {
                    segments.push(segment.trim_matches('/'));
                    complete = false;
                    if let Some(key) = &arg.path_key {
                        key_parts.push(format!("path:{key}"));
                    } else if let Some(name) = &arg.name {
                        key_parts.push(format!("value:{name}"));
                    }
                } else {
                    complete = false;
                    if let Some(key) = &arg.path_key {
                        key_parts.push(format!("path:{key}"));
                    } else if let Some(name) = &arg.name {
                        key_parts.push(format!("value:{name}"));
                    }
                }
            }
            let path = segments.join("/");
            if complete {
                value.literal = Some(path);
                value.path_key = None;
            } else {
                value.literal = None;
                if !path.is_empty() {
                    value.path_hint = Some(path);
                }
                if key_parts.len() == args.len() {
                    value.path_key = Some(format!("{normalized}({})", key_parts.join(",")));
                }
            }
            return value;
        }
        if normalized.ends_with(".getReader")
            && let Some(stream) = args.iter().find(|value| {
                value
                    .label(&[Label::Remote, Label::DecodedRemote])
                    .is_some()
            })
        {
            let mut reader = stream.clone();
            reader.stream_reader = true;
            return reader.propagate(format!("stream reader: {file_path}:{line} {name}"));
        }
        if normalized.ends_with(".read")
            && let Some(reader) = args.first()
            && reader.stream_reader
        {
            let mut result = Value::default();
            result.fields.insert(
                "value".to_owned(),
                reader
                    .clone()
                    .propagate(format!("stream chunk: {file_path}:{line} {name}")),
            );
            return result;
        }
        if matches!(
            normalized,
            "clipboard.readText"
                | "clipboard.read"
                | "clipboardy.read"
                | "clipboardy.readSync"
                | "electron.clipboard.readText"
                | "navigator.clipboard.readText"
                | "globalThis.navigator.clipboard.readText"
                | "window.navigator.clipboard.readText"
        ) {
            return Value::labeled(Label::Clipboard, source);
        }
        if matches!(
            normalized,
            "Buffer.from"
                | "atob"
                | "decodeURI"
                | "decodeURIComponent"
                | "unescape"
                | "String.fromCharCode"
                | "TextDecoder.decode"
        ) {
            let mut output = args.first().cloned().unwrap_or_default();
            if output.labels.contains_key(&Label::Remote) {
                let route = output.labels.remove(&Label::Remote).unwrap();
                output.labels.insert(Label::DecodedRemote, route);
            }
            return output.propagate(format!("decode: {file_path}:{line} {name}"));
        }
        if matches!(
            normalized,
            "JSON.parse" | "JSON.stringify" | "String" | "Buffer.toString" | "Promise.resolve"
        ) || normalized.ends_with(".toString")
            || normalized.ends_with(".json")
            || normalized.ends_with(".text")
            || normalized.ends_with(".buffer")
            || normalized.ends_with(".arrayBuffer")
            || normalized.ends_with(".blob")
            || normalized.ends_with(".formData")
            || normalized.ends_with(".bytes")
            || normalized.ends_with(".clone")
            || normalized.ends_with(".get")
            || normalized == "Buffer.concat"
            || normalized.ends_with(".concat")
            || normalized.ends_with(".replace")
            || normalized.ends_with(".slice")
            || normalized.ends_with(".substring")
            || normalized.ends_with(".split")
            || normalized.ends_with(".map")
            || normalized.ends_with(".join")
            || normalized.ends_with(".charCodeAt")
            || normalized.ends_with(".toLowerCase")
            || normalized.ends_with(".toUpperCase")
            || normalized.ends_with(".trim")
            || matches!(
                normalized,
                "Object.values"
                    | "btoa"
                    | "encodeURI"
                    | "encodeURIComponent"
                    | "TextEncoder.encode"
            )
        {
            return args
                .first()
                .cloned()
                .unwrap_or_default()
                .propagate(format!("transform: {file_path}:{line} {name}"));
        }
        if normalized == "fs.createWriteStream" {
            let mut stream = Value::named("file-stream".to_owned());
            stream.literal = args.first().and_then(Value::file_target);
            return stream;
        }
        if normalized.ends_with(".pipe")
            && let Some(contents) = args
                .iter()
                .find(|arg| arg.label(&[Label::Remote, Label::DecodedRemote]).is_some())
            && let Some(stream) = args
                .iter()
                .find(|arg| arg.name.as_deref() == Some("file-stream"))
            && let Some(target) = stream.literal.clone()
        {
            self.written.insert(
                target,
                contents
                    .clone()
                    .propagate(format!("stream write: {file_path}:{line} {name}")),
            );
        }
        if matches!(
            normalized,
            "fs.writeFile" | "fs.writeFileSync" | "fs.promises.writeFile" | "fs/promises.writeFile"
        ) && let (Some(target), Some(contents)) =
            (args.first().and_then(Value::file_target), args.get(1))
        {
            if args
                .first()
                .and_then(|value| value.literal.as_deref())
                .is_some_and(persistence_path)
            {
                self.findings.push(Finding {
                    id: "JS-PERSISTENCE-WRITE".to_owned(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    score: 85,
                    title: "JavaScript writes to an automatic startup location".to_owned(),
                    message: "A filesystem write targets a recognized persistence location."
                        .to_owned(),
                    file: Some(file_path.clone()),
                    line: Some(line),
                    evidence: self
                        .route(path)
                        .into_iter()
                        .chain([format!("write target: {target}")])
                        .collect(),
                });
            }
            if contents
                .label(&[Label::Remote, Label::DecodedRemote])
                .is_some()
            {
                self.written.insert(
                    target,
                    contents
                        .clone()
                        .propagate(format!("write: {file_path}:{line} {name}")),
                );
            }
        }
        if matches!(
            normalized,
            "fs.chmod" | "fs.chmodSync" | "fs.promises.chmod" | "fs/promises.chmod"
        ) && let Some(target) = args.first().and_then(Value::file_target)
            && let Some(written) = self.written.get_mut(&target)
        {
            *written = written
                .clone()
                .propagate(format!("chmod: {file_path}:{line} {name}"));
        }
        if matches!(
            normalized,
            "eval"
                | "Function"
                | "global.eval"
                | "globalThis.eval"
                | "window.eval"
                | "global.Function"
                | "globalThis.Function"
                | "window.Function"
                | "vm.runInThisContext"
                | "vm.runInNewContext"
                | "vm.runInContext"
                | "vm.Script"
                | "vm.compileFunction"
                | "process.dlopen"
                | "import"
                | "require"
                | "dynamic require"
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
                | "child_process.execFile"
                | "child_process.execFileSync"
                | "child_process.fork"
                | "Bun.spawn"
                | "Deno.Command"
        ) {
            if let Some(command) = args.first().and_then(|arg| arg.literal.as_deref())
                && persistence_command(command)
            {
                self.findings.push(Finding {
                    id: "JS-PERSISTENCE-COMMAND".to_owned(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    score: 85,
                    title: "JavaScript invokes an automatic-startup command".to_owned(),
                    message: "A process execution API receives a recognized persistence command."
                        .to_owned(),
                    file: Some(file_path.clone()),
                    line: Some(line),
                    evidence: self
                        .route(path)
                        .into_iter()
                        .chain([format!("command: {command}")])
                        .collect(),
                });
            }
            if let Some(route) = args
                .iter()
                .find_map(|arg| arg.label(&[Label::DecodedRemote, Label::Remote]))
            {
                self.emit(ChainRule::RemoteProcess, path, line, name, route);
            }
            if let Some(target) = args.first().and_then(Value::file_target)
                && let Some(written) = self.written.get(&target)
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
                .map(|specifier| {
                    if specifier.starts_with('.') {
                        Value::named(format!("import:{specifier}#*"))
                    } else {
                        Value::named(specifier)
                    }
                })
                .unwrap_or_default();
        }
        Value::default()
    }

    fn call_function(
        &mut self,
        path: &str,
        name: &str,
        function: &Function,
        args: Vec<Value>,
        mut scope: BTreeMap<String, Value>,
        depth: usize,
    ) -> Value {
        if let Some((receiver, _)) = name.rsplit_once('.') {
            scope.insert("this".to_owned(), Value::named(receiver.to_owned()));
        }
        for (index, parameter) in function.params.iter().enumerate() {
            self.bind(
                parameter,
                args.get(index).cloned().unwrap_or_default(),
                &mut scope,
            );
        }
        let returned = self
            .run(path, &function.body, &mut scope, depth)
            .unwrap_or_default();
        returned.propagate(format!("return: {} {name}", self.file_path(path)))
    }

    fn exported_function(
        &mut self,
        path: &str,
        exported: &str,
    ) -> Option<(String, String, Function)> {
        let mut id = path.to_owned();
        let mut exported = if exported == "*" {
            "default".to_owned()
        } else {
            exported.to_owned()
        };
        for _ in 0..MAX_CALL_DEPTH {
            let module = self.modules.get(id.as_str())?;
            if let Some(local) = module.flow.exports.get(&exported)
                && let Some(function) = module.flow.functions.get(local)
            {
                return Some((id, local.clone(), function.clone()));
            }
            if let Some((object, method)) = exported.split_once('.') {
                let local = module
                    .flow
                    .exports
                    .get(object)
                    .map_or(object, String::as_str);
                let function_name = format!("{local}.{method}");
                if let Some(function) = module.flow.functions.get(&function_name) {
                    return Some((id, function_name, function.clone()));
                }
            }
            let reexport = module
                .flow
                .reexports
                .get(&exported)
                .map(|(specifier, imported)| (specifier.clone(), imported.clone()))
                .or_else(|| {
                    (exported != "default")
                        .then(|| module.flow.reexports.get("*"))
                        .flatten()
                        .map(|(specifier, _)| (specifier.clone(), exported.clone()))
                })?;
            let target = resolve_import(&module.path, &reexport.0, &self.by_path)?;
            id = self.by_path.get(target)?.id.clone();
            exported = reexport.1;
        }
        self.limited = true;
        None
    }

    fn exfiltration(&mut self, path: &str, line: u64, sink: &str, args: &[Value]) {
        if let Some(route) = args.iter().find_map(|arg| {
            arg.label(&[
                Label::EnvSecret,
                Label::FileSecret,
                Label::Clipboard,
                Label::UserHome,
            ])
        }) {
            self.emit(ChainRule::SecretExfiltration, path, line, sink, route);
        }
    }

    fn emit(&mut self, rule: ChainRule, path: &str, line: u64, sink: &str, route: &[String]) {
        let (id, title, impact, score) = rule.details();
        if !self.seen.insert((id.to_owned(), path.to_owned(), line)) {
            return;
        }
        let mut evidence = self.route(path);
        evidence.extend(route.iter().cloned());
        let file_path = self.file_path(path).to_owned();
        evidence.push(format!("sink: {file_path}:{line} {sink}"));
        self.findings.push(Finding {
            id: id.to_owned(),
            severity: Severity::Critical,
            confidence: if self.reachable.contains_key(path) {
                Confidence::VeryHigh
            } else {
                Confidence::High
            },
            score,
            title: title.to_owned(),
            message: impact.to_owned(),
            file: Some(file_path),
            line: Some(line),
            evidence,
        });
    }
}

fn sensitive_path(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    [
        ".ssh",
        ".aws",
        ".azure",
        "gcloud",
        ".npmrc",
        ".gitconfig",
        ".kube",
        ".docker",
        ".mozilla",
        "mozilla/firefox/profiles",
        "firefox/profiles",
        "logins.json",
        "key4.db",
        "chrome/user data",
        "google/chrome/user data",
        "microsoft/edge/user data",
        "chromium/user data",
        "brave",
        "keychain",
        "keychains/",
        "login data",
        "cookies",
        "1password",
        "bitwarden",
        "lastpass",
        ".password-store",
        "keepass",
        "wallet",
        "metamask",
        "exodus",
        "electrum",
        "wallet.dat",
        "password",
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

fn persistence_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        "/etc/cron",
        "/launchagents/",
        "/systemd/user/",
        "/.config/autostart/",
        "/startup/",
        "/.bashrc",
        "/.zshrc",
        "\\run\\",
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

fn persistence_command(command: &str) -> bool {
    let command = command.trim().to_ascii_lowercase();
    [
        "crontab ",
        "reg add ",
        "reg.exe add ",
        "schtasks /create",
        "launchctl load ",
        "systemctl --user enable ",
    ]
    .iter()
    .any(|prefix| command.starts_with(prefix))
}
