use super::*;
use crate::AnalysisControl;
use std::collections::BTreeSet;

pub fn identifier(text: &str) -> String {
    let mut result = String::new();
    for (i, ch) in text.chars().take(128).enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if i == 0 && ch.is_ascii_digit() {
                result.push('_');
            }
            result.push(ch);
        } else {
            result.push('_');
        }
    }
    if result.is_empty() {
        result.push_str("unnamed");
    }
    if [
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
        "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
        "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
        "union", "unsigned", "void", "volatile", "while", "bool", "true", "false", "_Bool",
        "_Atomic", "_Alignas", "_Alignof",
    ]
    .contains(&result.as_str())
    {
        result.insert_str(0, "user_");
    }
    result
}
fn comment(text: &str) -> String {
    text.chars()
        .take(256)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .replace("*/", "* /")
}
fn storage_type(ty: Type) -> String {
    match ty.width() {
        Some(1) => "bool".into(),
        Some(8 | 16 | 32 | 64) => format!("uint{}_t", ty.width().unwrap()),
        Some(width) => format!("ura_bits{width}_t"),
        None => "ura_memory_t".into(),
    }
}
pub(super) fn type_name(ty: &TypeRef, address_bits: u16) -> String {
    match ty {
        TypeRef::Void => "void".into(),
        TypeRef::Bool => "bool".into(),
        TypeRef::Int { bits, signed } => format!(
            "{}int{bits}_t",
            if *signed == Some(true) { "" } else { "u" }
        ),
        TypeRef::Pointer {
            to,
            address_bits: width,
        } if *width != address_bits => format!(
            "ura_ptr{width}_t /* {} */",
            comment(&type_name(to, address_bits))
        ),
        TypeRef::Pointer { to, .. } => format!("{} *", type_name(to, address_bits)),
        TypeRef::Struct { name } => format!("struct {}", identifier(name)),
        TypeRef::Union { name } => format!("union {}", identifier(name)),
        TypeRef::Enum { name, .. } => format!("enum {}", identifier(name)),
        TypeRef::Typedef { name, .. } | TypeRef::Named { name } => identifier(name),
        TypeRef::Qualified { qualifier, target } => format!(
            "{} {}",
            identifier(qualifier),
            type_name(target, address_bits)
        ),
        TypeRef::Float { bits: 32 } => "float".into(),
        TypeRef::Float { bits: 64 } => "double".into(),
        TypeRef::Array { element, count } => format!(
            "{}[{}]",
            type_name(element, address_bits),
            count.map_or(String::new(), |n| n.to_string())
        ),
        _ => format!(
            "ura_unknown{}_t",
            ty.bits(&super::super::types::TypeDatabase::new(address_bits))
                .unwrap_or(u64::from(address_bits))
        ),
    }
}

struct Printer<'a> {
    function: &'a Function,
    lines: Vec<Line>,
    indent: usize,
    truncated: bool,
    pending_addresses: BTreeSet<Address>,
}
impl Printer<'_> {
    fn expr(&self, e: &Expr) -> String {
        use semantic::ScalarOp as Op;
        let value = match &e.kind {
            ExprKind::Variable { id } => {
                let variable = &self.function.variables[*id];
                let pointer = variable
                    .parameter
                    .and_then(|i| {
                        self.function
                            .signature
                            .as_ref()?
                            .parameters
                            .iter()
                            .find(|p| p.index == i)
                    })
                    .is_some_and(|p| matches!(p.ty, TypeRef::Pointer { .. }));
                if pointer {
                    format!("((uintptr_t){})", variable.name)
                } else if variable.parameter.is_some() {
                    format!("(({}){})", storage_type(variable.storage), variable.name)
                } else {
                    variable.name.clone()
                }
            }
            ExprKind::Parameter { index, .. } => {
                let parameter = self
                    .function
                    .signature
                    .as_ref()
                    .and_then(|s| s.parameters.iter().find(|p| p.index == *index));
                parameter
                    .map(|p| format!("(({}){})", storage_type(e.storage), identifier(&p.name)))
                    .unwrap_or_else(|| "ura_unknown_parameter()".into())
            }
            ExprKind::Constant { constant } => {
                let value = constant.value.0;
                if value < 10 {
                    value.to_string()
                } else {
                    format!("0x{value:x}ULL")
                }
            }
            ExprKind::Load { address } => format!(
                "ura_load_u{}({})",
                e.storage.width().unwrap_or(64),
                self.expr(address)
            ),
            ExprKind::Unknown { reason } => format!(
                "ura_unknown_u{}(/* {} */)",
                e.storage.width().unwrap_or(64),
                comment(reason)
            ),
            ExprKind::Scalar {
                operator,
                arguments,
            } => {
                let args: Vec<_> = arguments.iter().map(|a| self.expr(a)).collect();
                let a = args
                    .first()
                    .map(String::as_str)
                    .unwrap_or("ura_missing_operand()");
                let b = args
                    .get(1)
                    .map(String::as_str)
                    .unwrap_or("ura_missing_operand()");
                let width = e.storage.width().unwrap_or(64);
                let input_width = arguments
                    .first()
                    .and_then(|a| a.storage.width())
                    .unwrap_or(width);
                let cast = |s: String| {
                    if matches!(width, 8 | 16 | 32 | 64) {
                        format!("((uint{width}_t)({s}))")
                    } else {
                        format!("ura_bits_{width}({s})")
                    }
                };
                match operator {
                    Op::Divide { signed, .. } | Op::DivideFault { signed } => {
                        let operation = match operator {
                            Op::DivideFault { .. } => "fault",
                            Op::Divide {
                                remainder: true, ..
                            } => "remainder",
                            _ => "quotient",
                        };
                        format!(
                            "ura_div_{operation}_{}{input_width}({a}, {b}, {})",
                            if *signed { "s" } else { "u" },
                            args.get(2)
                                .map(String::as_str)
                                .unwrap_or("ura_missing_operand()")
                        )
                    }
                    Op::Move | Op::ZeroExtend | Op::Truncate | Op::AddressCast | Op::BitsCast => {
                        if arguments
                            .first()
                            .is_some_and(|a| a.storage.width() == e.storage.width())
                        {
                            a.into()
                        } else {
                            cast(a.into())
                        }
                    }
                    Op::Add | Op::Subtract | Op::Multiply | Op::And | Op::Or | Op::Xor => {
                        if matches!(operator, Op::Xor)
                            && width == 1
                            && matches!(arguments.get(1).map(|e| &e.kind), Some(ExprKind::Constant {constant}) if constant.value.0 == 1)
                        {
                            return format!("(!({a}))");
                        }
                        let op = match operator {
                            Op::Add => "+",
                            Op::Subtract => "-",
                            Op::Multiply => "*",
                            Op::And => "&",
                            Op::Or => "|",
                            _ => "^",
                        };
                        if matches!(operator, Op::Multiply) {
                            // uint16_t operands otherwise promote to signed int
                            // and may overflow before the outer truncation.
                            cast(format!("((uint64_t)({a})) * ((uint64_t)({b}))"))
                        } else {
                            cast(format!("({a}) {op} ({b})"))
                        }
                    }
                    Op::Complement => cast(format!("~({a})")),
                    Op::Equal => format!("(({a}) == ({b}))"),
                    Op::UnsignedLess => format!("(({a}) < ({b}))"),
                    Op::SignedLess => {
                        format!("(ura_signed_u{input_width}({a}) < ura_signed_u{input_width}({b}))")
                    }
                    Op::UnsignedMultiplyHigh | Op::SignedMultiplyHigh => format!(
                        "ura_mul_high_{}_u{width}({a}, {b})",
                        if matches!(operator, Op::SignedMultiplyHigh) {
                            "signed"
                        } else {
                            "unsigned"
                        }
                    ),
                    Op::ShiftLeft => format!("ura_shl_u{input_width}({a}, {b})"),
                    Op::ShiftRight => format!("ura_shr_u{input_width}({a}, {b})"),
                    Op::RotateLeft => format!("ura_rol_u{input_width}({a}, {b})"),
                    Op::RotateRight => format!("ura_ror_u{input_width}({a}, {b})"),
                    Op::SignExtend => format!("ura_sext_{input_width}_{width}({a})"),
                    Op::Extract { offset } => {
                        if *offset == 0 && input_width == width {
                            a.into()
                        } else {
                            cast(format!("({a}) >> {offset}"))
                        }
                    }
                    Op::Insert { offset } => format!(
                        "ura_insert_{}_at_{offset}_{width}({a}, {b})",
                        arguments
                            .get(1)
                            .and_then(|a| a.storage.width())
                            .unwrap_or(0)
                    ),
                    Op::Parity => format!("ura_parity8({a})"),
                    Op::Select => format!(
                        "(({a}) ? ({b}) : ({}))",
                        args.get(2)
                            .map(String::as_str)
                            .unwrap_or("ura_missing_operand()")
                    ),
                }
            }
        };
        value
    }
    fn expression_meta(
        &self,
        e: &Expr,
        addresses: &mut BTreeSet<Address>,
        variables: &mut BTreeSet<usize>,
    ) {
        if let Some(source) = e.source.and_then(|id| self.function.sources.get(id)) {
            addresses.extend(source.instruction);
        }
        match &e.kind {
            ExprKind::Variable { id } => {
                variables.insert(*id);
            }
            ExprKind::Scalar { arguments, .. } => {
                for arg in arguments {
                    self.expression_meta(arg, addresses, variables);
                }
            }
            ExprKind::Load { address } => self.expression_meta(address, addresses, variables),
            _ => {}
        }
    }
    fn line(
        &mut self,
        text: String,
        statement: Option<&Statement>,
        expressions: &[&Expr],
        written: Option<usize>,
        callee: Option<Address>,
    ) {
        if self.lines.len() >= MAX_LINES - 2 {
            self.truncated = true;
            return;
        }
        let mut addresses = std::mem::take(&mut self.pending_addresses);
        let mut variables = BTreeSet::new();
        if let Some(source) = statement
            .and_then(|s| s.source)
            .and_then(|s| self.function.sources.get(s))
        {
            addresses.extend(source.instruction);
        }
        variables.extend(written);
        for expr in expressions {
            self.expression_meta(expr, &mut addresses, &mut variables);
        }
        let synthetic = addresses.is_empty() && statement.map_or(true, |s| s.synthetic);
        self.lines.push(Line {
            number: self.lines.len() + 1,
            indent: self.indent,
            text,
            addresses: addresses.into_iter().collect(),
            variables: variables.into_iter().collect(),
            callee,
            synthetic,
        });
    }
    fn body(
        &mut self,
        body: &[Statement],
        control: &dyn AnalysisControl,
        depth: usize,
    ) -> Result<(), String> {
        if depth > 64 {
            return Err("C-like AST nesting budget exceeded".into());
        }
        for statement in body {
            if control.is_cancelled() {
                return Err("C-like rendering cancelled".into());
            }
            if self.truncated {
                break;
            }
            match &statement.kind {
                StatementKind::Guard { condition, reason } => self.line(
                    format!(
                        "if ({}) ura_trap(/* {} */);",
                        self.expr(condition),
                        comment(reason)
                    ),
                    Some(statement),
                    &[condition],
                    None,
                    None,
                ),
                StatementKind::Assign { variable, value } => self.line(
                    format!(
                        "{} = {};",
                        self.function.variables[*variable].name,
                        self.expr(value)
                    ),
                    Some(statement),
                    &[value],
                    Some(*variable),
                    None,
                ),
                StatementKind::Store {
                    address,
                    value,
                    stack_name,
                } => {
                    let suffix = stack_name
                        .as_ref()
                        .map(|n| format!(" /* stack: {} */", comment(n)))
                        .unwrap_or_default();
                    self.line(
                        format!(
                            "ura_store_u{}({}, {});{suffix}",
                            value.storage.width().unwrap_or(0),
                            self.expr(address),
                            self.expr(value)
                        ),
                        Some(statement),
                        &[address, value],
                        None,
                        None,
                    );
                }
                StatementKind::Call {
                    target,
                    callee,
                    name,
                    arguments,
                    unknown_arguments,
                } => {
                    let target_text = name.clone().unwrap_or_else(|| {
                        callee
                            .map(|a| format!("sub_{:X}", a.0))
                            .unwrap_or_else(|| format!("ura_call_indirect({})", self.expr(target)))
                    });
                    let mut args = arguments
                        .iter()
                        .map(|e| self.expr(e))
                        .collect::<Vec<_>>()
                        .join(", ");
                    if *unknown_arguments {
                        if !args.is_empty() {
                            args.push_str(", ");
                        }
                        args.push_str("/* remaining arguments unknown */");
                    }
                    let mut exprs: Vec<_> = arguments.iter().collect();
                    exprs.push(target);
                    self.line(
                        format!("{target_text}({args});"),
                        Some(statement),
                        &exprs,
                        None,
                        *callee,
                    );
                }
                StatementKind::Unknown {
                    variable,
                    memory,
                    reason,
                } => {
                    let prefix = variable
                        .filter(|v| self.function.variables[*v].storage != Type::Memory)
                        .map(|v| format!("{} = ", self.function.variables[v].name))
                        .unwrap_or_default();
                    self.line(
                        format!(
                            "{prefix}ura_unknown_{}(/* {} */);",
                            if *memory { "memory_effect" } else { "value" },
                            comment(reason)
                        ),
                        Some(statement),
                        &[],
                        *variable,
                        None,
                    );
                }
                StatementKind::Label { address } => self.line(
                    format!("L_{:X}:", address.0),
                    Some(statement),
                    &[],
                    None,
                    None,
                ),
                StatementKind::Block { .. } => {}
                StatementKind::Provenance => {
                    if let Some(source) =
                        statement.source.and_then(|s| self.function.sources.get(s))
                    {
                        self.pending_addresses.extend(source.instruction);
                    }
                }
                StatementKind::Goto { target } => self.line(
                    format!("goto L_{:X};", target.0),
                    Some(statement),
                    &[],
                    None,
                    None,
                ),
                StatementKind::If {
                    condition,
                    taken,
                    otherwise,
                } => {
                    self.line(
                        format!("if ({}) {{", self.expr(condition)),
                        Some(statement),
                        &[condition],
                        None,
                        None,
                    );
                    self.indent += 1;
                    self.body(taken, control, depth + 1)?;
                    self.indent -= 1;
                    if !otherwise.is_empty() {
                        self.line("} else {".into(), Some(statement), &[], None, None);
                        self.indent += 1;
                        self.body(otherwise, control, depth + 1)?;
                        self.indent -= 1;
                    }
                    self.line("}".into(), Some(statement), &[], None, None);
                }
                StatementKind::Loop { body } => {
                    self.line("while (true) {".into(), Some(statement), &[], None, None);
                    self.indent += 1;
                    self.body(body, control, depth + 1)?;
                    self.indent -= 1;
                    self.line("}".into(), Some(statement), &[], None, None);
                }
                StatementKind::Break => {
                    self.line("break;".into(), Some(statement), &[], None, None)
                }
                StatementKind::Continue => {
                    self.line("continue;".into(), Some(statement), &[], None, None)
                }
                StatementKind::Return {
                    result,
                    destination,
                } => {
                    let mut exprs: Vec<_> = result.iter().collect();
                    exprs.extend(destination);
                    let text = match result {
                        Some(value) => format!("return {};", self.expr(value)),
                        None => "return;".into(),
                    };
                    self.line(text, Some(statement), &exprs, None, None);
                }
                StatementKind::Exit {
                    destination,
                    reason,
                } => self.line(
                    format!(
                        "ura_unresolved_exit({}); /* {} */",
                        destination
                            .as_ref()
                            .map(|e| self.expr(e))
                            .unwrap_or_default(),
                        comment(reason)
                    ),
                    Some(statement),
                    &destination.iter().collect::<Vec<_>>(),
                    None,
                    None,
                ),
            }
        }
        Ok(())
    }
}
pub fn render(mut ast: Function, control: &dyn AnalysisControl) -> Result<Output, String> {
    let mut printer = Printer {
        function: &ast,
        lines: Vec::new(),
        indent: 0,
        truncated: false,
        pending_addresses: BTreeSet::new(),
    };
    printer.line(
        "/* Reconstructed C-like pseudocode; machine helpers preserve explicit widths/effects. */"
            .into(),
        None,
        &[],
        None,
        None,
    );
    let mut used = BTreeSet::new();
    fn used_in(body: &[Statement], used: &mut BTreeSet<usize>) {
        let mut expr = |e: &Expr| {
            let mut ids = Vec::new();
            e.variables(&mut ids);
            used.extend(ids);
        };
        for s in body {
            match &s.kind {
                StatementKind::Guard { condition, .. } => expr(condition),
                StatementKind::Assign { variable, value } => {
                    expr(value);
                    let _ = variable;
                }
                StatementKind::Store { address, value, .. } => {
                    expr(address);
                    expr(value);
                }
                StatementKind::Call {
                    target, arguments, ..
                } => {
                    expr(target);
                    for a in arguments {
                        expr(a);
                    }
                }
                StatementKind::If { condition, .. } => expr(condition),
                StatementKind::Return {
                    result,
                    destination,
                } => {
                    for e in result.iter().chain(destination) {
                        expr(e);
                    }
                }
                StatementKind::Exit {
                    destination: Some(e),
                    ..
                } => expr(e),
                _ => {}
            }
        }
        for s in body {
            match &s.kind {
                StatementKind::Assign { variable, .. }
                | StatementKind::Unknown {
                    variable: Some(variable),
                    ..
                } => {
                    used.insert(*variable);
                }
                StatementKind::If {
                    taken, otherwise, ..
                } => {
                    used_in(taken, used);
                    used_in(otherwise, used);
                }
                StatementKind::Loop { body } => used_in(body, used),
                _ => {}
            }
        }
    }
    used_in(&ast.body, &mut used);
    let signature = ast.signature.as_ref();
    let result = signature
        .map(|s| type_name(&s.return_type, ast.address_width))
        .unwrap_or_else(|| format!("ura_unknown{}_t", ast.address_width));
    let mut params = Vec::new();
    if let Some(signature) = signature {
        for parameter in &signature.parameters {
            let name = ast
                .variables
                .iter()
                .find(|v| v.parameter == Some(parameter.index))
                .map(|v| v.name.clone())
                .unwrap_or_else(|| identifier(&parameter.name));
            params.push(format!(
                "{} {name}",
                type_name(&parameter.ty, ast.address_width)
            ));
        }
        if signature.variadic == Some(true) {
            params.push("...".into());
        }
        if signature.parameters.is_empty()
            && signature.user_override
            && signature.variadic == Some(false)
            && signature.conflicts.is_empty()
        {
            params.push("void".into());
        }
    }
    if params.is_empty() {
        params.push("/* parameters not established */".into());
    }
    printer.line(
        format!("{result} {}({}) {{", ast.name, params.join(", ")),
        None,
        &[],
        None,
        None,
    );
    printer.indent = 1;
    for id in &used {
        let v = &ast.variables[*id];
        if v.storage == Type::Memory || v.parameter.is_some() {
            continue;
        }
        let initializer = v
            .entry_register
            .as_ref()
            .map(|r| format!(" = ura_entry_{}()", identifier(r)))
            .unwrap_or_default();
        printer.line(
            format!("{} {}{initializer};", storage_type(v.storage), v.name),
            None,
            &[],
            Some(*id),
            None,
        );
    }
    printer.line(String::new(), None, &[], None, None);
    printer.body(&ast.body, control, 0)?;
    if printer.truncated {
        printer.lines.push(Line {
            number: printer.lines.len() + 1,
            indent: 1,
            text: "/* OUTPUT TRUNCATED: inspect bounded IR/semantic block queries. */".into(),
            addresses: Vec::new(),
            variables: Vec::new(),
            callee: None,
            synthetic: true,
        });
    }
    printer.lines.push(Line {
        number: printer.lines.len() + 1,
        indent: 0,
        text: "}".into(),
        addresses: printer.pending_addresses.iter().copied().collect(),
        variables: Vec::new(),
        callee: None,
        synthetic: true,
    });
    let lines = printer.lines;
    ast.truncated |= printer.truncated;
    Ok(Output {
        function: ast.address,
        syntax: "c-like".into(),
        status: if ast.unresolved > 0 || ast.truncated {
            "partial"
        } else {
            "reconstructed"
        }
        .into(),
        lines,
        unresolved: ast.unresolved,
        truncated: ast.truncated,
        diagnostics: ast.diagnostics.clone(),
        ast,
    })
}
