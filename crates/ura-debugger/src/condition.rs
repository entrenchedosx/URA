//! Bounded unsigned register predicates. No scripting, memory access or side effects.
use crate::{DebugError, Registers, Result};

#[derive(Clone, Debug)]
enum Expr {
    Number(u64),
    Register(String),
    Not(Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
}
#[derive(Clone, Debug)]
pub struct Condition(Expr);
#[derive(Clone, Debug, PartialEq)]
enum Token {
    Number(u64),
    Name(String),
    Op(&'static str),
    Left,
    Right,
}
impl Condition {
    pub fn parse(text: &str) -> Result<Self> {
        let error = || DebugError::new("condition", "invalid bounded unsigned register condition");
        if text.is_empty() || text.len() > 512 || !text.is_ascii() {
            return Err(error());
        }
        let mut tokens = Vec::new();
        let mut pos = 0;
        while pos < text.len() {
            let rest = &text[pos..];
            let ch = rest.as_bytes()[0];
            if ch.is_ascii_whitespace() {
                pos += 1;
                continue;
            }
            let token = if ch.is_ascii_digit() {
                let end = rest
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(rest.len());
                let word = &rest[..end];
                let n = if let Some(hex) =
                    word.strip_prefix("0x").or_else(|| word.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16)
                } else {
                    word.parse()
                }
                .map_err(|_| error())?;
                pos += end;
                Token::Number(n)
            } else if ch.is_ascii_alphabetic() {
                let end = rest
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(rest.len());
                let name = rest[..end].to_ascii_lowercase();
                if ![
                    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9",
                    "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "eax", "ebx", "ecx", "edx",
                    "esi", "edi", "ebp", "esp", "eip", "cs", "ss", "ds", "es", "fs", "gs",
                ]
                .contains(&name.as_str())
                {
                    return Err(error());
                }
                pos += end;
                Token::Name(name)
            } else if ch == b'(' || ch == b')' {
                pos += 1;
                if ch == b'(' {
                    Token::Left
                } else {
                    Token::Right
                }
            } else {
                let op = [
                    "==", "!=", "<=", ">=", "&&", "||", "!", "<", ">", "&", "|", "^",
                ]
                .into_iter()
                .find(|op| rest.starts_with(op))
                .ok_or_else(error)?;
                pos += op.len();
                Token::Op(op)
            };
            tokens.push(token);
            if tokens.len() > 128 {
                return Err(error());
            }
        }
        fn expression(tokens: &[Token], p: &mut usize, min: u8, depth: usize) -> Result<Expr> {
            if depth > 24 {
                return Err(DebugError::new("condition", "condition nesting limit"));
            }
            let invalid = || {
                DebugError::new(
                    "condition",
                    "condition operand or closing parenthesis expected",
                )
            };
            let mut left = match tokens.get(*p).ok_or_else(invalid)? {
                Token::Number(n) => {
                    *p += 1;
                    Expr::Number(*n)
                }
                Token::Name(n) => {
                    *p += 1;
                    Expr::Register(n.clone())
                }
                Token::Op("!") => {
                    *p += 1;
                    Expr::Not(Box::new(expression(tokens, p, 7, depth + 1)?))
                }
                Token::Left => {
                    *p += 1;
                    let result = expression(tokens, p, 0, depth + 1)?;
                    if tokens.get(*p) != Some(&Token::Right) {
                        return Err(invalid());
                    }
                    *p += 1;
                    result
                }
                _ => return Err(invalid()),
            };
            while let Some(Token::Op(op)) = tokens.get(*p) {
                let precedence = match *op {
                    "||" => 1,
                    "&&" => 2,
                    "|" => 3,
                    "^" => 4,
                    "&" => 5,
                    "==" | "!=" | "<" | ">" | "<=" | ">=" => 6,
                    _ => 0,
                };
                if precedence == 0 || precedence < min {
                    break;
                }
                *p += 1;
                let right = expression(tokens, p, precedence + 1, depth + 1)?;
                left = Expr::Binary(op, Box::new(left), Box::new(right));
            }
            Ok(left)
        }
        let mut p = 0;
        let root = expression(&tokens, &mut p, 0, 0)?;
        if p != tokens.len() {
            return Err(error());
        }
        Ok(Self(root))
    }
    pub fn evaluate(&self, registers: &Registers) -> Result<bool> {
        fn value(e: &Expr, r: &Registers) -> Result<u64> {
            Ok(match e {
                Expr::Number(n) => *n,
                Expr::Register(n) => {
                    let direct = r
                        .values
                        .get(n)
                        .and_then(|v| ura_core::parse_address(v).ok());
                    let alias = match n.as_str() {
                        "eax" => Some("rax"),
                        "ebx" => Some("rbx"),
                        "ecx" => Some("rcx"),
                        "edx" => Some("rdx"),
                        "esi" => Some("rsi"),
                        "edi" => Some("rdi"),
                        "ebp" => Some("rbp"),
                        "esp" => Some("rsp"),
                        "eip" => Some("rip"),
                        _ => None,
                    };
                    direct
                        .or_else(|| {
                            alias
                                .and_then(|a| r.values.get(a))
                                .and_then(|v| ura_core::parse_address(v).ok())
                                .map(|n| n & 0xffff_ffff)
                        })
                        .ok_or_else(|| {
                            DebugError::new(
                                "condition",
                                format!("register {n} unavailable in captured context"),
                            )
                        })?
                }
                Expr::Not(e) => u64::from(value(e, r)? == 0),
                Expr::Binary(op, a, b) => {
                    let a = value(a, r)?;
                    if *op == "&&" && a == 0 {
                        return Ok(0);
                    }
                    if *op == "||" && a != 0 {
                        return Ok(1);
                    }
                    let b = value(b, r)?;
                    match *op {
                        "==" => u64::from(a == b),
                        "!=" => u64::from(a != b),
                        "<" => u64::from(a < b),
                        ">" => u64::from(a > b),
                        "<=" => u64::from(a <= b),
                        ">=" => u64::from(a >= b),
                        "&&" | "||" => u64::from(b != 0),
                        "&" => a & b,
                        "|" => a | b,
                        "^" => a ^ b,
                        _ => unreachable!(),
                    }
                }
            })
        }
        Ok(value(&self.0, registers)? != 0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn regs() -> Registers {
        Registers {
            thread: 1,
            architecture: "windows-x64".into(),
            values: [
                ("rcx".into(), "0x5".into()),
                ("rax".into(), "0xFFFFFFFFFFFFFFFF".into()),
            ]
            .into(),
        }
    }
    #[test]
    fn predicate_precedence_unsigned_and_short_circuit() {
        for text in [
            "RCX == 5",
            "!(rcx < 5) && (rax & 1) == 1",
            "rax > 0x7fffffffffffffff",
            "rcx != 5 || 1",
            "1 || rip == 0",
        ] {
            assert!(
                Condition::parse(text).unwrap().evaluate(&regs()).unwrap(),
                "{text}"
            );
        }
        for text in ["rcx == 0", "rcx == 5 && 0", "0 && rip == 0"] {
            assert!(
                !Condition::parse(text).unwrap().evaluate(&regs()).unwrap(),
                "{text}"
            );
        }
        assert!(Condition::parse("rip == 0")
            .unwrap()
            .evaluate(&regs())
            .is_err());
    }
    #[test]
    fn condition_rejects_scripts_overflow_and_excessive_nesting() {
        for text in [
            "",
            "unknown == 0",
            "rax = 0",
            "mem[0]",
            "1 + 2",
            "0x10000000000000000",
            "(rax == 0",
            "rax == 0)",
            "0xQQ",
        ] {
            assert!(Condition::parse(text).is_err(), "{text}");
        }
        assert!(Condition::parse(&format!("{}1{}", "(".repeat(30), ")".repeat(30))).is_err());
        assert!(Condition::parse(&"1||".repeat(100)).is_err());
    }
}
