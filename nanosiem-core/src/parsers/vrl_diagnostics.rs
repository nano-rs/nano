// SPDX-License-Identifier: AGPL-3.0-or-later

//! Byte spans from the guarded compiler, without parsing rendered diagnostics.
use super::{vrl_functions::safe_vrl_functions, vrl_guard};

#[derive(Debug, Clone)]
pub struct CompilerSite {
    pub code: usize,
    pub start: usize,
    pub end: usize,
    /// A proven-safe abort marker insertion, at the parsed function identifier.
    pub abort_insert: Option<usize>,
}

/// `set` can fail only on an invalid path segment once the compiler has
/// verified its argument types. Literal string/integer segments cannot cause
/// that error. Keeping the successful object type avoids a null union that
/// breaks subsequent mutations. Never apply this to dynamic paths or casts.
fn safe_set_abort(source: &str) -> Option<usize> {
    use vrl::parser::ast::{Container, Expr, Literal, RootExpr};
    vrl_guard::check(source).ok()?;
    let program = vrl::parser::parse(source).ok()?;
    if program.0.len() != 1 {
        return None;
    }
    let RootExpr::Expr(expr) = program.0[0].inner() else {
        return None;
    };
    let Expr::FunctionCall(call) = expr.inner() else {
        return None;
    };
    let call = call.inner();
    if call.ident.inner().to_string() != "set" || call.abort_on_error {
        return None;
    }
    let path = call
        .arguments
        .iter()
        .find(|a| {
            a.inner()
                .ident
                .as_ref()
                .is_some_and(|name| name.inner().to_string() == "path")
        })
        .or_else(|| call.arguments.get(1))?;
    let Expr::Container(container) = path.inner().expr.inner() else {
        return None;
    };
    let Container::Array(array) = container.inner() else {
        return None;
    };
    let mut segments = array.inner().clone().into_iter().peekable();
    if segments.peek().is_none() { return None; }
    let literal_segments = segments.all(|segment| {
        matches!(segment.inner(), Expr::Literal(literal) if matches!(literal.inner(),
            Literal::String(_) | Literal::RawString(_) | Literal::Integer(_)))
    });
    literal_segments.then_some(call.ident.end())
}

pub async fn compiler_sites(source: &str) -> Vec<CompilerSite> {
    let source = source.to_string();
    tokio::task::spawn_blocking(
        move || match vrl_guard::compile(&source, &safe_vrl_functions()) {
            Err(vrl_guard::VrlCompileError::Diagnostics(list)) => list
                .iter()
                .filter_map(|d| {
                    let label = d.labels.iter().find(|l| l.primary)?;
                    // Extra primary labels on E103 describe an unverified
                    // argument type. Such calls must keep runtime handling.
                    let verified =
                        d.code == 103 && d.labels.iter().filter(|l| l.primary).count() == 1;
                    let abort_insert = verified
                        .then(|| {
                            source
                                .get(label.span.start()..label.span.end())
                                .and_then(safe_set_abort)
                                .map(|offset| label.span.start() + offset)
                        })
                        .flatten();
                    Some(CompilerSite {
                        code: d.code,
                        start: label.span.start(),
                        end: label.span.end(),
                        abort_insert,
                    })
                })
                .collect(),
            _ => Vec::new(),
        },
    )
    .await
    .unwrap_or_default()
}
