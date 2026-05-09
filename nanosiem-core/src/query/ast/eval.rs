// SPDX-License-Identifier: AGPL-3.0-or-later

//! Eval expression types for the query AST
//!
//! This module defines types related to eval expressions, binary operators,
//! risk score expressions, and structural types like TableField, SortField,
//! and Aggregation-related assignments.

use serde::{Deserialize, Serialize};

use super::types::Value;

/// Eval assignment: field = expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalAssignment {
    /// Field name to assign to
    pub field: String,
    /// Expression to evaluate
    pub expression: EvalExpression,
}

/// Risk score expression - can be a literal integer or a dynamic expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RiskScoreExpr {
    /// Static literal score (0-100)
    Literal(i32),
    /// Dynamic expression that evaluates to a score (will be clamped to 0-100)
    Dynamic(EvalExpression),
}

impl RiskScoreExpr {
    /// Check if this is a literal value
    pub fn is_literal(&self) -> bool {
        matches!(self, RiskScoreExpr::Literal(_))
    }

    /// Get the literal value if this is a literal
    pub fn as_literal(&self) -> Option<i32> {
        match self {
            RiskScoreExpr::Literal(v) => Some(*v),
            RiskScoreExpr::Dynamic(_) => None,
        }
    }
}

/// Expression types for eval command
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvalExpression {
    /// Field reference
    Field(String),
    /// Literal value
    Literal(Value),
    /// Binary operation (left op right)
    BinaryOp {
        left: Box<EvalExpression>,
        op: BinaryOperator,
        right: Box<EvalExpression>,
    },
    /// Function call
    FunctionCall {
        name: String,
        args: Vec<EvalExpression>,
    },
}

/// Binary operators for eval expressions
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BinaryOperator {
    /// Addition (+)
    Add,
    /// Subtraction (-)
    Sub,
    /// Multiplication (*)
    Mul,
    /// Division (/)
    Div,
    /// Modulo (%)
    Mod,
    /// String concatenation (.)
    Concat,
    /// Equal (==)
    Eq,
    /// Not equal (!=)
    Ne,
    /// Greater than (>)
    Gt,
    /// Less than (<)
    Lt,
    /// Greater than or equal (>=)
    Gte,
    /// Less than or equal (<=)
    Lte,
    /// Logical AND (&&)
    And,
    /// Logical OR (||)
    Or,
    /// CONTAINS (string containment check, used in eval expressions)
    Contains,
    /// LIKE (pattern matching, used in eval expressions)
    Like,
}

impl BinaryOperator {
    /// Returns the string representation of the operator
    pub fn as_str(&self) -> &'static str {
        match self {
            BinaryOperator::Add => "+",
            BinaryOperator::Sub => "-",
            BinaryOperator::Mul => "*",
            BinaryOperator::Div => "/",
            BinaryOperator::Mod => "%",
            BinaryOperator::Concat => ".",
            BinaryOperator::Eq => "==",
            BinaryOperator::Ne => "!=",
            BinaryOperator::Gt => ">",
            BinaryOperator::Lt => "<",
            BinaryOperator::Gte => ">=",
            BinaryOperator::Lte => "<=",
            BinaryOperator::And => "&&",
            BinaryOperator::Or => "||",
            BinaryOperator::Contains => "CONTAINS",
            BinaryOperator::Like => "LIKE",
        }
    }
}

/// Table field with optional alias
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableField {
    /// Field name
    pub name: String,
    /// Optional alias for the field
    pub alias: Option<String>,
}

/// Sort field with direction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SortField {
    /// Field name to sort by
    pub field: String,
    /// Sort direction (true = descending, false = ascending)
    pub descending: bool,
}
