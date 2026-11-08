// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4303: Nano-side `+` concatenates when an operand is text, the same
//! text the SQL path's `concat(toString(l), toString(r))` gives.
use super::eval::apply_binary_op;
use crate::query::BinaryOperator;
use serde_json::json;

#[test]
fn plus_with_a_string_operand_concatenates() {
    let plus = |l, r| apply_binary_op(&BinaryOperator::Add, l, r);
    assert_eq!(plus(json!("a"), json!("b")), Some(json!("ab")));
    assert_eq!(plus(json!("port "), json!(443.0)), Some(json!("port 443")));
    assert_eq!(plus(json!("v"), json!(1.5)), Some(json!("v1.5")));
    assert_eq!(plus(json!("bob"), json!(true)), Some(json!("bobtrue")));
    // Numbers still add; a NULL operand stays NULL.
    assert_eq!(plus(json!(2.0), json!(3.0)), Some(json!(5.0)));
    assert_eq!(plus(json!("a"), serde_json::Value::Null), None);
}
