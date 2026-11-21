// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5742: integrity violations raised while deleting a principal (user or
//! group), with what an operator needs to find the cause.

/// A Postgres integrity violation raised by a principal delete.
///
/// `23503` (foreign key) is an expected refusal: a reference that does not
/// detach deleted principals, or a trigger refusing to orphan evidence.
/// `23502` (NOT NULL) and `23514` (CHECK) mean an `ON DELETE SET NULL`
/// cascade broke a constraint: a schema bug, logged at error level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteIntegrityViolation {
    pub sqlstate: String,
    pub table: Option<String>,
    pub column: Option<String>,
    pub constraint: Option<String>,
}

impl DeleteIntegrityViolation {
    /// `Some` for SQLSTATE 23503 / 23502 / 23514, `None` for anything else.
    pub fn from_sqlx(e: &sqlx::Error) -> Option<Self> {
        let sqlx::Error::Database(db_err) = e else {
            return None;
        };
        let sqlstate = db_err.code()?.into_owned();
        if !matches!(sqlstate.as_str(), "23503" | "23502" | "23514") {
            return None;
        }
        let column = db_err
            .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .and_then(|pg| pg.column())
            .map(str::to_string);
        Some(Self {
            sqlstate,
            table: db_err.table().map(str::to_string),
            column,
            constraint: db_err.constraint().map(str::to_string),
        })
    }

    /// True for the foreign-key refusal; false for a broken NOT NULL / CHECK.
    pub fn is_foreign_key(&self) -> bool {
        self.sqlstate == "23503"
    }

    /// Constraint name, else `table.column`, else the table: what to name in
    /// logs and admin-facing error detail.
    pub fn label(&self) -> String {
        match (&self.constraint, &self.table, &self.column) {
            (Some(c), _, _) => c.clone(),
            (None, Some(t), Some(col)) => format!("{t}.{col}"),
            (None, Some(t), None) => t.clone(),
            (None, None, Some(col)) => col.clone(),
            (None, None, None) => "unknown".to_string(),
        }
    }
}
