// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3226: no internal suffixes keeps the domain list SQL unchanged; added
//! suffixes become a label-boundary `endsWith` exclusion.

use super::*;
use crate::internal_domains::InternalDomains;

#[test]
fn internal_domain_predicate_is_label_bounded_and_empty_by_default() {
    assert_eq!(internal_domain_predicate(&InternalDomains::builtin()), "");
    let predicate = internal_domain_predicate(&InternalDomains::with_suffixes(["prod", "corp.example.com"]));
    assert_eq!(
        predicate,
        " AND NOT arrayExists(s -> endsWith(concat('.', domain), concat('.', s)), ['corp.example.com', 'prod'])"
    );
}

#[test]
fn invalid_suffixes_never_reach_the_sql_and_idn_is_a_labels() {
    // `a'b` is not a DNS name (and could not inject); U-labels are stored as A-labels.
    let predicate = internal_domain_predicate(&InternalDomains::with_suffixes(["a'b", "bücher.example"]));
    assert_eq!(
        predicate,
        " AND NOT arrayExists(s -> endsWith(concat('.', domain), concat('.', s)), ['xn--bcher-kva.example'])"
    );
}

#[cfg(feature = "enterprise")]
#[test]
fn refused_stored_suffixes_never_reach_the_sql() {
    let stored = crate::internal_domains::store::with_tenant(["com", "prod"]);
    assert_eq!(
        internal_domain_predicate(&stored),
        " AND NOT arrayExists(s -> endsWith(concat('.', domain), concat('.', s)), ['prod'])"
    );
}
