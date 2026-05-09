// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_value_display_string() {
    assert_eq!(Value::String("hello".to_string()).to_string(), "hello");
    assert_eq!(
        Value::String("hello world".to_string()).to_string(),
        "\"hello world\""
    );
}

#[test]
fn test_value_display_number() {
    assert_eq!(Value::Number(42.0).to_string(), "42");
    assert_eq!(Value::Number(3.14).to_string(), "3.14");
}

#[test]
fn test_value_display_bool() {
    assert_eq!(Value::Bool(true).to_string(), "true");
    assert_eq!(Value::Bool(false).to_string(), "false");
}

#[test]
fn test_value_display_ip() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(Value::Ip(ip).to_string(), "192.168.1.1");
}

#[test]
fn test_comparator_as_str() {
    assert_eq!(Comparator::Eq.as_str(), "=");
    assert_eq!(Comparator::Ne.as_str(), "!=");
    assert_eq!(Comparator::Gt.as_str(), ">");
    assert_eq!(Comparator::Lt.as_str(), "<");
    assert_eq!(Comparator::Gte.as_str(), ">=");
    assert_eq!(Comparator::Lte.as_str(), "<=");
    assert_eq!(Comparator::Regex.as_str(), "=");
    assert_eq!(Comparator::NotRegex.as_str(), "!=");
}

#[test]
fn test_agg_func_as_str() {
    assert_eq!(AggFunc::Count.as_str(), "count");
    assert_eq!(AggFunc::Dc.as_str(), "dc");
    assert_eq!(AggFunc::Sum.as_str(), "sum");
    assert_eq!(AggFunc::Avg.as_str(), "avg");
    assert_eq!(AggFunc::Min.as_str(), "min");
    assert_eq!(AggFunc::Max.as_str(), "max");
    assert_eq!(AggFunc::Values.as_str(), "values");
    assert_eq!(AggFunc::List.as_str(), "list");
    assert_eq!(AggFunc::First.as_str(), "first");
    assert_eq!(AggFunc::Last.as_str(), "last");
    assert_eq!(AggFunc::Range.as_str(), "range");
    assert_eq!(AggFunc::Earliest.as_str(), "earliest");
    assert_eq!(AggFunc::Latest.as_str(), "latest");
    assert_eq!(AggFunc::Stdev.as_str(), "stdev");
    assert_eq!(AggFunc::Var.as_str(), "var");
    assert_eq!(AggFunc::Median.as_str(), "median");
    assert_eq!(AggFunc::Percentile(95).as_str(), "percentile");
    assert_eq!(AggFunc::Mode.as_str(), "mode");
}

#[test]
fn test_prevalence_field_as_str() {
    assert_eq!(PrevalenceField::HashPrevalence.as_str(), "hash_prevalence");
    assert_eq!(
        PrevalenceField::DomainPrevalence.as_str(),
        "domain_prevalence"
    );
    assert_eq!(PrevalenceField::HashFirstSeen.as_str(), "hash_first_seen");
    assert_eq!(
        PrevalenceField::DomainFirstSeen.as_str(),
        "domain_first_seen"
    );
}

#[test]
fn test_prevalence_field_is_count_field() {
    assert!(PrevalenceField::HashPrevalence.is_count_field());
    assert!(PrevalenceField::DomainPrevalence.is_count_field());
    assert!(!PrevalenceField::HashFirstSeen.is_count_field());
    assert!(!PrevalenceField::DomainFirstSeen.is_count_field());
}

#[test]
fn test_prevalence_field_is_timestamp_field() {
    assert!(!PrevalenceField::HashPrevalence.is_timestamp_field());
    assert!(!PrevalenceField::DomainPrevalence.is_timestamp_field());
    assert!(PrevalenceField::HashFirstSeen.is_timestamp_field());
    assert!(PrevalenceField::DomainFirstSeen.is_timestamp_field());
}

#[test]
fn test_prevalence_operator_as_str() {
    assert_eq!(PrevalenceOperator::Lt.as_str(), "<");
    assert_eq!(PrevalenceOperator::Lte.as_str(), "<=");
    assert_eq!(PrevalenceOperator::Gt.as_str(), ">");
    assert_eq!(PrevalenceOperator::Gte.as_str(), ">=");
    assert_eq!(PrevalenceOperator::Eq.as_str(), "=");
    assert_eq!(PrevalenceOperator::Ne.as_str(), "!=");
}

#[test]
fn test_prevalence_time_window_hours() {
    assert_eq!(PrevalenceTimeWindow::OneHour.hours(), 1);
    assert_eq!(PrevalenceTimeWindow::TwentyFourHours.hours(), 24);
    assert_eq!(PrevalenceTimeWindow::SevenDays.hours(), 168);
    assert_eq!(PrevalenceTimeWindow::ThirtyDays.hours(), 720);
}

#[test]
fn test_prevalence_time_window_from_str() {
    assert_eq!(
        PrevalenceTimeWindow::from_str("1h"),
        Some(PrevalenceTimeWindow::OneHour)
    );
    assert_eq!(
        PrevalenceTimeWindow::from_str("24h"),
        Some(PrevalenceTimeWindow::TwentyFourHours)
    );
    assert_eq!(
        PrevalenceTimeWindow::from_str("7d"),
        Some(PrevalenceTimeWindow::SevenDays)
    );
    assert_eq!(
        PrevalenceTimeWindow::from_str("30d"),
        Some(PrevalenceTimeWindow::ThirtyDays)
    );
    assert_eq!(PrevalenceTimeWindow::from_str("invalid"), None);
}

#[test]
fn test_prevalence_time_window_as_str() {
    assert_eq!(PrevalenceTimeWindow::OneHour.as_str(), "1h");
    assert_eq!(PrevalenceTimeWindow::TwentyFourHours.as_str(), "24h");
    assert_eq!(PrevalenceTimeWindow::SevenDays.as_str(), "7d");
    assert_eq!(PrevalenceTimeWindow::ThirtyDays.as_str(), "30d");
}
