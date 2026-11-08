use super::*;

#[test]
fn rows_keep_the_max_per_normalized_value_and_drop_zero() {
    let w = EntityScoreWeights::from_rows([
        ("Alice ".to_string(), 25),
        ("alice".to_string(), 60),
        ("bob".to_string(), 0),
        (" ".to_string(), 50),
    ]);
    assert_eq!(w.weight("ALICE"), 0.6);
    assert_eq!(w.weight("bob"), 0.0);
    assert_eq!(w.len(), 1);
}

#[test]
fn parallel_arrays_carry_a_typing_sentinel() {
    let (e, w) = EntityScoreWeights::default().parallel_arrays();
    assert_eq!((e, w), (vec![String::new()], vec![0.0]));
    let (e, w) = EntityScoreWeights::from_rows([("x".to_string(), 50)]).parallel_arrays();
    assert_eq!(e, vec!["x".to_string(), String::new()]);
    assert_eq!(w, vec![0.5, 0.0]);
}

#[test]
fn weighted_score_rounds_half_to_even() {
    assert_eq!(weighted_score(100, 0.0), 100);
    assert_eq!(weighted_score(100, 0.6), 160);
    assert_eq!(weighted_score(3, 0.5), 4);
    assert_eq!(weighted_score(5, 0.5), 8);
    assert_eq!(weighted_score(7, f64::NAN), 7);
}
