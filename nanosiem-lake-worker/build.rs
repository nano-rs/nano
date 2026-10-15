fn main() {
    // Integration tests embed both migration chains with sqlx::migrate!.
    println!("cargo:rerun-if-changed=../migrations/postgres");
}
