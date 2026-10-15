fn main() {
    // sqlx::migrate! embeds files known at expansion time. Track directories too
    // so adding an additive migration cannot leave a stale migrator binary.
    println!("cargo:rerun-if-changed=../migrations/postgres");
}
