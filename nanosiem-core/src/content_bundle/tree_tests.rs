// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn files(entries: &[(&str, &str)]) -> Files {
    entries.iter().map(|(p, c)| (p.to_string(), c.as_bytes().to_vec())).collect()
}

#[test]
fn git_blob_sha1_matches_git() {
    // `printf 'hello\n' | git hash-object --stdin`
    assert_eq!(git_blob_sha1(b"hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a");
    // empty blob
    assert_eq!(git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
}

#[test]
fn pack_is_deterministic_and_round_trips() {
    let f = files(&[("parsers/a/parser.yaml", "name: a\n"), ("README.md", "x"), ("rules/b.yml", "id: b\n")]);
    let one = pack(&f).unwrap();
    let two = pack(&f).unwrap();
    assert_eq!(one, two, "same tree must give byte-identical payload");
    assert_eq!(unpack(&one).unwrap(), f);
    assert_eq!(summarize(&f), summarize(&unpack(&one).unwrap()));
}

#[test]
fn long_paths_round_trip() {
    let long = format!("{}/parser.yaml", "d".repeat(200));
    let f = files(&[(long.as_str(), "x")]);
    assert_eq!(unpack(&pack(&f).unwrap()).unwrap(), f);
}

#[test]
fn unsafe_paths_are_refused() {
    for bad in ["../etc/passwd", "/abs", "a//b", "a/./b", "a\\b", "", "a/../b"] {
        assert!(!path_ok(bad), "{bad:?} must be refused");
    }
    assert!(path_ok("parsers-ocsf/okta/parser.yaml"));
}

fn raw_tar(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    build(&mut b);
    let tar = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

#[test]
fn unpack_refuses_symlinks_traversal_and_duplicates() {
    let link = raw_tar(|b| {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "evil", "/etc/passwd").unwrap();
    });
    assert!(matches!(unpack(&link), Err(TreeError::Invalid(_))));

    let traversal = raw_tar(|b| {
        let mut h = tar::Header::new_old();
        h.set_size(1);
        h.set_entry_type(tar::EntryType::Regular);
        // bypass the builder's own path checks
        let name = b"../x";
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_cksum();
        b.append(&h, &b"y"[..]).unwrap();
    });
    assert!(unpack(&traversal).is_err());

    let dup = raw_tar(|b| {
        for _ in 0..2 {
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, "a.txt", &b"z"[..]).unwrap();
        }
    });
    assert!(matches!(unpack(&dup), Err(TreeError::Invalid(m)) if m.contains("duplicate")));
}

