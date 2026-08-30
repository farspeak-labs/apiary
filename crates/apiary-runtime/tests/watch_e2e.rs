// integration test: watch schema validates + engine detects a real file change
use apiary_core::manifest::Manifest;
use apiary_runtime::watches::{scan_vault, step, Step, WatchRecord};

#[test]
fn a_real_file_change_becomes_a_fire() {
    let root = std::env::temp_dir().join(format!("apiary-watch-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let yaml = format!(
        "manifest_version: 1\nidentity:\n  npub: npub1m8mfxnr32mlkylq9s0cj5l6vheatdu39kaze26e65ptzfr8vudgse6kgv3\n\
         inference:\n  - name: brain\n    provider: mock\nrouting:\n  default: brain\n\
         memory:\n  log: local\n  vaults:\n    - name: Projects\n      path: {}\n\
         governance:\n  suspend_keys:\n    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg\n\
         watches:\n  - name: project-changed\n    on: vault\n    vault: Projects\n    match: PROJECT.md\n    task: Note what changed.\n    debounce: 1s\n    max_per_day: 5\n",
        root.display()
    );
    let m = Manifest::from_yaml(&yaml).expect("watch manifest validates");
    let w = &m.watches[0];
    let mut rec = WatchRecord {
        seen_through: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        ..Default::default()
    };
    // Nothing yet.
    let now = chrono::Utc::now();
    let c0 = scan_vault(&root, rec.seen_through, w.match_path.as_deref());
    assert_eq!(step(w, &mut rec, c0, now), Step::Wait);
    // A real file lands.
    std::fs::write(root.join("PROJECT.md"), "# Apiary voice\nstatus: active\n").unwrap();
    let changes = scan_vault(&root, rec.seen_through, w.match_path.as_deref());
    assert_eq!(
        changes.paths,
        vec!["PROJECT.md".to_string()],
        "the scan sees the new file"
    );
    let t = chrono::Utc::now();
    assert_eq!(
        step(w, &mut rec, changes, t),
        Step::Wait,
        "debounce holds it"
    );
    let later = t + chrono::Duration::seconds(2);
    let c2 = scan_vault(&root, rec.seen_through, w.match_path.as_deref());
    match step(w, &mut rec, c2, later) {
        Step::Fire { paths } => assert_eq!(paths, vec!["PROJECT.md".to_string()]),
        other => panic!("expected a fire once the debounce elapsed, got {other:?}"),
    }
    // An unrelated file is ignored by the filter.
    std::fs::write(root.join("scratch.md"), "x").unwrap();
    let after = scan_vault(&root, rec.seen_through, w.match_path.as_deref());
    assert!(
        after.is_empty(),
        "the match filter holds: {:?}",
        after.paths
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_watch_on_an_ungranted_vault_is_refused() {
    let yaml = "manifest_version: 1\nidentity:\n  npub: npub1m8mfxnr32mlkylq9s0cj5l6vheatdu39kaze26e65ptzfr8vudgse6kgv3\n\
        inference:\n  - name: brain\n    provider: mock\nrouting:\n  default: brain\nmemory:\n  log: local\n\
        governance:\n  suspend_keys:\n    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg\n\
        watches:\n  - name: w\n    on: vault\n    vault: NotGranted\n    task: look\n";
    let error = Manifest::from_yaml(yaml).expect_err("cannot watch what it was never given");
    assert!(
        error.to_string().contains("has not been granted"),
        "{error}"
    );
}
