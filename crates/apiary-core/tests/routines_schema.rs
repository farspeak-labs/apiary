use apiary_core::manifest::Manifest;

fn with(routines: &str) -> Result<Manifest, apiary_core::Error> {
    Manifest::from_yaml(&format!(
        r#"
manifest_version: 1
identity:
  npub: npub1m8mfxnr32mlkylq9s0cj5l6vheatdu39kaze26e65ptzfr8vudgse6kgv3
inference:
  - name: brain
    provider: mock
routing:
  default: brain
connectors: []
memory:
  log: local
presence:
  telegram:
    allowed_chats: ["1"]
governance:
  suspend_keys:
    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg
routines:
{routines}
"#
    ))
}

#[test]
fn routines_validate_shape_and_targets() {
    assert!(with("  - name: ok\n    when: \"0 8 * * *\"\n    tz: America/Chicago\n    task: hi\n    deliver:\n      - telegram: \"1\"\n").is_ok());
    assert!(
        with("  - name: notz\n    when: \"0 8 * * *\"\n    task: hi\n").is_err(),
        "cron needs tz"
    );
    assert!(
        with("  - name: two\n    when: \"0 8 * * *\"\n    every: 5m\n    tz: UTC\n    task: hi\n")
            .is_err(),
        "one spelling"
    );
    assert!(
        with(
            "  - name: nobuzz\n    every: 5m\n    task: hi\n    deliver:\n      - buzz: general\n"
        )
        .is_err(),
        "no buzz presence"
    );
    assert!(
        with("  - name: e\n    every: 5m\n    task: hi\n").is_ok(),
        "every needs no tz"
    );
    assert!(
        with("  - name: cu\n    every: 5m\n    task: hi\n    catch_up: all\n").is_err(),
        "catch_up none|one"
    );
    let m = with("  - name: ok\n    every: 5m\n    task: hi\n").unwrap();
    assert_eq!(m.routines[0].class, "routine");
    assert!(m.routines[0].enabled);
}

#[test]
fn mcp_connector_without_allowlist_is_valid_but_inert() {
    let m = |caps: &str| {
        Manifest::from_yaml(&format!(
            r#"
manifest_version: 1
identity:
  npub: npub1m8mfxnr32mlkylq9s0cj5l6vheatdu39kaze26e65ptzfr8vudgse6kgv3
inference:
  - name: brain
    provider: mock
routing:
  default: brain
connectors:
  - type: mcp
    caps:
{caps}
memory:
  log: local
governance:
  suspend_keys:
    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg
"#
        ))
    };
    // A fresh grant (or an OAuth re-connect, which re-grants) copies the
    // library entry, which has no allowlist yet — that must VALIDATE, or
    // granting an MCP connector is impossible. It just binds no tools.
    let bare = m("      transport: stdio\n      command: npx\n").unwrap();
    assert!(
        bare.connectors[0].grants_no_tools(),
        "no allowlist = inert, and detectably so"
    );
    let with_tools =
        m("      transport: stdio\n      command: npx\n      allowed_tools: [read_file]\n")
            .unwrap();
    assert!(!with_tools.connectors[0].grants_no_tools());
    let with_access = m("      transport: stdio\n      command: npx\n      tool_access:\n        read_file: read-only\n").unwrap();
    assert!(!with_access.connectors[0].grants_no_tools());
    let empty_list =
        m("      transport: stdio\n      command: npx\n      allowed_tools: []\n").unwrap();
    assert!(
        empty_list.connectors[0].grants_no_tools(),
        "empty list is no allowlist"
    );
}
