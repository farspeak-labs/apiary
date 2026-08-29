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

/// A knowledge home names WHERE durable knowledge goes. It is a destination,
/// never a grant: it can only point at a vault the agent already has, and it
/// cannot point outside it.
#[test]
fn a_knowledge_home_is_a_destination_not_a_grant() {
    let manifest = |memory: &str| {
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
memory:
{memory}
governance:
  suspend_keys:
    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg
"#
        ))
    };
    let granted = "  log: local\n  vaults:\n    - name: TeamKB\n      path: /tmp/kb\n";

    // Points at a granted vault: fine.
    let ok = manifest(&format!(
        "{granted}  knowledge_home:\n    vault: TeamKB\n    folder: agent-notes\n"
    ))
    .expect("a home in a granted vault validates");
    let home = ok.memory.knowledge_home.expect("home present");
    assert_eq!(home.vault.as_deref(), Some("TeamKB"));

    // Points at a vault it was never given: refused, and says why.
    let error = manifest(&format!("{granted}  knowledge_home:\n    vault: SomeoneElsesKB\n"))
        .expect_err("cannot write knowledge into a vault it has no access to");
    assert!(error.to_string().contains("has not been granted"), "{error}");
    assert!(error.to_string().contains("destination, not a grant"), "{error}");

    // Cannot escape the vault it was pointed at.
    for bad in ["../elsewhere", "/etc", "notes/../../escape"] {
        let error = manifest(&format!(
            "{granted}  knowledge_home:\n    vault: TeamKB\n    folder: \"{bad}\"\n"
        ))
        .expect_err("traversal must be refused");
        assert!(error.to_string().contains("no traversal"), "{bad}: {error}");
    }

    // Absent is legal — the agent simply has nowhere durable to put things.
    assert!(manifest(granted).unwrap().memory.knowledge_home.is_none());
}

/// The note path is chosen by the host, not the agent: always inside the
/// declared folder, always .md, whatever title it hands over.
#[test]
fn the_host_decides_where_a_remembered_note_lands() {
    use apiary_core::manifest::KnowledgeHome;
    let home = KnowledgeHome {
        vault: Some("TeamKB".into()),
        folder: Some("agent-notes".into()),
        ..Default::default()
    };
    assert_eq!(
        home.note_path("Shrinkage varies by machine"),
        "agent-notes/shrinkage-varies-by-machine.md"
    );
    // Titles that try to steer the path are slugified, not obeyed.
    assert_eq!(
        home.note_path("../../etc/passwd"),
        "agent-notes/etc-passwd.md"
    );
    assert_eq!(home.note_path("  !!!  "), "agent-notes/note.md");
    // No folder: still inside the vault, still markdown.
    let flat = KnowledgeHome {
        vault: Some("TeamKB".into()),
        ..Default::default()
    };
    assert_eq!(flat.note_path("A Fact"), "a-fact.md");
}

/// A knowledge home can point at a knowledge base over MCP instead of a
/// vault. The vault speaks the filesystem, the KB speaks MCP, and neither
/// has to learn the other's protocol — but both are destinations, not grants.
#[test]
fn a_knowledge_home_may_live_in_a_connector_instead_of_a_vault() {
    let manifest = |extra: &str| {
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
      library_name: TeamKB
      transport: http
      url: https://example.invalid/mcp
      allowed_tools: [kb_upsert]
memory:
  log: local
{extra}
governance:
  suspend_keys:
    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg
"#
        ))
    };

    // A granted connector plus the tool that writes: valid.
    let ok = manifest("  knowledge_home:\n    connector: TeamKB\n    tool: kb_upsert\n")
        .expect("a KB home on a granted connector validates");
    let home = ok.memory.knowledge_home.expect("home");
    assert_eq!(home.connector.as_deref(), Some("TeamKB"));
    assert_eq!(home.title_field, "title", "sensible default");
    assert_eq!(home.body_field, "content");

    // Naming the connector without saying which tool writes is refused:
    // knowledge bases do not agree on what it is called.
    let error = manifest("  knowledge_home:\n    connector: TeamKB\n")
        .expect_err("a KB home needs its write tool named");
    assert!(error.to_string().contains("must name the"), "{error}");

    // A connector it was never granted is refused, same as a vault.
    let error = manifest("  knowledge_home:\n    connector: SomeoneElsesKB\n    tool: write\n")
        .expect_err("cannot write knowledge through a connector it lacks");
    assert!(error.to_string().contains("not been granted"), "{error}");
    assert!(error.to_string().contains("destination"), "{error}");

    // Both at once is refused: one place for durable knowledge, not two.
    let error = manifest(
        "  vaults:\n    - name: V\n      path: /tmp/v\n  knowledge_home:\n    vault: V\n    connector: TeamKB\n    tool: kb_upsert\n",
    )
    .expect_err("two homes is no home");
    assert!(error.to_string().contains("pick one place"), "{error}");

    // Neither is refused too.
    let error = manifest("  knowledge_home:\n    folder: notes\n")
        .expect_err("a home must name somewhere");
    assert!(error.to_string().contains("needs a vault or a connector"), "{error}");
}

/// A harness is a capability. Routing can point work at one, but pointing
/// is not granting — otherwise a line in `routing` would hand an agent a
/// coding loop that was never approved as a capability.
#[test]
fn routing_can_only_send_work_to_a_harness_that_was_granted() {
    let manifest = |extra: &str| {
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
{extra}
memory:
  log: local
governance:
  suspend_keys:
    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg
"#
        ))
    };

    let granted = "harnesses:\n  - name: coder\n    command: /usr/local/bin/claude-code-acp\n";

    // Granted, and pointed at: fine.
    let ok = manifest(&format!("  harness: coder\n{granted}")).expect("a granted harness routes");
    assert_eq!(ok.routing.harness.as_deref(), Some("coder"));

    // Pointed at without the grant: refused, and it says why.
    let error = manifest("  harness: coder\n").expect_err("routing cannot invent a capability");
    assert!(error.to_string().contains("not a granted harness"), "{error}");

    // Absent is the normal case — most agents have no harness at all, and
    // their work runs on the native loop.
    assert!(manifest("").unwrap().routing.harness.is_none());
    assert!(manifest(granted).unwrap().routing.harness.is_none());
}
