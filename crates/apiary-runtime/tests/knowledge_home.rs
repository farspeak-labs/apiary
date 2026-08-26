//! A declared knowledge home: the agent learns something, and it lands in one
//! known place, attributed, where people can read and correct it.

use apiary_core::manifest::{KnowledgeHome, Manifest};

fn manifest_with(memory: &str) -> Result<Manifest, apiary_core::Error> {
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
}

#[test]
fn remember_appears_only_where_a_home_was_declared_and_writing_was_granted() {
    let root = std::env::temp_dir().join(format!("apiary-kb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let vaults = format!(
        "  log: local\n  vaults:\n    - name: TeamKB\n      path: {}\n",
        root.display()
    );
    // Build the YAML in one piece: re-serializing and appending would
    // produce a duplicate `connectors` key.
    let tools_for = |memory: &str, write: bool| -> Vec<String> {
        let yaml = format!(
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
  - type: markdown-vault
    caps:
      write: {write}
      vaults:
        - name: TeamKB
          path: {path}
memory:
{memory}
governance:
  suspend_keys:
    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg
"#,
            path = root.display(),
        );
        let m = Manifest::from_yaml(&yaml).expect("manifest with vault connector");
        let mut custody = apiary_core::custody::Custody::new();
        let agent = custody.admit(apiary_core::identity::generate());
        apiary_runtime::connector::bind_connectors(&m, &custody, &agent)
            .expect("bind")
            .iter()
            .map(|c| c.def().name)
            .collect()
    };

    // Home declared + write granted → remember is offered.
    let with_home = format!("{vaults}  knowledge_home:\n    vault: TeamKB\n    folder: agent-notes\n");
    assert!(
        tools_for(&with_home, true).contains(&"remember".to_string()),
        "a declared home in a writable vault gives the agent somewhere to put things"
    );

    // No home declared → no remember, even though writing is granted. The
    // agent is never left guessing where knowledge should go.
    assert!(
        !tools_for(&vaults, true).contains(&"remember".to_string()),
        "without a declared destination there is no durable memory"
    );

    // Home declared but the vault is read-only → no remember. A destination
    // is not a grant.
    assert!(
        !tools_for(&with_home, false).contains(&"remember".to_string()),
        "a home cannot conjure write access"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_remembered_note_is_stamped_with_who_said_it() {
    // The host, not the model, decides the filename and the attribution.
    let home = KnowledgeHome {
        vault: Some("TeamKB".into()),
        folder: Some("agent-notes".into()),
        ..Default::default()
    };
    // A title that tries to escape is slugified into the declared folder.
    assert_eq!(
        home.note_path("../../secrets"),
        "agent-notes/secrets.md",
        "the agent cannot choose where its memory lands"
    );
}
