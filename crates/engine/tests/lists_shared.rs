//! The shared list files (`policy/shared/`, shared contract §1): embedded byte-for-byte, every
//! file parses, MANIFEST counts and hashes match, and the seeded counts are pinned.

use std::path::PathBuf;

use safe_ai_skill::lists::{self, CredClass, Os, SbTier, VerbClass, VerbCluster};
use safe_ai_skill::policy::tier::Tier;

fn shared(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../policy/shared")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn lists_embedded_equal_policy_shared_byte_for_byte() {
    assert_eq!(lists::CREDENTIALS_LIST, shared("credentials.list"));
    assert_eq!(lists::EXFIL_HOSTS_LIST, shared("exfil-hosts.list"));
    assert_eq!(lists::ONCHAIN_VERBS_LIST, shared("onchain-verbs.list"));
    assert_eq!(lists::MANIFEST, shared("MANIFEST"));
}

#[test]
fn lists_every_file_parses_and_the_manifest_matches() {
    let all = lists::lists().expect("embedded lists parse and match MANIFEST");
    assert_eq!(all.contract, "1.2.0");
    assert_eq!(all.manifest_sha256.len(), 64);
    assert_eq!(all.credentials.len(), 66);
    assert_eq!(all.exfil_hosts.len(), 84);
    assert_eq!(all.verbs.len(), 43);
}

#[test]
fn lists_manifest_mismatch_is_unavailable() {
    let manifest = lists::MANIFEST.replace("exfil-hosts.list 84", "exfil-hosts.list 83");
    assert!(lists::parse_all(
        lists::CREDENTIALS_LIST,
        lists::EXFIL_HOSTS_LIST,
        lists::ONCHAIN_VERBS_LIST,
        &manifest
    )
    .is_err());
    let edited = lists::EXFIL_HOSTS_LIST.replace("relaxed webhook.site", "relaxed webhook.sitf");
    assert!(lists::parse_all(
        lists::CREDENTIALS_LIST,
        &edited,
        lists::ONCHAIN_VERBS_LIST,
        lists::MANIFEST
    )
    .is_err());
}

#[test]
fn lists_exfil_host_counts_are_pinned_per_tier() {
    assert_eq!(lists::exfil_hosts(Tier::Off).unwrap().len(), 0);
    assert_eq!(lists::exfil_hosts(Tier::Relaxed).unwrap().len(), 70);
    assert_eq!(lists::exfil_hosts(Tier::Medium).unwrap().len(), 79);
    assert_eq!(lists::exfil_hosts(Tier::High).unwrap().len(), 84);
    let relaxed = lists::exfil_hosts(Tier::Relaxed).unwrap();
    assert!(relaxed.contains(&"webhook.site") && relaxed.contains(&"*.ngrok-free.app"));
    assert!(!relaxed.contains(&"api.telegram.org"));
    assert!(lists::exfil_hosts(Tier::High)
        .unwrap()
        .contains(&"*.vercel.app"));
}

#[test]
fn lists_kit_derived_credentials_are_pinned() {
    let creds = lists::credentials().unwrap();
    let in_section = |s: &str| creds.iter().filter(|c| c.section == s).count();
    assert_eq!(in_section("kit:SB_CREDENTIALS"), 13);
    assert_eq!(in_section("kit:SB_HOST_CREDENTIALS"), 10);
    assert_eq!(in_section("kit:SB_BROWSER_STORES"), 22);
    assert_eq!(in_section("plugin"), 21);
    let find = |g: &str| {
        creds
            .iter()
            .find(|c| c.glob == g)
            .unwrap_or_else(|| panic!("{g}"))
    };
    // Contract fixes: id.json is never sandbox-denied, ~/.aws is from Relaxed.
    assert_eq!(find("~/.config/solana/id.json").sb, SbTier::Never);
    assert_eq!(find("~/.aws/").sb, SbTier::Relaxed);
    assert_eq!(find("~/.npmrc").class, CredClass::HostToken);
    assert_eq!(find("~/.npmrc").sb, SbTier::Medium);
    assert_eq!(find("~/.kube/config").class, CredClass::KeyMaterial);
    // Contract 1.1.0: cloud and infrastructure CLI token stores.
    for g in [
        "~/.config/gcloud/",
        "~/.azure/",
        "~/.config/doctl/",
        "~/.terraform.d/credentials.tfrc.json",
        "~/.config/helm/",
        "~/.vault-token",
    ] {
        let c = find(g);
        assert_eq!(
            (c.class, c.sb, c.exception),
            (CredClass::HostToken, SbTier::Medium, false),
            "{g}"
        );
    }
    let chrome = find("~/AppData/Local/Google/Chrome/User Data/");
    assert_eq!(
        (chrome.class, chrome.os),
        (CredClass::BrowserStore, Os::Windows)
    );
    assert_eq!(
        find("**/Local Extension Settings/").class,
        CredClass::WalletExt
    );
    // Q1: ssh config, known_hosts and public keys are readable exceptions.
    for g in [
        "~/.ssh/config",
        "~/.ssh/known_hosts",
        "~/.ssh/*.pub",
        "~/.config/solana/cli/config.yml",
    ] {
        assert!(find(g).exception, "{g}");
    }
    assert!(!find("~/.ssh/").exception);
}

#[test]
fn lists_onchain_verbs_split_by_class() {
    let irreversible = lists::irreversible().unwrap();
    let recoverable = lists::recoverable().unwrap();
    assert_eq!(irreversible.len() + recoverable.len(), 43);
    assert!(irreversible
        .iter()
        .all(|v| v.class == VerbClass::Irreversible));
    let shape = |v: &&lists::Verb| v.argv.join(" ");
    let u: Vec<String> = irreversible.iter().map(shape).collect();
    for row in [
        "solana program deploy [--final]",
        "solana program-v4 finalize",
        "spl-token authorize [--disable]",
        "spl-token burn",
        "anchor idl erase-authority",
        "solana close-vote-account",
    ] {
        assert!(u.contains(&row.to_string()), "{row}");
    }
    let keygen: Vec<&&lists::Verb> = irreversible
        .iter()
        .filter(|v| v.cluster == VerbCluster::Any)
        .collect();
    assert!(!keygen.is_empty() && keygen.iter().all(|v| v.argv[0] == "solana-keygen"));
    let c: Vec<String> = recoverable.iter().map(shape).collect();
    assert!(c.contains(&"solana transfer".to_string()));
    assert!(!u.contains(&"solana transfer".to_string()));
}

#[test]
fn lists_parsers_reject_bad_records() {
    for bad in [
        "[plugin]\nkey_material any never\n",
        "[plugin]\nsecret any never ~/.x\n",
        "[plugin]\nkey_material bsd never ~/.x\n",
        "[plugin]\nkey_material any sometimes ~/.x\n",
        "[plugin]\nkey_material any never ~/.{a,b}\n",
    ] {
        assert!(lists::parse_credentials(bad).is_err(), "{bad:?}");
    }
    for bad in [
        "relaxed\n",
        "low x.io\n",
        "relaxed X.io\n",
        "relaxed x.io.\n",
    ] {
        assert!(lists::parse_exfil_hosts(bad).is_err(), "{bad:?}");
    }
    for bad in [
        "irreversible net solana\n",
        "fatal net solana close\n",
        "irreversible mainnet solana close\n",
    ] {
        assert!(lists::parse_onchain_verbs(bad).is_err(), "{bad:?}");
    }
    assert!(lists::parse_credentials(
        "# c\n\n[plugin]\nkey_material any relaxed ${CLAUDE_CONFIG_DIR:-~/.claude}/.credentials.json\n"
    )
    .is_ok());
}
