//! Golden regression corpus for rule precision.
//!
//! Each fixture in `tests/fixtures/` pins one of the false-positive root
//! causes found scanning Halo CMS:
//!
//! * RC1 — SnakeYAML `.load()` matched on the method name without resolving
//!   the receiver type (5 false positives).
//! * RC2 — `enableDefaultTyping` matched on the bare method name, hitting
//!   Spring Security's hardened wrapper (1 false positive).
//! * RC3 — hardcoded-secret matched on the identifier name without inspecting
//!   the value (5 false positives).
//! * RC4 — no trust-boundary awareness: local-filesystem and plugin inputs
//!   ranked as if they were attacker-controlled (3 over-rated findings).
//!
//! Negative fixtures must produce no finding for the named rule. Positive
//! fixtures must still produce one, so a precision fix cannot silently become
//! a recall regression.

use javscan::config::Config;
use javscan::findings::{Finding, Severity, TrustSource};
use javscan::scanner::{scan, ScanOptions};
use std::path::PathBuf;

fn scan_fixture(relative: &str) -> Vec<Finding> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative);
    assert!(path.exists(), "fixture not found: {}", path.display());
    let opts = ScanOptions {
        paths: vec![path],
        exclude: Vec::new(),
        // fixtures live under tests/, which the default heuristics skip
        include_tests: true,
        parallel: false,
        disabled_rules: Vec::new(),
    };
    let (findings, _) = scan(&opts, &Config::default());
    findings
}

fn of_rule<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.rule_id == rule).collect()
}

fn assert_no_finding(fixture: &str, rule: &str) {
    let findings = scan_fixture(fixture);
    let hits = of_rule(&findings, rule);
    assert!(
        hits.is_empty(),
        "{fixture}: expected no {rule} finding, got {}: {:?}",
        hits.len(),
        hits.iter().map(|f| (f.line, &f.message)).collect::<Vec<_>>()
    );
}

fn assert_fires(fixture: &str, rule: &str) -> Vec<Finding> {
    let findings = scan_fixture(fixture);
    let hits = of_rule(&findings, rule);
    assert!(
        !hits.is_empty(),
        "{fixture}: expected a {rule} finding, got none (recall regression)"
    );
    hits.into_iter().cloned().collect()
}

// ---------------------------------------------------------------------------
// RC1 — SnakeYAML receiver-type resolution
// ---------------------------------------------------------------------------

#[test]
fn yaml_processor_subclass_does_not_fire() {
    // Halo's YamlUnstructuredLoader shape: extends Spring's YamlProcessor,
    // which builds its Yaml with a SafeConstructor.
    assert_no_finding("negative/YamlSafeWrapper.java", "JS501");
}

#[test]
fn cross_file_yaml_wrapper_does_not_fire() {
    // The real Halo shape: the wrapper is declared in another compilation
    // unit, so the supertype is invisible. The receiver still resolves to a
    // type that is not `org.yaml.snakeyaml.Yaml`, which is enough.
    assert_no_finding("negative/CrossFileYamlWrapper.java", "JS501");
}

#[test]
fn yaml_with_safe_constructor_does_not_fire() {
    assert_no_finding("negative/SafeConstructorYaml.java", "JS501");
}

#[test]
fn yaml_with_permissive_constructor_fires() {
    let hits = assert_fires("positive/UnsafeYaml.java", "JS501");
    assert_eq!(hits[0].severity, Severity::Critical);
}

// ---------------------------------------------------------------------------
// RC2 — Jackson default typing owner resolution
// ---------------------------------------------------------------------------

#[test]
fn spring_security_default_typing_does_not_fire() {
    assert_no_finding("negative/SecurityJacksonModule.java", "JS501");
}

#[test]
fn laissez_faire_default_typing_fires() {
    let hits = assert_fires("positive/LaissezFaireMapper.java", "JS501");
    // both activateDefaultTyping(LaissezFaire) and enableDefaultTyping()
    assert_eq!(hits.len(), 2, "expected both mapper calls flagged: {hits:?}");
}

// ---------------------------------------------------------------------------
// RC3 — hardcoded-secret value gate
// ---------------------------------------------------------------------------

#[test]
fn label_constants_do_not_fire() {
    // Secret type discriminator, validation regex, token prefix, event id,
    // problem-detail URI — all five Halo false positives.
    assert_no_finding("negative/Discriminators.java", "JS401");
}

#[test]
fn real_key_material_fires() {
    let hits = assert_fires("positive/RealSecrets.java", "JS401");
    assert_eq!(hits.len(), 3, "expected all three secrets flagged: {hits:?}");
}

// ---------------------------------------------------------------------------
// JS105 — EvaluationContext resolution
// ---------------------------------------------------------------------------

#[test]
fn simple_evaluation_context_does_not_fire() {
    assert_no_finding("negative/SimpleSpel.java", "JS105");
}

#[test]
fn standard_evaluation_context_fires_at_full_severity() {
    let hits = assert_fires("positive/StandardSpel.java", "JS105");
    assert_eq!(hits[0].severity, Severity::Critical);
    assert_eq!(hits[0].source, TrustSource::Network);
}

// ---------------------------------------------------------------------------
// RC4 — trust-source tagging
// ---------------------------------------------------------------------------

#[test]
fn self_serialized_roundtrip_is_downranked() {
    let hits = assert_fires("negative/SelfSerializedIndex.java", "JS501");
    assert_eq!(hits[0].source, TrustSource::LocalFs);
    // Deprioritized, not erased: the API is still dangerous, so the trusted
    // source floors at LOW rather than sinking into INFO.
    assert_eq!(hits[0].severity, Severity::Low);
    assert!(
        hits[0].message.contains("local write access"),
        "expected the finding to explain why it was downranked: {}",
        hits[0].message
    );
}

#[test]
fn plugin_supplied_class_name_is_downranked() {
    let hits = assert_fires("negative/PluginReflection.java", "JS702");
    assert_eq!(hits[0].source, TrustSource::Plugin);
    assert_eq!(hits[0].severity, Severity::Low);
}

#[test]
fn snakeyaml_2_downgrades_default_yaml_but_not_permissive_constructor() {
    // The version gate is project-level: it relaxes a bare `new Yaml()` only.
    let findings = scan_fixture("versioned");
    let hits = of_rule(&findings, "JS501");
    let by_severity: Vec<_> = hits.iter().map(|f| f.severity).collect();
    assert!(
        by_severity.contains(&Severity::Info),
        "bare `new Yaml()` should be INFO on SnakeYAML >= 2.0: {hits:?}"
    );
    assert!(
        by_severity.contains(&Severity::Critical),
        "an explicit permissive Constructor stays CRITICAL regardless of version: {hits:?}"
    );
}

// ---------------------------------------------------------------------------
// Value-gate unit checks
// ---------------------------------------------------------------------------

#[test]
fn value_gate_classifies_halo_constants_as_non_secret() {
    use javscan::rules::secrets::{classify_value, ValueVerdict};
    for v in [
        "Opaque",
        "^[A-Za-z0-9!@#$%^&*.?]+$",
        "pat_",
        "reset-password-by-email",
        "https://halo.run/probs/invalid-credential",
    ] {
        assert_eq!(
            classify_value(v, false),
            ValueVerdict::NotSecret,
            "expected {v:?} to be rejected by the value gate"
        );
    }
}

#[test]
fn value_gate_accepts_key_material() {
    use javscan::rules::secrets::{classify_value, ValueVerdict};
    for v in [
        "s7Kd93MzQpXv2LbNr8YtWc4HgJf6DaEu",
        "my-jwt-signing-secret-key-2024",
    ] {
        assert_eq!(
            classify_value(v, true),
            ValueVerdict::Keylike,
            "expected {v:?} to be accepted as key material"
        );
    }
}

// ---------------------------------------------------------------------------
// RC5 — precision fixes from the OpenRefine / CommaFeed / SkyWalking scan
// ---------------------------------------------------------------------------

#[test]
fn algorithm_name_is_not_key_material() {
    // `new SecretKeySpec(randomBytes(32), "AES")` — the literal is the
    // algorithm, never the key.
    assert_no_finding("negative/RandomKeySpec.java", "JS304");
}

#[test]
fn baked_in_key_material_still_fires() {
    let hits = assert_fires("positive/HardcodedKeySpec.java", "JS304");
    assert_eq!(hits.len(), 3, "expected all three hardcoded keys: {hits:?}");
}

#[test]
fn bound_parameters_are_not_sql_injection() {
    assert_no_finding("negative/ParameterizedDao.java", "JS101");
}

#[test]
fn concatenated_values_still_fire_as_sql_injection() {
    let hits = assert_fires("positive/ConcatenatedSql.java", "JS101");
    assert_eq!(hits.len(), 2, "expected both concatenations: {hits:?}");
    assert!(hits.iter().all(|f| f.severity >= Severity::High));
}

#[test]
fn web_noise_fixtures_do_not_fire() {
    for rule in ["JS203", "JS204", "JS207", "JS701"] {
        assert_no_finding("negative/WebNoise.java", rule);
    }
    // `private` contains `iv`, but that is not a security-sensitive context:
    // the Random finding stays informational instead of being promoted.
    let hits = assert_fires("negative/WebNoise.java", "JS303");
    assert!(
        hits.iter().all(|f| f.severity <= Severity::Low),
        "`private` must not imply a security context: {hits:?}"
    );
}

#[test]
fn pem_header_constants_are_not_secrets() {
    assert_no_finding("negative/PemHeaders.java", "JS401");
}

#[test]
fn service_loader_is_not_a_yaml_sink() {
    let hits = assert_fires("negative/ServiceLoaderYaml.java", "JS501");
    assert_eq!(
        hits.len(),
        1,
        "only the real `new Yaml().load()` should fire: {hits:?}"
    );
    assert!(
        hits[0].snippet.contains("Yaml"),
        "wrong call anchored: {}",
        hits[0].snippet
    );
}

#[test]
fn whole_string_regex_validation_kills_taint() {
    assert_no_finding("negative/RegexValidated.java", "JS201");
}

#[test]
fn unvalidated_reflection_still_fires() {
    let hits = assert_fires("positive/ReflectedEcho.java", "JS201");
    assert_eq!(
        hits.len(),
        2,
        "raw echo and a `find()`-only check must both fire: {hits:?}"
    );
}

#[test]
fn findings_anchor_at_the_sink_not_the_receiver_chain() {
    let hits = assert_fires("positive/ChainedSink.java", "JS101");
    assert!(
        hits[0].snippet.contains("executeQuery"),
        "expected the snippet to show the sink line, got {:?}",
        hits[0].snippet
    );
}

#[test]
fn name_role_gate_rejects_domain_nouns() {
    use javscan::rules::secrets::has_non_secret_role;
    assert!(has_non_secret_role("SECRET_TYPE_OPAQUE"));
    assert!(has_non_secret_role("PASSWORD_REGEX"));
    assert!(has_non_secret_role("PAT_TOKEN_PREFIX"));
    assert!(has_non_secret_role("RESET_PASSWORD_BY_EMAIL_REASON_TYPE"));
    assert!(has_non_secret_role("INVALID_CREDENTIAL_TYPE"));
    // camelCase forms too
    assert!(has_non_secret_role("passwordRegex"));
    assert!(has_non_secret_role("tokenPrefix"));
    // real credential names must survive
    assert!(!has_non_secret_role("JWT_SECRET"));
    assert!(!has_non_secret_role("apiKey"));
    assert!(!has_non_secret_role("clientSecret"));
}
