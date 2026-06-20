// SPDX-License-Identifier: Apache-2.0
//! Attribute-release CEL adapter.
//!
//! Registry Relay evaluates two kinds of operator-authored CEL expressions for
//! identity attribute release:
//!
//! * **release predicates** (e.g. `deceased == false`) that gate whether a
//!   subject's claims may be released at all, and
//! * **computed claim scalars** (e.g. `given_name + ' ' + surname`) that derive
//!   a single claim value from a subject's source fields.
//!
//! Rather than introduce a second expression language, this module reuses the
//! existing crosswalk mapping runtime (the same engine that backs SP DCI and
//! PublicSchema response mapping). Each expression is carried inside a
//! synthesized single-field SP DCI-shape mapping document, compiled at config
//! load and evaluated at request time over the subject row. The single output
//! field is read back as a `bool` (predicate) or a raw [`serde_json::Value`]
//! (scalar).
//!
//! Privacy and fail-closed posture:
//!
//! * Compile failures are surfaced at config load as [`AttributeReleaseError::Compile`].
//! * Any evaluation error, any non-empty mapping `errors` set, or a missing /
//!   wrong-typed output field fails **closed**: a predicate never silently
//!   evaluates to `true` and a computed claim is never silently dropped.
//! * Diagnostics are value-free. Error `Display` and any tracing output reuse
//!   the PII-free discipline of `spdci::mapping_issue_diagnostics`: they carry
//!   structural locators (paths, kinds) only, never source values or the
//!   expression text.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttributeReleaseError {
    /// The CEL expression failed to compile (config-load time). PII-free.
    #[error("attribute-release expression failed to compile")]
    Compile(String),
    /// The CEL expression failed to evaluate, or the mapping runtime reported
    /// one or more errors. Fail-closed. PII-free.
    #[error("attribute-release expression evaluation failed")]
    Eval(String),
    /// The mapping produced no value for the synthesized output field. A
    /// missing predicate or claim value fails closed. PII-free.
    #[error("attribute-release expression produced no value")]
    MissingField(String),
    /// The mapping produced a value of the wrong type (e.g. a predicate that
    /// did not resolve to a boolean). Fail-closed. PII-free.
    #[error("attribute-release expression produced a value of the wrong type")]
    TypeMismatch(String),
}

#[cfg(feature = "attribute-release")]
pub use enabled::{
    evaluate_release_predicate, evaluate_release_scalar, validate_release_expression,
};

#[cfg(feature = "attribute-release")]
mod enabled {
    use super::AttributeReleaseError;

    use std::collections::HashMap;
    use std::sync::{Arc, OnceLock, RwLock};

    use serde_json::{json, Value};

    use crosswalk_core::{
        CompiledMapping, EvaluationInput, MappingError, MappingRuntime, RuntimeOptions,
    };

    /// The synthesized output record name and the single field name carried by
    /// the one-field mapping document. Centralized so the document grammar is
    /// trivially adjustable in one place.
    const RECORD_NAME: &str = "release";
    const FIELD_NAME: &str = "value";

    /// Compile-only validation hook used at config load. Fails closed: an
    /// expression that does not compile is rejected before the runtime serves
    /// any request.
    pub fn validate_release_expression(cel: &str) -> Result<(), AttributeReleaseError> {
        let runtime = MappingRuntime::new(RuntimeOptions::default());
        compile(&runtime, cel).map(|_| ())
    }

    /// Evaluate a release **predicate** over a subject record. Fails closed:
    /// compile error, evaluation error, missing field, or a non-boolean result
    /// all return `Err` rather than a permissive `true`.
    pub fn evaluate_release_predicate(
        cel: &str,
        record: &Value,
    ) -> Result<bool, AttributeReleaseError> {
        let value = evaluate_single_field(cel, record)?;
        match value.as_bool() {
            Some(b) => Ok(b),
            None => Err(AttributeReleaseError::TypeMismatch(
                predicate_type_diagnostic(&value),
            )),
        }
    }

    /// Evaluate a computed-claim **scalar** over a subject record, returning the
    /// raw [`Value`]. Fails closed: a missing or erroring expression returns
    /// `Err` rather than silently dropping the claim. A JSON `null` result is
    /// treated as a missing value (fail-closed) so an absent computed claim is
    /// never silently emitted as `null`.
    pub fn evaluate_release_scalar(
        cel: &str,
        record: &Value,
    ) -> Result<Value, AttributeReleaseError> {
        let value = evaluate_single_field(cel, record)?;
        if value.is_null() {
            return Err(AttributeReleaseError::MissingField(
                "field=value kind=null".to_string(),
            ));
        }
        Ok(value)
    }

    /// Synthesize the one-field document, compile it (once, cached), evaluate it
    /// against `record`, and read the single output field back. Shared by both
    /// the predicate and scalar entry points so the fail-closed handling is
    /// identical.
    ///
    /// CEL is compiled lazily on first use and cached process-wide by expression
    /// text (see [`compiled_mapping`]); subsequent resolves reuse the compiled
    /// mapping instead of recompiling on the identity hot path. This matches the
    /// caching the SP DCI / PublicSchema mappers already do.
    fn evaluate_single_field(cel: &str, record: &Value) -> Result<Value, AttributeReleaseError> {
        let mapping = compiled_mapping(cel)?;

        let out = shared_runtime().evaluate(
            &mapping,
            EvaluationInput {
                source: record.clone(),
                context: json!({}),
            },
        );

        if !out.errors.is_empty() {
            return Err(AttributeReleaseError::Eval(issue_diagnostics(&out.errors)));
        }

        // A false predicate may surface as zero records (emit suppressed) rather
        // than a false-valued field; both forms must be distinguishable from an
        // erroring evaluation. We read the single output field back and treat an
        // absent field as a fail-closed MissingField. The predicate wrapper maps
        // a missing field to deny; the scalar wrapper maps it to drop-as-error.
        // CI-VERIFY: confirm against CROSSWALK_REF whether a false predicate
        // yields a `false`-valued record field or zero records; if zero-record,
        // callers translate MissingField → deny (still fail-closed).
        read_single_field(out.records)
    }

    /// Process-wide runtime used to both compile and evaluate cached mappings, so
    /// each mapping is evaluated by the runtime that compiled it. `evaluate` takes
    /// `&self`, and the SP DCI adapter already shares one `MappingRuntime` across
    /// concurrent requests, so a single shared instance is safe here.
    fn shared_runtime() -> &'static MappingRuntime {
        static RUNTIME: OnceLock<MappingRuntime> = OnceLock::new();
        RUNTIME.get_or_init(|| MappingRuntime::new(RuntimeOptions::default()))
    }

    /// The compiled-mapping cache, keyed by raw CEL expression text.
    fn cel_cache() -> &'static RwLock<HashMap<String, Arc<CompiledMapping>>> {
        static CACHE: OnceLock<RwLock<HashMap<String, Arc<CompiledMapping>>>> = OnceLock::new();
        CACHE.get_or_init(|| RwLock::new(HashMap::new()))
    }

    /// Compile `cel` once and cache the resulting `Arc<CompiledMapping>` by
    /// expression text, returning a clone on later calls. CEL only ever comes from
    /// validated config (a finite set), so the cache is bounded by configuration
    /// size, never by request data. Compilation is the expensive step; caching it
    /// removes the per-resolve recompile from the identity auth path. This mirrors
    /// the `Arc<CompiledMapping>` caching the SP DCI adapter already uses.
    fn compiled_mapping(cel: &str) -> Result<Arc<CompiledMapping>, AttributeReleaseError> {
        let cache = cel_cache();
        // Fast path: an explicit scope drops the read guard before the (rare)
        // write lock below, so we never hold a read lock across a write.
        {
            let guard = cache.read().unwrap_or_else(|poison| poison.into_inner());
            if let Some(mapping) = guard.get(cel) {
                return Ok(Arc::clone(mapping));
            }
        }
        // Slow path: compile and insert. A concurrent double-compile is collapsed
        // to a single stored value by the entry API, keeping one mapping per
        // distinct expression.
        let mapping = Arc::new(compile(shared_runtime(), cel)?);
        let mut guard = cache.write().unwrap_or_else(|poison| poison.into_inner());
        let entry = guard.entry(cel.to_string()).or_insert(mapping);
        Ok(Arc::clone(entry))
    }

    /// Compile the synthesized document, mapping any compile error to a
    /// PII-free [`AttributeReleaseError::Compile`].
    ///
    /// The compile-error type is bound only by `Display` (the discipline proven
    /// by the existing call sites in `spdci.rs` / `config/validate.rs`, which
    /// only ever render `compile_mapping`'s error via `%err`). We deliberately
    /// discard the rendered message — crosswalk compile errors can embed the
    /// failing expression text — and keep a fixed structural marker so operator
    /// CEL never reaches logs or error bodies.
    fn compile(
        runtime: &MappingRuntime,
        cel: &str,
    ) -> Result<CompiledMapping, AttributeReleaseError> {
        let doc = synthesize_document(cel);
        runtime
            .compile_mapping(&doc)
            .map_err(|_err| AttributeReleaseError::Compile("kind=compile".to_string()))
    }

    /// Build the single-field SP DCI-shape mapping document carrying `cel`.
    ///
    /// The expression is placed verbatim as the field expression of a single
    /// record/field. The `emit` guard is `true` so the record is always emitted
    /// and a missing output field is unambiguously a missing *value*, not a
    /// suppressed record.
    ///
    /// CI-VERIFY: the exact `version: "0.1"` source-field binding grammar is not
    /// verifiable in this workspace. `demo/mappings/spdci/crvs-person.yaml` binds
    /// source fields as `source.<field>` and uses inline CEL, so operator
    /// expressions are expected to reference `source.<field>` (e.g.
    /// `source.deceased == false`). If the pinned CROSSWALK_REF accepts bare
    /// field names instead, this is the single place to adjust the doc/grammar.
    fn synthesize_document(cel: &str) -> String {
        // serde_json renders the expression as a correctly-escaped JSON string,
        // which is valid YAML, so arbitrary operator CEL cannot break the doc.
        let expr = Value::String(cel.to_string()).to_string();
        format!(
            concat!(
                "version: \"0.1\"\n",
                "name: registry_relay_attribute_release\n",
                "source_system: registry-relay.attribute_release\n",
                "target_model: registry-relay.attribute_release\n",
                "records:\n",
                "  {record}:\n",
                "    emit: \"true\"\n",
                "    fields:\n",
                "      {field}: {expr}\n",
            ),
            record = RECORD_NAME,
            field = FIELD_NAME,
            expr = expr,
        )
    }

    /// Read the single output field back from the evaluated records. Returns
    /// `MissingField` (fail-closed) if no record or no field was produced, and
    /// `Eval` if the mapping produced more than one record (ambiguous output).
    fn read_single_field(
        records: std::collections::BTreeMap<String, Vec<Value>>,
    ) -> Result<Value, AttributeReleaseError> {
        let mut values = records.into_values().flatten();
        let Some(first) = values.next() else {
            return Err(AttributeReleaseError::MissingField(
                "field=value kind=no_record".to_string(),
            ));
        };
        if values.next().is_some() {
            return Err(AttributeReleaseError::Eval(
                "kind=multiple_records".to_string(),
            ));
        }
        match first {
            Value::Object(mut map) => match map.remove(FIELD_NAME) {
                Some(value) => Ok(value),
                None => Err(AttributeReleaseError::MissingField(
                    "field=value kind=absent".to_string(),
                )),
            },
            // A non-object record means the runtime did not wrap the field as
            // expected; fail closed rather than guess.
            _ => Err(AttributeReleaseError::TypeMismatch(
                "field=value kind=non_object_record".to_string(),
            )),
        }
    }

    /// PII-free diagnostic for a set of mapping issues: structural locators only,
    /// never the offending source value or expression text. Mirrors the
    /// value-free discipline of `spdci::mapping_issue_diagnostics`.
    fn issue_diagnostics(issues: &[MappingError]) -> String {
        let joined: Vec<String> = issues
            .iter()
            .map(|issue| format!("path={} kind=error", issue.path.as_deref().unwrap_or("$")))
            .collect();
        joined.join("; ")
    }

    /// PII-free diagnostic for a predicate that resolved to a non-boolean value.
    /// Carries only the JSON type tag, never the value itself.
    fn predicate_type_diagnostic(value: &Value) -> String {
        let kind = match value {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        format!("field=value expected=bool kind={kind}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn predicate_true() {
            let record = json!({ "deceased": false });
            let allowed = evaluate_release_predicate("source.deceased == false", &record)
                .expect("predicate evaluates");
            assert!(allowed);
        }

        #[test]
        fn predicate_false() {
            let record = json!({ "deceased": true });
            let allowed = evaluate_release_predicate("source.deceased == false", &record)
                .expect("predicate evaluates");
            assert!(!allowed);
        }

        #[test]
        fn scalar_concat() {
            let record = json!({ "given_name": "Ada", "surname": "Lovelace" });
            let value =
                evaluate_release_scalar("source.given_name + ' ' + source.surname", &record)
                    .expect("scalar evaluates");
            assert_eq!(value, json!("Ada Lovelace"));
        }

        #[test]
        fn invalid_cel_rejected_at_compile() {
            let err = validate_release_expression("source.given_name +")
                .expect_err("invalid CEL must be rejected");
            assert!(matches!(err, AttributeReleaseError::Compile(_)));
            // PII-free: the rendered message carries no expression text.
            assert!(!err.to_string().contains("given_name"));
        }

        #[test]
        fn compiled_mapping_is_cached_and_reused() {
            // The fix for the per-resolve recompile: identical expression text
            // must resolve to one shared compiled mapping, distinct text must not.
            let a = compiled_mapping("source.deceased == false").expect("compiles");
            let b = compiled_mapping("source.deceased == false").expect("compiles");
            assert!(
                Arc::ptr_eq(&a, &b),
                "identical expressions must share one cached compiled mapping"
            );
            let c = compiled_mapping("source.given_name").expect("compiles");
            assert!(!Arc::ptr_eq(&a, &c), "distinct expressions must not alias");
        }

        #[test]
        fn missing_field_fails_closed_for_predicate() {
            // The referenced source field is absent. A predicate that cannot be
            // evaluated must deny (Err), never silently allow.
            let record = json!({ "given_name": "Ada" });
            let result = evaluate_release_predicate("source.deceased == false", &record);
            assert!(
                result.is_err(),
                "missing source field must fail closed, got {result:?}"
            );
        }

        #[test]
        fn missing_field_fails_closed_for_scalar() {
            // A computed claim whose inputs are absent must error, never be
            // silently dropped or emitted as null.
            let record = json!({ "given_name": "Ada" });
            let result = evaluate_release_scalar("source.surname", &record);
            assert!(
                result.is_err(),
                "missing source field must fail closed, got {result:?}"
            );
        }

        #[test]
        fn diagnostics_are_pii_free() {
            // Error Display strings must never carry source values.
            let record = json!({ "deceased": true, "national_id": "SECRET-451123" });
            // Force a type mismatch by treating a string-returning expression as
            // a predicate.
            let result = evaluate_release_predicate("source.national_id", &record);
            let err = result.expect_err("string is not a boolean predicate");
            assert!(matches!(err, AttributeReleaseError::TypeMismatch(_)));
            assert!(!err.to_string().contains("SECRET-451123"));
        }
    }
}
