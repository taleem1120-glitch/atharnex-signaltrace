# ATHARNEX SignalTrace v0.2.0

**Evidence integrity and defensive digital-file triage — research prototype.** This is an improved release, **not** a validated forensic product, manipulation detector, or legal chain-of-custody certificate.

## Capabilities

- Chunked SHA-256 fingerprinting with within-read file change checks and a 256 MiB per-file cap.
- Limited binary header signature identification (JPEG, PNG, GIF, PDF, ZIP family, RIFF/WAV/AVI/WebP, ISO base media and EBML). A magic signature is **not proof of originality or manipulation**.
- Privacy-minded image metadata inspection, exporting dimensions and selected EXIF tag **names**, not EXIF values, when Pillow is installed.
- Structured JSON evidence records with canonical JSON SHA-256 checksums.
- Case manifests containing 1–1,000 validated evidence records.
- Reproducible hash-linked audit records, with sequencing, mutation, and truncation checks.
- Command-line inspection/verification plus an optional Streamlit interface.
- Automated tests for corruption and adversarial inputs.

## Critical limitations and privacy

- **If deployed publicly, uploads travel to the server. Do not upload confidential, classified, intimate, or legally protected evidence to a public Streamlit host.** Files are copied into temporary directories and explicitly disposed after processing, but server request infrastructure, logs, and backups remain outside this tool's control.
- A malicious actor able to rewrite a whole manifest or log can recompute all hashes. External signed anchoring and trusted acquisition practices are still required for authoritative custody claims.
- The app does not verify ownership, photo originality, document truth, malware safety, or manipulation. File-type mismatches are only triage indicators.
- It does not execute uploaded files, recover deleted data, identify people, or extract embedded metadata values. Image libraries can themselves have vulnerabilities; keep dependencies patched and inspect untrusted inputs in an isolated environment.
- Synthetic examples are for demonstration; not production, legal, or investigative conclusions.
- Previous v0.1 evidence JSON is deliberately **not silently accepted** by the v0.2 verifier. Retain legacy records and use a separately reviewed migration procedure.
- The file-size cap and JSON limits are application controls, not a replacement for reverse-proxy, network, process, and resource quotas.

## Install and run locally

Requires Python 3.10+.

```bash
python -m pip install -r requirements.txt
python -m pytest -q
streamlit run app.py
```

For command-line inspection:

```bash
python signaltrace.py inspect examples/synthetic_sample.txt --output local-record.json
python signaltrace.py verify examples/synthetic_sample.txt local-record.json
```

Run on a copy of evidence in an isolated machine where possible. The CLI's nonzero exit code indicates an integrity mismatch or rejected input.

## Design / verification

- The **record hash** excludes only the `record_sha256` field; a manifest hash excludes only `manifest_sha256`.
- Evidence bytes are fingerprinted using SHA-256 in 1 MiB blocks. A changed file during the hash raises an error rather than producing a report marked stable.
- Audit event chains carry `sequence`, `previous_sha256`, and `entry_sha256`. Without external signed anchoring, the entire log remains rewritable.
- Case manifests validate each evidence record's own digest before inclusion.
- Metadata is descriptive, never a categorical tamper finding.

## Development quality gate

The release was validated with 29 unit tests and a CLI sample demonstration at packaging time. These are **not** independent security audits, fuzzing, penetration testing, legal validation, third-party benchmarks, or evidence-admissibility certifications. Do not call this the strongest available forensic suite without those studies.

## Commercial roadmap

Before any commercial or court-facing use: add signed provenance, externally anchored timestamps, a repeatable chain-of-custody workflow, independent verification, a formally scoped threat model, benchmark datasets with false-positive reporting, and access controls for sensitive evidence. Monetization pathways would be support, integrations, training, and hosted enterprise deployment; no revenue is currently demonstrated.

## License

MIT (see [LICENSE](LICENSE)).
