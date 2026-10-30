"""Streamlit UI — server-side processing of user-selected synthetic/non-sensitive files."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path
import streamlit as st
from signaltrace import (VERSION, MAX_EVIDENCE_BYTES, EvidenceError, inspect_file,
                         verify_record, build_audit, verify_audit, build_case_manifest,
                         verify_case_manifest)

st.set_page_config(page_title='ATHARNEX SignalTrace', page_icon='🔎', layout='wide')
st.title('ATHARNEX SignalTrace')
st.caption(f'v{VERSION} · Evidence integrity · Case manifests · Reproducible audit logs')
st.error('Research prototype only. Do not upload confidential or legally restricted evidence to public hosting. Uploaded bytes are processed on the server, not exclusively on your device.')
st.info('SHA-256 matching establishes content equality under the hash algorithm, NOT authenticity, custody, attribution, or proof of manipulation.')


def stage_upload(upload):
    """Copy with an explicit cap; context manager deletes the temporary content."""
    suffix = Path(upload.name).suffix[:16]
    with tempfile.TemporaryDirectory(prefix='signaltrace-') as folder:
        path = Path(folder) / ('evidence' + suffix)
        total = 0
        upload.seek(0)
        with path.open('wb') as target:
            while True:
                chunk = upload.read(1024 * 1024)
                if not chunk: break
                total += len(chunk)
                if total > MAX_EVIDENCE_BYTES:
                    raise EvidenceError('Upload exceeds 256 MiB limit.')
                target.write(chunk)
        yield path


if 'records' not in st.session_state: st.session_state.records = []
if 'events' not in st.session_state: st.session_state.events = []

with st.form('intake_form'):
    st.subheader('1 · Inspect evidence')
    item = st.file_uploader('Select non-sensitive evidence file', key='intake')
    label = st.text_input('Evidence label', max_chars=300)
    note = st.text_area('Acquisition context (unverified)', value='Not provided', max_chars=4000)
    do_inspect = st.form_submit_button('Inspect and add to case', type='primary')
if do_inspect:
    if not item: st.error('Choose a file first.')
    else:
        try:
            for path in stage_upload(item):
                record = inspect_file(path, evidence_label=label or item.name, acquisition_note=note)
            # Avoid exporting temporary upload name. Recompute self-hash.
            from signaltrace import digest_json
            record['original_filename'] = Path(item.name).name
            record['record_sha256'] = digest_json({k:v for k,v in record.items() if k!='record_sha256'})
            if len(st.session_state.records) >= 1000: raise EvidenceError('Case record limit reached.')
            st.session_state.records.append(record)
            st.session_state.events.append({'action':'inspect', 'record_sha256': record['record_sha256'], 'evidence_sha256':record['sha256']})
            st.success('Inspection recorded. The upload is not deliberately retained after processing; hosting infrastructure may still process/log requests.')
        except (EvidenceError, OSError, ValueError) as exc: st.error(f'Could not inspect: {exc}')

if st.session_state.records:
    st.subheader('2 · Case manifest and audit')
    case_id = st.text_input('Case identifier (avoid personal identifiers)', value='SYNTHETIC-CASE-001', max_chars=120)
    for i, record in enumerate(st.session_state.records, 1):
        with st.expander(f"Evidence {i} — {record['evidence_label']}"):
            st.code(record['sha256'], language=None)
            st.json(record)
    try:
        manifest = build_case_manifest(case_id, st.session_state.records)
        audit = build_audit(st.session_state.events)
        st.caption(f"Case entries: {len(st.session_state.records)} · Manifest check: {verify_case_manifest(manifest)} · Audit chain check: {verify_audit(audit)}")
        st.download_button('Download case manifest JSON', json.dumps(manifest,indent=2,ensure_ascii=False),file_name='signaltrace-case.json',mime='application/json')
        st.download_button('Download audit JSON', json.dumps(audit,indent=2,ensure_ascii=False),file_name='signaltrace-audit.json',mime='application/json')
    except (EvidenceError, ValueError) as exc: st.error(f'Could not generate case: {exc}')
    if st.button('Clear case in this session'):
        st.session_state.records=[]; st.session_state.events=[]; st.rerun()

st.divider()
st.subheader('3 · Verify previous evidence record')
st.caption('Use a v0.2 evidence JSON record; older formats require explicit migration.')
vfile=st.file_uploader('Recheck file',key='verifyfile')
vrecord=st.file_uploader('Previous v0.2 evidence JSON',type=['json'],key='verifyjson')
if st.button('Verify existing record'):
    if not (vfile and vrecord): st.error('Select both file and JSON record.')
    else:
        try:
            vrecord.seek(0)
            if vrecord.size > 10*1024*1024: raise EvidenceError('JSON is too large.')
            record=json.load(vrecord)
            for path in stage_upload(vfile): result=verify_record(path,record)
            (st.success if result['verified'] else st.error)('Verification checks passed.' if result['verified'] else 'Mismatch or integrity failure.')
            st.json(result)
        except (EvidenceError, ValueError, TypeError, OSError) as exc: st.error(f'Verification rejected: {exc}')

st.caption('Uploaded bytes travel to the hosting server. Do not claim this workflow is locally air-gapped or forensically certified.')
