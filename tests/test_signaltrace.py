import copy
import hashlib
import json
import os
import pytest
from pathlib import Path
from signaltrace import (inspect_file, verify_record, sha256_file, EvidenceError,
                         build_audit, verify_audit, build_case_manifest,
                         verify_case_manifest, detect_signature, canonical_json,
                         load_json, digest_json)

@pytest.fixture
def sample(tmp_path):
    p=tmp_path/'photo.png'; p.write_bytes(b'\x89PNG\r\n\x1a\nsynthetic')
    return p

def test_sha256_known_value(tmp_path):
    p=tmp_path/'test';p.write_bytes(b'test')
    assert sha256_file(p)=='9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'

def test_record_verifies(sample): assert verify_record(sample,inspect_file(sample))['verified']
def test_modified_evidence_fails(sample):
    r=inspect_file(sample);sample.write_bytes(b'changed')
    assert not verify_record(sample,r)['verified']
def test_modified_record_fails(sample):
    r=inspect_file(sample);r['evidence_label']='tampered'
    assert not verify_record(sample,r)['record_integrity_matches']
def test_invalid_record_schema_rejected(sample):
    r=inspect_file(sample);r['schema']='other'
    with pytest.raises(EvidenceError):verify_record(sample,r)
def test_invalid_digest_rejected(sample):
    r=inspect_file(sample);r['sha256']='xyz'
    with pytest.raises(EvidenceError): verify_record(sample,r)
def test_wrong_size_rejected_even_if_hash_matches(sample):
    r=inspect_file(sample);r['size_bytes']+=1;r['record_sha256']=digest_json({k:v for k,v in r.items() if k!='record_sha256'})
    assert not verify_record(sample,r)['verified']
def test_magic_png(sample): assert detect_signature(sample)['detected_header_family']=='PNG'
def test_extension_spoof_detected(tmp_path):
    p=tmp_path/'photo.jpg';p.write_bytes(b'%PDF-1.7\n')
    assert detect_signature(p)['detected_header_family']=='PDF'
def test_empty_file(tmp_path):
    p=tmp_path/'empty';p.write_bytes(b'')
    assert verify_record(p,inspect_file(p))['verified']
def test_symlink_rejected(sample,tmp_path):
    link=tmp_path/'link';link.symlink_to(sample)
    with pytest.raises(EvidenceError):inspect_file(link)
def test_directory_rejected(tmp_path):
    with pytest.raises(EvidenceError):sha256_file(tmp_path)
def test_length_note_rejected(sample):
    with pytest.raises(EvidenceError):inspect_file(sample,acquisition_note='x'*4001)
def test_audit_valid_and_mutation_fails():
    audit=build_audit([{'action':'intake'},{'action':'inspect'}])
    assert verify_audit(audit)
    audit['entries'][0]['event']['action']='altered'
    assert not verify_audit(audit)
def test_audit_reordered_fails():
    audit=build_audit([{'a':1},{'a':2}]);audit['entries'].reverse()
    assert not verify_audit(audit)
def test_audit_truncation_fails():
    audit=build_audit([{'a':1},{'a':2}]);audit['entries'].pop()
    assert not verify_audit(audit)
def test_audit_empty_valid(): assert verify_audit(build_audit([]))
def test_invalid_audit_types_fail():
    for x in (None,[],{}, {'schema':'atharnex.signaltrace.audit.v0.2','entries':'bad'}): assert not verify_audit(x)
def test_manifest_valid(sample):
    case=build_case_manifest('CASE-A',[inspect_file(sample)])
    assert verify_case_manifest(case)
def test_manifest_tamper_fails(sample):
    case=build_case_manifest('CASE-A',[inspect_file(sample)])
    case['evidence_records'][0]['sha256']='0'*64
    assert not verify_case_manifest(case)
def test_manifest_delete_fails(sample):
    case=build_case_manifest('CASE-A',[inspect_file(sample)])
    case['evidence_records'].clear()
    assert not verify_case_manifest(case)
def test_manifest_refuses_tampered_record(sample):
    rec=inspect_file(sample);rec['evidence_label']='altered'
    with pytest.raises(EvidenceError):build_case_manifest('CASE-A',[rec])
def test_two_evidence_files(sample,tmp_path):
    q=tmp_path/'b.txt';q.write_text('more')
    m=build_case_manifest('CASE-2',[inspect_file(sample),inspect_file(q)])
    assert m['evidence_count']==2 and verify_case_manifest(m)
def test_audit_determinism(): assert build_audit([{'z':2,'a':1}])==build_audit([{'a':1,'z':2}])
def test_nonfinite_json_rejected():
    with pytest.raises(ValueError):canonical_json({'x':float('nan')})
def test_bad_json_rejected(tmp_path):
    p=tmp_path/'bad.json';p.write_text('{bad')
    with pytest.raises(json.JSONDecodeError):load_json(p)
def test_json_infinity_rejected(tmp_path):
    p=tmp_path/'bad.json';p.write_text('{"x":NaN}')
    with pytest.raises(EvidenceError):load_json(p)
def test_case_id_length_limit(sample):
    with pytest.raises(EvidenceError):build_case_manifest('X'*121,[inspect_file(sample)])
def test_record_serialization_is_stable(sample):
    r=inspect_file(sample)
    assert digest_json({k:v for k,v in r.items() if k!='record_sha256'})==r['record_sha256']
