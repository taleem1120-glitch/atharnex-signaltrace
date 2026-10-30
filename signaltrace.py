"""ATHARNEX SignalTrace: defensive, read-only evidence integrity toolkit.

SHA-256 supports content equality; neither records nor hash chains authenticate provenance.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import mimetypes
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = '0.2.0'
CHUNK_SIZE = 1024 * 1024
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_ITEMS = 1000
MAX_REPORT_BYTES = 10 * 1024 * 1024
HEX64 = re.compile(r'^[0-9a-f]{64}$')

class EvidenceError(ValueError):
    """Input cannot be inspected or verified safely."""


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()


def _regular_path(path: str | Path) -> Path:
    p = Path(path)
    if p.is_symlink():
        raise EvidenceError('Symlinks are not accepted (source could change).')
    info = p.stat()
    if not stat.S_ISREG(info.st_mode):
        raise EvidenceError('Only regular files are supported.')
    if info.st_size > MAX_EVIDENCE_BYTES:
        raise EvidenceError(f'File exceeds {MAX_EVIDENCE_BYTES} byte limit.')
    return p


def sha256_file(path: str | Path) -> str:
    p = _regular_path(path)
    h = hashlib.sha256()
    with p.open('rb') as stream:
        start = os.fstat(stream.fileno())
        if not stat.S_ISREG(start.st_mode):
            raise EvidenceError('Opened object is not a regular file.')
        if start.st_size > MAX_EVIDENCE_BYTES:
            raise EvidenceError('File exceeds evidence size limit.')
        count = 0
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b''):
            count += len(chunk)
            if count > MAX_EVIDENCE_BYTES:
                raise EvidenceError('File grew beyond evidence size limit.')
            h.update(chunk)
        end = os.fstat(stream.fileno())
        if (start.st_dev, start.st_ino, start.st_size, start.st_mtime_ns, start.st_ctime_ns) != (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns) or count != start.st_size:
            raise EvidenceError('Evidence changed during hashing. Do not issue an integrity record.')
    return h.hexdigest()


def detect_signature(path: Path) -> dict:
    """Detect limited container signatures; do not infer authenticity or tampering."""
    with path.open('rb') as stream:
        head = stream.read(32)
    kind = 'unknown'
    if head.startswith(b'\xff\xd8\xff'): kind = 'JPEG'
    elif head.startswith(b'\x89PNG\r\n\x1a\n'): kind = 'PNG'
    elif head.startswith((b'GIF87a', b'GIF89a')): kind = 'GIF'
    elif head.startswith(b'%PDF-'): kind = 'PDF'
    elif head.startswith(b'PK\x03\x04'): kind = 'ZIP-compatible container'
    elif head.startswith(b'RIFF') and head[8:12] in (b'WAVE', b'AVI ', b'WEBP'):
        kind = {b'WAVE':'WAV', b'AVI ':'AVI', b'WEBP':'WebP'}[head[8:12]]
    elif len(head) >= 12 and head[4:8] == b'ftyp': kind = 'ISO base media (MP4/HEIF family)'
    elif head.startswith(b'\x1a\x45\xdf\xa3'): kind = 'EBML (Matroska/WebM family)'
    ext_guess = mimetypes.guess_type(path.name)[0]
    return {'detected_header_family': kind, 'extension_mime_guess': ext_guess,
            'limitations': 'Header signatures and extensions cannot establish authenticity, codec validity, or manipulation.'}


def _media_metadata(path: Path) -> dict:
    metadata: dict[str, Any] = {'signature': detect_signature(path)}
    try:
        from PIL import Image, ExifTags, ImageFile
        with Image.open(path) as im:
            metadata['image'] = {'format': im.format, 'width': im.width,
                                 'height': im.height, 'mode': im.mode,
                                 'frames_reported': getattr(im, 'n_frames', 1),
                                 'exif_values_exported': False}
            tags = im.getexif()
            blocked = {'GPSInfo', 'BodySerialNumber', 'CameraSerialNumber', 'OwnerName', 'Artist', 'UserComment', 'MakerNote'}
            metadata['image']['exif_tag_names_present'] = sorted(str(ExifTags.TAGS.get(k,k)) for k in tags if str(ExifTags.TAGS.get(k,k)) not in blocked)
    except ImportError:
        metadata['image_inspection'] = 'Skipped: Pillow not installed.'
    except (OSError, ValueError, SyntaxError, TypeError):
        metadata['image_inspection'] = 'No recognizable image metadata.'
    return metadata


def inspect_file(path: str | Path, *, evidence_label: str | None = None,
                 acquisition_note: str = 'Not provided', acquired_at_utc: str | None = None) -> dict:
    p = _regular_path(path)
    fingerprint = sha256_file(p)
    info = p.stat()
    # We avoid asserting stat proves stability across a second (metadata) read.
    label = evidence_label if evidence_label is not None else p.name
    if len(label) > 300 or len(acquisition_note) > 4000:
        raise EvidenceError('Label or note exceeds length limit.')
    data = {'schema': 'atharnex.signaltrace.evidence.v0.2', 'tool_version': VERSION,
            'evidence_label': label, 'original_filename': p.name,
            'size_bytes': info.st_size, 'sha256': fingerprint,
            'filesystem_mtime_utc': datetime.fromtimestamp(info.st_mtime, tz=timezone.utc).isoformat(),
            'filesystem_mtime_is_untrusted': True,
            'acquisition': {'note': acquisition_note, 'acquired_at_utc_user_supplied': acquired_at_utc},
            'metadata': _media_metadata(p),
            'limitations': ['Content hashes verify equality, not authenticity or origin.',
                            'Untrusted file timestamps and self-reported acquisition data are not independently verified.',
                            'Header signatures cannot establish manipulation.',
                            'Record hashes and audit chains are not digital signatures or chain-of-custody certificates.']}
    data['record_sha256'] = digest_json(data)
    return data


def _validate_record(record: Any) -> dict:
    if not isinstance(record, dict): raise EvidenceError('Record must be a JSON object.')
    if record.get('schema') != 'atharnex.signaltrace.evidence.v0.2':
        raise EvidenceError('Unsupported record schema; migrate explicitly, never silently.')
    if not isinstance(record.get('size_bytes'), int) or record['size_bytes'] < 0:
        raise EvidenceError('Invalid recorded size.')
    if not isinstance(record.get('sha256'), str) or not HEX64.fullmatch(record['sha256']):
        raise EvidenceError('Invalid SHA-256 digest format.')
    if not isinstance(record.get('record_sha256'), str) or not HEX64.fullmatch(record['record_sha256']):
        raise EvidenceError('Invalid record digest format.')
    return record


def verify_record(path: str | Path, record: dict) -> dict:
    record = _validate_record(record)
    record_core = {k:v for k,v in record.items() if k != 'record_sha256'}
    intact = digest_json(record_core) == record['record_sha256']
    p = _regular_path(path)
    actual = sha256_file(p)
    size_ok = p.stat().st_size == record['size_bytes']
    return {'record_integrity_matches': intact,
            'file_sha256_matches': actual == record['sha256'],
            'file_size_matches': size_ok,
            'actual_file_sha256': actual,
            'verified': intact and size_ok and actual == record['sha256'],
            'limitations': 'Matching hashes do not establish origin, custody or authenticity.'}


def build_audit(events: list[dict]) -> dict:
    if not isinstance(events, list) or len(events) > MAX_MANIFEST_ITEMS or any(not isinstance(e, dict) for e in events):
        raise EvidenceError('Audit must contain up to 1000 JSON-object events.')
    prev = '0' * 64
    entries = []
    for i, event in enumerate(events, 1):
        body = {'sequence': i, 'previous_sha256': prev, 'event': event}
        prev = digest_json(body)
        entries.append({**body, 'entry_sha256': prev})
    return {'schema': 'atharnex.signaltrace.audit.v0.2', 'entries': entries, 'head_sha256': prev,
            'limitations': 'Not tamper-proof without an independently trusted signed or externally anchored head.'}


def verify_audit(log: Any) -> bool:
    if not isinstance(log, dict) or log.get('schema') != 'atharnex.signaltrace.audit.v0.2': return False
    entries = log.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_MANIFEST_ITEMS: return False
    prev = '0' * 64
    try:
        for i, entry in enumerate(entries, 1):
            if not isinstance(entry, dict) or set(entry) != {'sequence','previous_sha256','event','entry_sha256'}: return False
            if entry['sequence'] != i or type(entry['sequence']) is not int or entry['previous_sha256'] != prev or not isinstance(entry['event'], dict): return False
            prev = digest_json({'sequence':i, 'previous_sha256':prev, 'event':entry['event']})
            if entry['entry_sha256'] != prev: return False
    except (TypeError, ValueError): return False
    return prev == log.get('head_sha256')


def build_case_manifest(case_id: str, records: list[dict], *, note: str = '') -> dict:
    if not isinstance(case_id, str) or not 1 <= len(case_id) <= 120 or not isinstance(note, str) or len(note) > 4000:
        raise EvidenceError('Invalid case identifier or note.')
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_MANIFEST_ITEMS:
        raise EvidenceError('Case requires 1–1000 records.')
    for r in records:
        _validate_record(r)
        if digest_json({k:v for k,v in r.items() if k != 'record_sha256'}) != r['record_sha256']:
            raise EvidenceError('Cannot include a modified or corrupt evidence record.')
    manifest = {'schema':'atharnex.signaltrace.case.v0.2', 'case_id':case_id,
                'note':note, 'evidence_count':len(records),
                'evidence_records': records,
                'limitations':'Case manifest hash is an internal integrity checksum, not an external signature.'}
    manifest['manifest_sha256'] = digest_json(manifest)
    return manifest


def verify_case_manifest(manifest: Any) -> bool:
    if not isinstance(manifest, dict) or manifest.get('schema') != 'atharnex.signaltrace.case.v0.2': return False
    records = manifest.get('evidence_records')
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_MANIFEST_ITEMS or manifest.get('evidence_count') != len(records): return False
    try:
        for r in records:
            _validate_record(r)
            if digest_json({k:v for k,v in r.items() if k != 'record_sha256'}) != r['record_sha256']: return False
        return manifest.get('manifest_sha256') == digest_json({k:v for k,v in manifest.items() if k != 'manifest_sha256'})
    except (EvidenceError, ValueError, TypeError): return False


def load_json(path: str | Path) -> Any:
    p = _regular_path(path)
    if p.stat().st_size > MAX_REPORT_BYTES: raise EvidenceError('JSON report exceeds limit.')
    with p.open('r', encoding='utf-8') as stream:
        return json.load(stream, parse_constant=lambda s: (_ for _ in ()).throw(EvidenceError(f'Invalid JSON constant: {s}')))


def main() -> None:
    parser = argparse.ArgumentParser(description='ATHARNEX SignalTrace — read-only evidence inspection')
    sub = parser.add_subparsers(dest='command', required=True)
    a = sub.add_parser('inspect'); a.add_argument('file'); a.add_argument('--output'); a.add_argument('--label'); a.add_argument('--note',default='Not provided')
    b = sub.add_parser('verify'); b.add_argument('file'); b.add_argument('record')
    c = sub.add_parser('verify-case'); c.add_argument('manifest')
    d = sub.add_parser('verify-audit'); d.add_argument('audit')
    args = parser.parse_args()
    try:
        if args.command == 'inspect':
            result = inspect_file(args.file, evidence_label=args.label, acquisition_note=args.note)
            rendered = json.dumps(result, indent=2, ensure_ascii=False)
            if args.output: Path(args.output).write_text(rendered+'\n', encoding='utf-8')
            else: print(rendered)
        elif args.command == 'verify':
            verdict = verify_record(args.file, load_json(args.record)); print(json.dumps(verdict,indent=2))
            if not verdict['verified']: raise SystemExit(1)
        elif args.command == 'verify-case':
            ok = verify_case_manifest(load_json(args.manifest)); print(json.dumps({'manifest_verified':ok}));
            if not ok: raise SystemExit(1)
        else:
            ok = verify_audit(load_json(args.audit)); print(json.dumps({'audit_verified':ok}));
            if not ok: raise SystemExit(1)
    except (EvidenceError, FileNotFoundError, OSError, ValueError, TypeError) as exc:
        parser.exit(2, f'Inspection error: {exc}\n')

if __name__ == '__main__': main()
