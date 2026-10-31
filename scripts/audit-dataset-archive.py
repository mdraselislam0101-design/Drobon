#!/usr/bin/env python3
"""Read the user's pinned Dataset archive in RAM and pipe JSON to Main App checks.

No extraction, Dataset checkout, file creation or mutation. With --archive this
is offline; otherwise only the pinned user-owned GitHub archive is requested.
The SHA-256 must match before any member is processed.
"""
import argparse
import base64
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import urllib.request

COMMIT = '3986082b22007b47930da3bc99be9c2f2b036080'
EXPECTED_SHA256 = 'd1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d'
URL = f'https://codeload.github.com/mdraselislam0101-design/Drobon-Dataset/tar.gz/{COMMIT}'
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 20_000
ROOT = pathlib.Path(__file__).resolve().parent.parent
CATEGORIES = {
    'vulnIntel': ('vuln-intel/npm/', 'vuln-intel/pypi/'),
    'sast': ('packs/sast/v1/',), 'secrets': ('packs/secrets/v1/',),
    'dast': ('packs/dast/v1/',), 'sca': ('packs/sca/v1/',),
    'remediation': ('knowledge/remediation/',), 'cwe': ('knowledge/cwe/',),
    'lessons': ('learning/lessons/',), 'assessmentTemplates': ('assessments/templates/',),
    'engagementTemplates': ('engagements/',), 'interop': ('interop/',),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', help='read an existing archive without network access')
    args = parser.parse_args()
    if args.archive:
        with open(args.archive, 'rb') as source:
            archive = source.read(MAX_ARCHIVE + 1)
    else:
        with urllib.request.urlopen(URL, timeout=60) as source:
            archive = source.read(MAX_ARCHIVE + 1)
    if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError('Archive size or SHA-256 does not match the pinned Dataset')
    print(f'Pinned archive SHA-256: {EXPECTED_SHA256}; compressed bytes: {len(archive)}', file=sys.stderr)
    process = subprocess.Popen(['node', '--import', 'tsx', str(ROOT / 'scripts/verify-dataset-memory.mjs')],
                               cwd=ROOT, stdin=subprocess.PIPE)
    count = 0
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as container:
            for member in container:
                if not member.isfile() or '/' not in member.name:
                    continue
                path = member.name.split('/', 1)[1]
                category = next((key for key, prefixes in CATEGORIES.items()
                                 if any(path.startswith(prefix) for prefix in prefixes)), None)
                if category is None or not path.endswith('.json') or '/samples/' in f'/{path}':
                    continue
                count += 1
                total += member.size
                if member.size > MAX_FILE or count > MAX_FILES or total > MAX_TOTAL:
                    raise RuntimeError('Selected archive members exceed bounded input limits')
                source = container.extractfile(member)
                if source is None:
                    raise RuntimeError('Selected archive member is not readable')
                data = source.read(member.size + 1)
                if len(data) != member.size:
                    raise RuntimeError('Selected archive member size changed')
                line = json.dumps({'category': category, 'path': path,
                                   'base64': base64.b64encode(data).decode('ascii')}, separators=(',', ':'))
                process.stdin.write(line.encode('ascii') + b'\n')
        process.stdin.close()
        return process.wait()
    except Exception:
        process.stdin.close()
        process.wait()
        raise


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, tarfile.TarError):
        print('Read-only archive verification failed (details withheld)', file=sys.stderr)
        raise SystemExit(1)
