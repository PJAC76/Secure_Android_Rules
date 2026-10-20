"""Sign source rules; private key stays outside repository. No samples or binaries.

Requires cryptography. Example (run in controlled release environment):
python sign-bundle.py --rules builtin.yar --private-key /secret/key.pem --version 1 \
  --provenance 'Secure_Android original MIT heuristics' --output manifest.json
The APK must carry the corresponding Ed25519 public key as X509 DER in
rules/src/main/assets/rules-public-key.der.
"""
import argparse
import base64
import hashlib
import json
import time
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules', type=Path, required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    parser.add_argument('--version', type=int, required=True)
    parser.add_argument('--provenance', required=True)
    parser.add_argument('--license', default='MIT')
    parser.add_argument('--days', type=int, default=90)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.rules.read_text(encoding='utf-8')
    encoded = source.encode('utf-8')
    if not 0 < len(encoded) <= 524288 or '\0' in source:
        parser.error('Source must be 1..524288 UTF-8 bytes without NUL')
    if args.version < 1 or not 1 <= args.days <= 366:
        parser.error('Positive monotonic version and 1..366 days required')
    key = load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        parser.error('An Ed25519 private key is required')
    now = int(time.time() * 1000)
    payload = json.dumps(dict(version=args.version, minEngine=1, createdAt=now,
                             expiresAt=now + args.days*86400000, source=source,
                             sha256=hashlib.sha256(encoded).hexdigest(),
                             provenance=args.provenance, license=args.license),
                         ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    envelope = dict(payload=base64.b64encode(payload).decode('ascii'),
                    signature=base64.b64encode(key.sign(payload)).decode('ascii'))
    args.output.write_text(json.dumps(envelope, separators=(',', ':')), encoding='utf-8')
    print(f'Signed source bundle version {args.version}: {args.output.name}')


if __name__ == '__main__':
    main()
