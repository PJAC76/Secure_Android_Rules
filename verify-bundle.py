import base64
import hashlib
import json
import time
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_public_key

envelope = json.loads(Path('manifest.json').read_text(encoding='utf-8'))
payload = base64.b64decode(envelope['payload'], validate=True)
key = load_der_public_key(Path('rules-public-key.der').read_bytes())
key.verify(base64.b64decode(envelope['signature'], validate=True), payload)
data = json.loads(payload)
assert data['sha256'] == hashlib.sha256(data['source'].encode()).hexdigest()
assert data['source'] == Path('rules.yar').read_text(encoding='utf-8')
assert data['expiresAt'] > int(time.time() * 1000)
assert data['version'] >= 1
print('Firma, contenido, versión y caducidad verificados')
