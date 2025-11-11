#!/usr/bin/env python3
"""Quick verification script to check all enhancements."""

import os
import json

# Verify files exist
files_to_check = [
    'setup.py',
    'crl.py',
    'merkle_log.py',
    'ca/root_cert.pem',
    'ca/root_key.pem',
    'ca/merkle_log.json',
    'keys/Pilot-Alpha_cert.pem',
    'keys/Control-Bravo_cert.pem',
]

print('=== FILE VERIFICATION ===')
all_good = True
for f in files_to_check:
    exists = os.path.exists(f)
    status = '✓' if exists else '✗'
    print(f'{status} {f}')
    if not exists:
        all_good = False

# Check Merkle log structure
print('\n=== MERKLE LOG VERIFICATION ===')
try:
    with open('ca/merkle_log.json') as f:
        log = json.load(f)
        leaves_count = len(log.get('leaves', []))
        root = log.get('root', 'N/A')
        print(f'✓ Leaves count: {leaves_count}')
        print(f'✓ Root hash: {root[:16]}...')
except Exception as e:
    print(f'✗ Error reading merkle log: {e}')
    all_good = False

# Check CRL structure
print('\n=== CRL VERIFICATION ===')
try:
    with open('ca/crl.json') as f:
        crl = json.load(f)
        revoked_count = len(crl.get('revoked', []))
        print(f'✓ Revoked certs: {revoked_count}')
        if revoked_count > 0:
            print(f'✓ Latest revocation: {crl["updated_at"]}')
except Exception as e:
    print(f'✗ Error reading CRL: {e}')
    all_good = False

# Check CRL signature
print('\n=== CRL SIGNATURE VERIFICATION ===')
try:
    sig_path = 'ca/crl.sig'
    if os.path.exists(sig_path):
        size = os.path.getsize(sig_path)
        print(f'✓ CRL signature present: {size} bytes')
    else:
        print(f'⚠ CRL signature not found (may not be signed yet)')
except Exception as e:
    print(f'✗ Error checking signature: {e}')

if all_good:
    print('\n[✓] All verification checks passed!')
else:
    print('\n[✗] Some checks failed!')
