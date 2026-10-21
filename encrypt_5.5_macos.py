#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SuperPrompt 5.5 Encryptor - macOS Edition"""
import base64, hashlib, sys, os, re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT, IT = b'SuperPrompt_v5.5o', 480_000
NONCE_SIZE = 12

def derive_keys(master: str):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=SALT, iterations=IT)
    raw = kdf.derive(master.encode())
    return raw[:32], raw[32:]

def encrypt_data(data: str, master: str):
    enc_key, hmac_key = derive_keys(master)
    aesgcm = AESGCM(enc_key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    h = hashlib.sha256()
    h.update(hmac_key + ciphertext)
    hmac_hash = h.hexdigest()[:16]
    payload = base64.b64encode(ciphertext).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    return f"AES256:{payload}", nonce_b64, hmac_hash

def parse_block(block: str):
    if not block.strip() or '---START---' not in block:
        return None
    lines = block.strip().split('\n')
    header = re.match(r'^\.(\d+)\.\s*/([^—]+)[—-]\s*(.+)$', lines[0].strip())
    if not header:
        return None
    slot, name_id, title = header.groups()
    block_id = hashlib.md5(name_id.strip().encode()).hexdigest()[:5]
    desc, tags = "No description", []
    for line in lines[1:]:
        if line.startswith('ОПИСАНИЕ:') or line.startswith('DESCRIPTION:'):
            desc = line.split(':', 1)[1].strip()
        elif line.startswith('ОСОБЕННОСТИ:') or line.startswith('FEATURES:'):
            tags = [f"#{t.strip().lower()}" for t in line.split(':', 1)[1].split(',') if t.strip()]
    try:
        start, end = block.index('---START---') + 11, block.index('---END---')
        content = block[start:end].strip()
    except:
        return None
    return {'slot': int(slot), 'id': block_id, 'name': title.strip(), 'desc': desc, 'tags': tags, 'content': content}

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 encrypt_5.5_macos.py addon.txt 'MASTER_KEY'")
        sys.exit(1)
    infile, key = sys.argv[1], sys.argv[2]
    if not os.path.exists(infile):
        print(f"File not found: {infile}")
        sys.exit(1)
    with open(infile, 'r', encoding='utf-8') as f:
        content = f.read()
    blocks = re.split(r'\n(?=\.\d+\.)', content)
    out = []
    for blk in blocks:
        if not blk.strip():
            continue
        parsed = parse_block(blk)
        if not parsed:
            continue
        enc, nonce, hmac = encrypt_data(parsed['content'], key)
        tags_str = ' '.join(parsed['tags']) if parsed['tags'] else '#general'
        out.append(f"//.{parsed['slot']}. /{parsed['id']} ——\\{parsed['name']}/\nDESCRIPTION: {parsed['desc']}\nTAGS: {tags_str}\nNONCE: {nonce}\nHMAC: {hmac}\n---START---\n{enc}\n---END---")
    outfile = infile.replace('.txt', '_encrypted_5.5.txt')
    with open(outfile, 'w', encoding='utf-8') as f:
        f.write("\n\n".join(out))
    print(f"✅ Created: {outfile} ({len(out)} blocks)")

if __name__ == '__main__':
    main()