''' MongoDB, starting from version 4.0, uses Salted Challenge Response Authentication Mechanism (SCRAM).
as detailed in RFC 5802.  There is no known tool to decrypt a SCRAM hash so I made one.
''''



#!/usr/bin/python3

import base64
import hashlib
import hmac
import sys

USERNAME = '<username>'
SALT = '<salt>'
CLIENT_NONCE = '<client_nonce>'
SERVER_NONCE = '<server_nonce>'
ITERATIONS = 15000
TARGET = '<target>'
WORDLIST = '<wordlist>'

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def proof(username, password, salt, client_nonce, server_nonce, iterations):
    raw_salt = base64.b64decode(salt)
    client_first_bare = 'n={},r={}'.format(username, client_nonce)
    server_first = 'r={},s={},i={}'.format(server_nonce, salt, iterations)
    client_final_without_proof = 'c=biws,r={}'.format(server_nonce)
    auth_msg = '{},{},{}'.format(client_first_bare, server_first, client_final_without_proof)

    salted_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), raw_salt, iterations)
    client_key = hmac.digest(salted_password, b'Client Key', 'sha256')
    stored_key = hashlib.sha256(client_key).digest()
    client_signature = hmac.new(stored_key, auth_msg.encode('utf-8'), 'sha256').digest()
    client_proof = byte_xor(client_key, client_signature)

    return base64.b64encode(client_proof).decode('utf-8')

counter = 0
with open(WORDLIST) as f:
    for candidate in f:
        counter = counter + 1
        if counter % 1000 == 0:
            print('Tried {} passwords'.format(counter))

        p = proof(USERNAME, candidate.rstrip('\n'), SALT, CLIENT_NONCE, SERVER_NONCE, ITERATIONS)
        if p == TARGET:
            print('Password found: {}'.format(candidate.rstrip('\n')))
            sys.exit(0)

print('Wordlist exhausted with no password found.')
