#!/usr/bin/env python3
# Copyright 2022 EDF. This software was developed in collaboration with Christian Amsüss.
# SPDX-License-Identifier: BSD-3-Clause

import socket
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler, HTTPStatus
import time
from pathlib import Path
import yaml

import cbor2
import pycose.messages, pycose.keys, pycose.headers, pycose.algorithms

configs_by_audience = {}
for config in Path("configs/").glob('*.yaml'):
    data = yaml.safe_load(open(config))
    configs_by_audience[data['audience']] = data

def generate_token_for(key, scope, exp):
    """Generate an ACE-OSCORE token with fresh key material for communication
    with the RS with which the given `key` is agreed."""

    # for encrypted token
    #
    # A realistic server should either implement a counter here, or keep track
    # of issued tokens; otherwise an attacking client could keep requesting a
    # token, wait for a birthday to happen after 2**52 requests, and use that
    # to geain the AS-RS key
    iv = secrets.token_bytes(13)

    # for cnf (we don't provide extra salt or contextId)
    master_secret = secrets.token_bytes(16)
    identifier = secrets.token_bytes(4) # we don't allow upgrades, so we just pick random ones; a longer running server would ensure they don't conflict

    # keys are CWT confirmation methods; inner are from OSCORE Security Context Parameters
    cnf = {4: {
        0: identifier,
        2: master_secret,
        }}
    # keys from OAuth Parameters CBOR Mappings
    encrypted = {
            4: int(exp),
            8: cnf,
            9: scope,
            # Not repeating RS or AS: our RS only have one AS, and they'll know from the unique keys that it's for them
            }
    enc0 = pycose.messages.Enc0Message(
            {
                pycose.headers.Algorithm.identifier:
                    pycose.algorithms.AESCCM16128256.identifier
            }, {
                pycose.headers.IV.identifier: iv
            },
            cbor2.dumps(encrypted))
    enc0.key = key
    token = enc0.encode()

    # keys from OAuth Parameters CBOR Mappings
    message = {
            1: token,
            8: cnf,
            9: scope,
            }

    return cbor2.dumps(message)

class AceServer(BaseHTTPRequestHandler):
    """HTTP handler implementing a simple ACE AS.

    This supports POSTs to /token as per the ACE OSCORE profile. An OPTIONS
    handler ensures that CORS requirements are met.

    Unauthenticated requests are redirected to `/`, where the index.html page
    is served. That page takes care of the bespoke OAuth-like protocol the
    client webapp expects.
    """

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(HTTPStatus.FOUND)
            self.end_headers()
            self.wfile.write(open('index.html', 'rb').read())
        elif self.path == "/token":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.OK)
        self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin'))
        self.send_header('Access-Control-Allow-Headers', 'Authorization')
        self.end_headers()

    def do_POST(self):
        if self.path != '/token':
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        scope = self.headers.get('Authorization')

        if scope == 'bearer senior':
            aif = [['/temp', 0], ['/identify', 1], ['/leds', 2]]
            expiry = 2 * 60 * 60
        elif scope == 'bearer junior':
            aif = [['/temp', 0], ['/identify', 1]]
            expiry = 5 * 60
        else:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin'))
            self.send_header('Access-Control-Expose-Headers', 'Location')
            self.send_header('Location', './')
            self.end_headers()
            return

        scope = cbor2.dumps(aif)

        request = cbor2.load(self.rfile)
        # from ACE Authorization Server Request Creation Hints
        audience = request[5]
        # ignoring scope, we'll tell them what they can have

        rs_key = pycose.keys.SymmetricKey(bytes.fromhex(configs_by_audience[audience]['key']))

        self.send_response(HTTPStatus.CREATED)
        self.send_header('Content-Format', 'application/ace+cbor')
        self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin'))
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.end_headers()
        self.wfile.write(generate_token_for(rs_key, scope, time.time() + expiry))

class HTTP6Server(HTTPServer):
    address_family = socket.AF_INET6

def run():
    httpd = HTTP6Server(('::1', 8119), AceServer)
    httpd.serve_forever()

if __name__ == "__main__":
    #rs_key = pycose.keys.SymmetricKey(bytes(list(b'abc') + list(range(4, 33))))
    #print(cbor2.loads(generate_token_for(rs_key, scope=b"somescope", exp=2**32-1)))
    run()
