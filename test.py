#!/usr/bin/env python3
# Copyright 2022 EDF. This software was developed in collaboration with Christian Amsüss.
# SPDX-License-Identifier: BSD-3-Clause

import subprocess
import sys
import http.client
import time

import cbor2

sub = subprocess.Popen([sys.executable, './demo-as.py'])
try:
    # demo-as has no means of indicating readiness
    time.sleep(1)

    con = http.client.HTTPConnection('localhost', 8119)
    con.request("POST", "/token", "doesn't matter")
    response = con.getresponse()
    assert response.status == 401
    assert response.headers['Location'] == './'

    con.request("GET", "/")
    response = con.getresponse()
    assert response.status == 200
    assert response.read() == open("index.html", "rb").read()

    con.request("POST", "/token", cbor2.dumps({5: 'd00'}), {'Authorization': 'bearer junior'})
    response = con.getresponse()
    assert response.status == 201
    token_response = cbor2.loads(response.read())
    scope = cbor2.loads(token_response[9])
    assert dict(scope)['/temp'] == 1
    assert dict(scope)['/identify'] == 2
    assert 8 in token_response # OSCORE material, will be randomized
finally:
    sub.kill()
