<!--
SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
SPDX-License-Identifier: BSD-3-Clause
-->
CoAP/ACE PoC: Authorization Server
==================================

This repository contains the Authorization Server (AS) part of the CoAP/ACE proof-of-concept implementation.

It is written in Python,
and generates ACE-OSCORE tokens for known resource servers configured in `./configs/`.

This server is purely suitable for demonstration purposes,
as it does not perform any actual authentication with the client;
instead, it accepts `"bearer junior"` and `"bearer senior"` values of the Authorization header,
and issues AIF tokens for the demo devices accordingly.
Its CORS setup lets users from any web page obtain access tokens
in order to simplify using a running AS with local experimental setups.

Unauthenticated users are redirected to a login page,
which uses a vastly simplifying bowdlerization of the OAuth protocol in a fashion coordinated with the PoC's webapp.

**Please also see
[the corrresponding firmware's README file],
which explains the whole setup and contains further links.**
The precise protocol between the Client and the AS id described
in the documentation of the web app's `authorizations` module.

[the corrresponding firmware's README file]: https://gitlab.com/oscore/coap-ace-poc-firmware/-/blob/main/README.md

Running
-------

As this server needs to run on a publicly reachable host,
and needs HTTPS certificates set up,
it is recommended to use a reverse proxy that handles the public name and SSL.
This server is then run on localhost only, on port 8119,
and can be set up and started like this:

```shell
$ python3 -m venv ./venv
$ source ./venv/bin/activate
$ pip install -r requirements.txt
$ python3 ./demo-as.py
```

License
-------

This project and all files contained in it is published under the
BSD-3-Clause license as defined in [`LICENSES/BSD-3-Clause.txt`](LICENSES/BSD-3-Clause.txt).

Copyright: 2022 EDF (Électricité de France S.A.)

Author: Christian Amsüss
