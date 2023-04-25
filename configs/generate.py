# SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
# SPDX-License-Identifier: BSD-3-Clause
# See README for all details on copyright, authorship and license.

import secrets
import yaml

for i in range(10):
    d = {
        'issuer': "AS",
        'as_uri': "https://as.coap.amsuess.com/token",
        }
    d['audience'] = "d%02d" % i
    d['key'] = secrets.token_bytes(32).hex()
    with open("%s.yaml" % d['audience'], "w") as o:
        o.write('''# SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
# SPDX-License-Identifier: BSD-3-Clause
# See README for all details on copyright, authorship and license.
''')
        yaml.dump(d, o)
