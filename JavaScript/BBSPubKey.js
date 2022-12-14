/*  Checking out the BBS public key generation from secret scalar. 
    This is done in the group G2 and not the G1 group.

```
Procedure:

```
PK = SkToPk(SK)

Inputs:

- SK (REQUIRED), a secret integer such that 0 < SK < r.

Outputs:

- PK, a public key encoded as an octet string.

Procedure:

1. W = SK * P2
2. return point_to_octets_g2(W)
```

Test vector for keygen from GitHub:

{
  "seed": "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579",
  "keyPair": {
    "publicKey": "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7",
    "secretKey": "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56"
  }
}

*/

import * as bls from '@noble/bls12-381';
import {bytesToHex, hexToBytes } from '@noble/hashes/utils';

let sk = hexToBytes("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56");
console.log("sk in bytes:")
console.log(sk);

// The following function performs the multiplication but also check for valid (within range) sk and
// deals with conversion from bytes to bigInt and such...
let pointSk = bls.PointG2.fromPrivateKey(sk);
let pointSkHex = bytesToHex(pointSk.toRawBytes(true));
let test1 = "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7";
console.log(`First test pass: ${test1 == pointSkHex}, pubkey1:\n`); // Checks
console.log(pointSkHex);
