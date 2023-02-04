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
    "publicKey": "aaff983278257afc45fa9d44d156c454d716fb1a250dfed132d65b2009331f618c623c14efa16245f50cc92e60334051087f1ae92669b89690f5feb92e91568f95a8e286d110b011e9ac9923fd871238f57d1295395771331ff6edee43e4ccc6",
    "secretKey": "4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7"
  }
}

*/

import {bls12_381 as bls} from '@noble/curves/bls12-381';
import {bytesToHex, hexToBytes } from '@noble/hashes/utils';

// let sk = hexToBytes("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56");
let sk = hexToBytes("4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7");
console.log("sk in bytes:")
console.log(sk);

// The following function performs the multiplication but also check for valid (within range) sk and
// deals with conversion from bytes to bigInt and such...
console.log(bls.G2);
let pointSk = bls.G2.ProjectivePoint.fromPrivateKey(sk)
let pointSkHex = bytesToHex(pointSk.toRawBytes(true));
let test1 = "aaff983278257afc45fa9d44d156c454d716fb1a250dfed132d65b2009331f618c623c14efa16245f50cc92e60334051087f1ae92669b89690f5feb92e91568f95a8e286d110b011e9ac9923fd871238f57d1295395771331ff6edee43e4ccc6";
console.log(`First test pass: ${test1 == pointSkHex}, pubkey1:\n`); // Checks
console.log(pointSkHex);
