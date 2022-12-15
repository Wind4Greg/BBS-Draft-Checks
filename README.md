# BBS-Draft-Checks

Coding examples to check procedures in the [draft BBS signature scheme](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) (the *draft*).

These examples try to be minimal in the sense of: 

1. relying on the fewest extra libraries to simplify installation;
2. using straight forward language constructs
3. use high level languages such as Python and JavaScript

They are not examples of secure coding techniques although they are provided to help in verifying the procedures in a draft cryptographic suite.

## Key Generation

## Secret Key Generation

The *draft* contains a procedure (section 3.3.1) for generation of secret key from an initial octet string. See the Jupyter notebook [BBS_KeyGen.ipynb](./Python/BBS_KeyGen.ipynb) or for JavaScript see [BBSKeyGen.js](JavaScript/BBSKeyGen.js).

**Status**: currently working to verify against test in draft.

## Public Key Generation

Given a secret key *Sk* produce a public key *Pk*. This is in the elliptic curve group *G2* of the *pairing*. See [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381#About-curve-BLS12-381) for an overview of pairing based elliptic curve cryptography. However, our application is a signature scheme for things like "credentials" that enhances user privacy. For JavaScript I'm using the [noble cryptography](https://paulmillr.com/noble/) libraries. These are pure JavaScript and easy to install on any platform. 

The JavaScript file [BBSPubKey.js](JavaScript/BBSPubKey.js) shows that this is really easy to do with the [noble-bls12-381](https://github.com/paulmillr/noble-bls12-381) library, i.e., one line of code:

```javascript
import * as bls from '@noble/bls12-381';
import {bytesToHex, hexToBytes } from '@noble/hashes/utils';
let sk = hexToBytes("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56");
// The following function performs the multiplication but also check for valid (within range) sk and
// deals with conversion from bytes to bigInt and such...
let pointSk = bls.PointG2.fromPrivateKey(sk); // Also properly formats curve point!
```

## Hashing to the G1 Curve

A key intermediate step needed below to create the generators in the group G1 is *hashing to an elliptic curve*. This is being standardized in [irtf draft: hash to curve](https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html). The *noble* library (referenced above) provides this capability and runs tests against the test vectors from the draft.

If you want to see a simple usage and test vector verification see the file [Hash2CurveCheckSimple.js](JavaScript/Hash2CurveCheckSimple.js). If you want to see every intermediate step checked against the full test vectors from the draft see the file [Hash2CurveCheck.js](JavaScript/Hash2CurveCheck.js).

## Creating Generators

For the signature scheme a number of distinct generators in the group *G1* are required and the procedure for this is given in the *draft* section 4.1. The JavaScript file [BBSGenGenerators.js](JavaScript/BBSGenGenerators.js) is a **work in progress** implementation.