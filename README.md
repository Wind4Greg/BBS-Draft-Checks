# BBS-Draft-Checks

Coding examples to check procedures in the [draft BBS signature scheme](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) (the *draft*).

These examples try to be minimal in the sense of:

1. relying on the fewest extra libraries to simplify installation;
2. using straight forward language constructs
3. use high level languages such as Python and JavaScript

They are not examples of secure coding techniques although they are provided to help in verifying the procedures in a draft cryptographic suite.

***Update***: The verification of the draft has been going quite well so I've decided to create a [BBSAllinOne.js](JavaScript/AllinOne/BBSAllinOne.js) file that only depends on [noble-bls12-381](https://github.com/paulmillr/noble-bls12-381) and [noble-hashes](https://www.npmjs.com/package/@noble/hashes) to use in demonstrations of BBS signatures. Example uses are given in [SignVerifyExample.js](JavaScript/AllinOne/SignVerifyExample.js) and [ProofGenVerifyExample.js](JavaScript/AllinOne/ProofGenVerifyExample.js).

## Key Generation

## Secret Key Generation

The *draft* contains a procedure (section 3.3.1) for generation of secret key from an initial octet string. See the Jupyter notebook [BBS_KeyGen.ipynb](./Python/BBS_KeyGen.ipynb) or for JavaScript see [BBSKeyGen.js](JavaScript/BBSKeyGen.js).

All checks pass with updated BBS+ test vectors.

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

If you want to see a simple usage and test vector verification see the file [Hash2CurveCheckSimple.js](JavaScript/Hash2CurveCheckSimple.js).

## Creating Generators

For the signature scheme a number of distinct generators in the group *G1* are required and the procedure for this is given in the *draft* section 4.1. The JavaScript file [BBSGenGenerators.js](JavaScript/BBSGenGenerators.js) shows how to do this and verifies against the draft test vectors. For the variant based on SHAKE-256 hashes see [BBSGenGenerators-SHAKE.js](JavaScript/BBSGenGenerators-SHAKE.js).

## Signing Pre-computations

Need to implement *MapMessageToScalar* per draft section 4.2.1. This requires implementing the functions *encode_for_hash()* and *hash_to_scalar()*. For individual messages the *encode_for_hash()* so I embedded it the the JavaScript file [BBSMsg2Scalar.js](JavaScript/BBSMsg2Scalar.js) which implements the *hash_to_scalar()* function and verifies it against the test vectors in section 7.4.1 of the draft. For the variant based on SHAKE-256 hashes see [BBSMsg2Scalar-SHAKE.js](JavaScript/BBSMsg2Scalar-SHAKE.js).

## Signing

Implemented and tested in file [BBSSign.js](JavaScript/BBSSign.js) with additional functions in [BBSEncodeHash.js](JavaScript/BBSEncodeHash.js) to put things in the proper format prior to hashing and some helpers in [myUtils.js](JavaScript/myUtils.js).

Verified against SHA-256 cases: [signature001.json](https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature001.json) (single message), and [signature004.json](https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature004.json).

## Verifying

Implemented and tested in file [BBSVerify.js](JavaScript/BBSVerify.js). Note that for now I just copied over the helper functions implemented in the [BBSSign.js](JavaScript/BBSSign.js). The new stuff in here are some computations in G2, the use of the elliptic curve pairing function, and some computations in GT, i.e., $F_{p^{12}}$.

## Proof Generation

Proof generation starts from a signature generated by the [BBSSign.js](JavaScript/BBSSign.js) code. The [BBSProofGen.js](JavaScript/BBSProofGen.js) code allows one to produce "proof" that can be verified against the original signers public key. However the "proof" can reveal only a subset of the original messages that were signed at the discretion of the "holder", i.e., the receiver of the signature, doesn't have to divulge all the messages if it doesn't want to.  Due to the anonymizing properties of proof generation no test vectors are provided and the output of proof generation needs to be checked with the *proof verification* code of the next section. To do this the [BBSProofGen.js](JavaScript/BBSProofGen.js) code generates a JSON file like the one shown below that contains all the information needed in the proof verification step.

```json
{
  "pk": "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7",
  "header": "11223344556677889900aabbccddeeff",
  "ph": "",
  "disclosedIndexes": [0, 1, 2, 3, 6, 7, 8, 9],
  "disclosedMsgs": [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
    "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
    "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943",
    "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  ],
  "totalMsgs": 10,
  "proof": "97d551d4e3af97c2bfd49a06dc80bddadcd4bc30ae6bdf4a7c3778676b2f69318daaccf710f40e91736c5e59114f4bc881876d1832296a2a8a0c6cbd74482c335fd1ec261965c0d5e3f3cdb6ee1cf0a99c6cd6e17a50c06b8d8b5302fd46918d8cea6cc7867502ad9e50cebd68a00f8c6cb4f3176996b19c97ea9f754d83df2def093f04a2e2c87d6b0ed6b39168e711204418c9b486dcfb65726fd6545d4e2db94c25cb09c4faa5a95a6e0145900b6d29d49df2d97aa9ff07dd3f1cf62e7b8f131bf728c426c0af00dfaf01f133a5b22c26a422a45cf1de17012243025c16828fa860aef6c7c0723dc126fc2bc3d657054a15335723938e2d70d18b841f5ee7bcda38ef11634d17e7849b60add97b2d71e75163b7e9af935c8a78ed784e0efbcbde3049fc8e7f24b1e66b461c0466475ade0c922671d8e2d5b3d1745e17882d1d9d52495d1cde354a5092f4a18fda201a119fa5b9a8a601c57a730695c8de08ecedc0fa629475d744d23c06c31aae13"
}
```

## Proof Verification

This is implemented in the file [BBSProofVerify.js](JavaScript/BBSProofVerify.js) and has been tested against test cases from the draft and from the [BBSProofGen.js](JavaScript/BBSProofGen.js) code.

## Mocking Random Scalars

For the purpose of generating test vectors for proof generation the draft will be specifying a seeded pseudo random scalar generation technique. This is being implemented in [BBSRandomScalars.js](JavaScript/BBSRandomScalars.js). *Verification in process*.