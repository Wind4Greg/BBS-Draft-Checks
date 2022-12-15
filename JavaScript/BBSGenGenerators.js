/*  Checking out the BBS Generation of Generators using @noble/hashes library.

Currently **NOT** able to verify/generate generators. Am able to verify valid that given
generators are valid curve points.

From the BBS draft:

```
generators = create_generators(count)

Inputs:

- count (REQUIRED), unsigned integer. Number of generators to create.

Parameters:

- hash_to_curve_suite, the hash to curve suite id defined by the
                       ciphersuite.
- hash_to_curve_g1, the hash_to_curve operation for the G1 subgroup,
                    defined by the suite specified by the
                    hash_to_curve_suite parameter.
- expand_message, the expand_message operation defined by the suite
                  specified by the hash_to_curve_suite parameter.
- generator_seed, octet string. A seed value selected by the
                  ciphersuite.
- P1, fixed point of G1, defined by the ciphersuite.

Definitions:

- seed_dst, octet string representing the domain separation tag:
            utf8(ciphersuite_id || "SIG_GENERATOR_SEED_"), where
            ciphersuite_id is defined by the ciphersuite.
- generator_dst, octet string representing the domain separation tag:
                 utf8(ciphersuite_id || "SIG_GENERATOR_DST_"), where
                 ciphersuite_id is defined by the ciphersuite.
- seed_len = ceil((ceil(log2(r)) + k)/8), where r and k are defined by
                                          the ciphersuite.

Outputs:

- generators, an array of generators.

Procedure:

1.  v = expand_message(generator_seed, seed_dst, seed_len)
2.  n = 1
3.  for i in range(1, count):
4.     v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
5.     n = n + 1
6.     generator_i = Identity_G1
7.     candidate = hash_to_curve_g1(v, generator_dst)
8.     if candidate in (generator_1, ..., generator_i):
9.        go back to step 4
10.    generator_i = candidate
11. return (generator_1, ..., generator_count)
```

Test vectors:

```
{
  "BP": "8533b3fbea84e8bd9ccee177e3c56fbe1d2e33b798e491228f6ed65bb4d1e0ada07bcc4489d8751f8ba7a1b69b6eecd7",
  "Q1": "b57ec5e001c28d4063e0b6f5f0a6eee357b51b64d789a21cf18fd11e73e73577910182d421b5a61812f5d1ca751fa3f0",
  "Q2": "909573cbb9da401b89d2778e8a405fdc7d504b03f0158c31ba64cdb9b648cc35492b18e56088b44c8b4dc6310afb5e49",
  "MsgGenerators": [
    "90248350d94fd550b472a54269e28b680757d8cbbe6bb2cb000742c07573138276884c2872a8285f4ecf10df6029be15",
    "8fb7d5c43273a142b6fc445b76a8cdfc0f96c5fdac7cdd73314ac4f7ec4990a0a6f28e4ad97fb0a3a22efb07b386e3ff",
    "8241e3e861aaac2a54a8d7093301143d7d3e9911c384a2331fcc232a3e64b4882498ce4d9da8904ffcbe5d6eadafc82b",
    "99bb19d202a4019c14a36933264ae634659994076bf02a94135e1026ea309c7d3fd6da60c7929d30b656aeaba7c0dcec",
    "81779fa5268e75a980799c0a01677a763e14ba82cbf0a66c653edc174057698636507ac58e73522a59585558dca80b42",
    "98a3f9af71d391337bc6ae5d26980241b6317d5d71570829ce03d63c17e0d2164e1ad793645e1762bfcc049a17f5994b",
    "aca6a84770bb1f515591b4b95d69777856ddc52d5439325839e31ce5b6237618a9bc01a04b0057d33eab14341504c7e9",
    "b96e206d6cf32b51d2f4d543972d488a4c4cbc5d994f6ebb0bdffbc5459dcb9a8e5ab045c5949dc7eb33b0545b62aae3",
    "8edf840b56ecf8d7c5a9c4a0aaf8a5525f3480df735743298dd2f4ae1cbb56f56ed6a04ef6fa7c92cd68d9101c7b8c8f",
    "86d4ae04738dc082eb37e753bc8ec35a8d982e463559214d0f777599f71aa1f95780b3dccbdcae45e146e5c7623dfe7d"
  ]
}
```

*/

import * as bls from '@noble/bls12-381';

import { hkdf, extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Integer to Octet Stream borrowed from inside bls12-381
function i2osp(value, length) {
    // This check fails if length is 4 or greater since the integer raps around in the browser
    // if (value < 0 || value >= 1 << (8 * length)) {
    //     throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    // }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8;
    }
    return new Uint8Array(res);
}

// Octet Stream to Integer (bytesToNumberBE)
function os2ip(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result <<= 8n;
        result += BigInt(bytes[i]);
    }
    return result;
}

// Strange that this doesn't exist...
function concat(buffer1, buffer2) {
    let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    for (let i = 0; i < buffer1.byteLength; i++) tmp[i] = buffer1[i];
    for (let i = 0; i < buffer2.byteLength; i++) tmp[i + buffer1.byteLength] = buffer2[i];
    return tmp;
};

// **Set up the various IDs and DSTs**
let te = new TextEncoder(); // Used to convert to
// - seed_dst, octet string representing the domain separation tag:
//             utf8(ciphersuite_id || "SIG_GENERATOR_SEED_"), where
//             ciphersuite_id is defined by the ciphersuite.
const ciphersuite_id =  "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
// See [TextEncoder](https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder)
const seed_dst = te.encode(ciphersuite_id + "SIG_GENERATOR_SEED_");
// - generator_dst, octet string representing the domain separation tag:
//                  utf8(ciphersuite_id || "SIG_GENERATOR_DST_"), where
//                  ciphersuite_id is defined by the ciphersuite.
const gen_dst = te.encode(ciphersuite_id + "SIG_GENERATOR_DST_");
const gen_dst_string = ciphersuite_id + "SIG_GENERATOR_DST_";
const r = bls.CURVE.r;
// From section 6.2
const k = 128
// - seed_len = ceil((ceil(log2(r)) + k)/8), where r and k are defined by
//                                           the ciphersuite.
const seed_len = Math.ceil((Math.ceil(Math.log2(Number(r)) + k)) / 16);
console.log(`seed_len is: ${seed_len}`);
const gen_seed = te.encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED");
// v = expand_message(generator_seed, seed_dst, seed_len)
let v = await bls.utils.expandMessageXMD(gen_seed, seed_dst, seed_len);
console.log(v);
let count = 3;
let n = 1;
// console.log(i2osp(1,4));
for (let i = 0; i < count; i++) {
    v = await bls.utils.expandMessageXMD(concat(v, i2osp(n, 4)), seed_dst, seed_len);
    console.log(v);
    n = n + 1;
    // candidate = hash_to_curve_g1(v, generator_dst)
    let thingy = await bls.PointG1.hashToCurve(v, {DST: gen_dst_string});
    console.log(thingy);
    console.log(bytesToHex(thingy.toRawBytes(true)));
}

let basePtG1 = bls.PointG1.BASE;
console.log(bytesToHex(basePtG1.toRawBytes(true)));

// Try taking one of the test vector points and see if it is really on the
// curve and if we can get it back. Will throw and exception if not a valid curve point
let samplePt = bls.PointG1.fromHex("8533b3fbea84e8bd9ccee177e3c56fbe1d2e33b798e491228f6ed65bb4d1e0ada07bcc4489d8751f8ba7a1b69b6eecd7");
console.log(samplePt);
// Note the parameter toRawBytes is *isCompressed* which encodes the sign of y and the x value
// Non-compressed gives you x and y.
console.log(bytesToHex(samplePt.toRawBytes(true)));