/*  Checking out the BBS Generation of Generators using @noble/hashes library.

SHAKE256 test vectors verified!

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

SHAKE-256 Test vectors:

```
{
  "BP": "91b784eaac4b2b2c6f9bfb2c9eae97e817dd12bba49a0821d175a50f1632465b319ca9fb81dda3fb0434412185e2cca5",
  "Q1": "b60acd4b0dc13b580394d2d8bc6c07d452df8e2a7eff93bc9da965b57e076cae640c2858fb0c2eaf242b1bd11107d635",
  "Q2": "ad03f655b4c94f312b051aba45977c924bc5b4b1780c969534c183784c7275b70b876db641579604328c0975eaa0a137",
  "MsgGenerators": [
    "b63ae18d3edd64a2edd381290f0c68bebabaf3d37bc9dbb0bd5ad8daf03bbd2c48260255ba73f3389d2d5ad82303ac25",
    "b0b92b79a3e1fc59f39c6b9f78f00b873121c6a4c1814b94c07848efd172762fefbc48447a16f9ba8ed1b638e2933029",
    "b671ed7256777fb5b82f66d1268d03492a1cecc19fd327d56e100cce69c2e15fcd03dcdcfe6b2d42aa039edcd58092f4",
    "867009da287e1186884084ed71477ce9bd401e0bf4a7be48e2af0a3a4f2e7e21d2b7bb0ffdc4c03b5aa9672c3c76e0c9",
    "a3a10489bf1a244753e864454fd24ed8c312f737c0c2a529905222509199a0b48715a048cd93d134dac2cd4934c549bb",
    "81d548904ec8aa58b3f56f69c3f543fb73f339699a33df82c338cad9657b70c457b735c4ae96e8ea0c1ea0da65059d95",
    "b4bbc2a56104c2289fc7688fef30222746467df27698b6c2d53dad5477fd05b7ec8a84122b8122c1de2d2f16750d2a92",
    "ae22a4e89029d3507b8e40af3531b114b564cc77375c249036926e6973f69d21b356e734cdeda47fd320035781eda7df",
    "98b266b03b9cea3d466bafbcd2e1c600c40cba8817d52d46ea77612df911a6e6c040635211fc1bffd4ca914afca1ce55",
    "b458cd3d7af0b5ceea335436a66e2015b216467c204b850b15547f68f6f2a209e8229d154d4f998c7b96aa4f88cdca15"
  ]
}
```

*/

import {bls12_381 as bls} from '@noble/curves/bls12-381';
import { bytesToHex } from '@noble/hashes/utils';
import {i2osp, concat} from './myUtils.js';
import {shake256} from '@noble/hashes/sha3';

function expandMessageXOF(msg, DST, len_in_bytes) {
  let DST_prime = concat(DST, i2osp(DST.length, 1));
  // console.log(bytesToHex(DST_prime))
  let msg_prime = concat(concat(msg, i2osp(len_in_bytes, 2)), DST_prime);
  // console.log(bytesToHex(msg_prime));
  // console.log(`Output length: ${len_in_bytes}`);
  return shake256(msg_prime, {dkLen: len_in_bytes});
}

// **Set up the various IDs and DSTs**
// See [TextEncoder](https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder)
let te = new TextEncoder(); // Used to convert string to uint8Array, utf8 encoding

// - seed_dst, octet string representing the domain separation tag:
//             utf8(ciphersuite_id || "SIG_GENERATOR_SEED_"), where
//             ciphersuite_id is defined by the ciphersuite.
const ciphersuite_id =  "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
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
const seed_len = Math.ceil((Math.ceil(Math.log2(Number(r)) + k)) / 8);
console.log(`seed_len is: ${seed_len}`);
// Use this for the base point P1 generation
// const gen_seed = te.encode("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED");
// Use this for message generator creation
const gen_seed = te.encode("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_MESSAGE_GENERATOR_SEED");
// v = expand_message(generator_seed, seed_dst, seed_len)
let v = expandMessageXOF(gen_seed, seed_dst, seed_len);
console.log("Initial v:");
console.log(bytesToHex(v));
console.log(bls.CURVE.G1.htfDefaults);
let count = 6;
let n = 1;
for (let i = 0; i < count; i++) {
    let v_cat_n_4 = concat(v, i2osp(n, 4));
    console.log("v concatenated with i2osp(n,4):");
    console.log(bytesToHex(v_cat_n_4));
    // order of arguments message, DST, length in bytes
    v = expandMessageXOF(v_cat_n_4, seed_dst, seed_len);
    // console.log("current v:")
    // console.log(bytesToHex(v));
    n = n + 1;
    // candidate = hash_to_curve_g1(v, generator_dst)
    let candidate = await bls.hashToCurve.G1.hashToCurve(v, {DST: gen_dst_string, expand: "xof", hash: shake256});
    console.log("Candidate compressed generator point:");
    console.log(bytesToHex(candidate.toRawBytes(true))); // true for compressed point
}

