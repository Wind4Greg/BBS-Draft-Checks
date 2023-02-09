/*

Implemented and verified with SHAKE256!

```
result = MapMessageToScalarAsHash(msg, dst)

Inputs:

- msg (REQUIRED), octet string.
- dst (OPTIONAL), an octet string representing a domain separation tag.
                  If not supplied, it default to the octet string
                  utf8(ciphersuite_id || "MAP_MSG_TO_SCALAR_AS_HASH_")
                  where ciphersuite_id is defined by the ciphersuite.

Outputs:

- result, a scalar value.

Procedure:

1. if length(msg) > 2^64 - 1 or length(dst) > 255 return INVALID
2. msg_scalar = hash_to_scalar(msg, 1, dst)
3. if msg_scalar is INVALID, return INVALID
4. return msg_scalar
```

Will implement *encode_for_hash* just for the case of a single "message".

Section 4.3 Hash to Scalar:

```
scalars = hash_to_scalar(msg_octets, count, dst)

Inputs:

- msg_octets (REQUIRED), octet string. The message to be hashed.
- count (REQUIRED), an integer greater or equal to 1. The number of
                    scalars to output.
- dst (OPTIONAL), an octet string representing a domain separation tag.
                  If not supplied, it defaults to the octet string given
                  by utf8(ciphersuite_id || "H2S_"), where
                  ciphersuite_id is defined by the ciphersuite.

Parameters:

- hash_to_curve_suite, the hash to curve suite id defined by the
                       ciphersuite.
- expand_message, the expand_message operation defined by the suite
                  specified by the hash_to_curve_suite parameter.

Definitions:

- expand_len = ceil((ceil(log2(r))+k)/8), where r and k are defined by
                                          the ciphersuite.

Outputs:

- scalars, an array of non-zero scalars mod r.

Procedure:

1.  len_in_bytes = count * expand_len
2.  t = 0
3.  msg_prime = msg_octets || I2OSP(t, 1) || I2OSP(count, 4)
4.  uniform_bytes = expand_message(msg_prime, dst, len_in_bytes)
5.  for i in (1, ..., count):
6.      tv = uniform_bytes[(i-1)*expand_len..i*expand_len-1]
7.      scalar_i = OS2IP(tv) mod r
8.  if 0 in (scalar_1, ..., scalar_count):
9.      t = t + 1
10.     go back to step 3
11. return (scalar_1, ..., scalar_count)

From the hash to curve spec https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-expand_message_xof:

expand_message_xof(msg, DST, len_in_bytes)

Parameters:
- H(m, d), an extendable-output function that processes
           input message m and returns d bytes.

Input:
- msg, a byte string.
- DST, a byte string of at most 255 bytes.
  See below for information on using longer DSTs.
- len_in_bytes, the length of the requested output in bytes.

Output:
- uniform_bytes, a byte string.

Steps:
1. ABORT if len_in_bytes > 65535 or len(DST) > 255
2. DST_prime = DST || I2OSP(len(DST), 1)
3. msg_prime = msg || I2OSP(len_in_bytes, 2) || DST_prime
4. uniform_bytes = H(msg_prime, len_in_bytes)
5. return uniform_bytes

For test vectors see: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-expand_message_xofshake256

name    = expand_message_xof
DST     = QUUX-V01-CS02-with-expander-SHAKE256
hash    = SHAKE256
k       = 256

msg     =
len_in_bytes = 0x20
DST_prime = 515555582d5630312d435330322d776974682d657870616e6465
          722d5348414b4532353624
msg_prime = 0020515555582d5630312d435330322d776974682d657870616e
          6465722d5348414b4532353624
uniform_bytes = 2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8
          fed38c5ccc15ad76

msg     = abc
len_in_bytes = 0x20
DST_prime = 515555582d5630312d435330322d776974682d657870616e6465
          722d5348414b4532353624
msg_prime = 6162630020515555582d5630312d435330322d776974682d6578
          70616e6465722d5348414b4532353624
uniform_bytes = b39e493867e2767216792abce1f2676c197c0692aed06156
          0ead251821808e07

msg     =
len_in_bytes = 0x80
DST_prime = 515555582d5630312d435330322d776974682d657870616e6465
          722d5348414b4532353624
msg_prime = 0080515555582d5630312d435330322d776974682d657870616e
          6465722d5348414b4532353624
uniform_bytes = 7a1361d2d7d82d79e035b8880c5a3c86c5afa719478c007d
          96e6c88737a3f631dd74a2c88df79a4cb5e5d9f7504957c70d669e
          c6bfedc31e01e2bacc4ff3fdf9b6a00b17cc18d9d72ace7d6b81c2
          e481b4f73f34f9a7505dccbe8f5485f3d20c5409b0310093d5d649
          2dea4e18aa6979c23c8ea5de01582e9689612afbb353df
```

*/

import {bls12_381 as bls} from '@noble/curves/bls12-381';
import { i2osp, os2ip, concat } from './myUtils.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {shake256} from '@noble/hashes/sha3';

const k = 128;
const expand_len = Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r))) + k) / 8);
console.log(`expand_len = ${expand_len}`);

function expandMessageXOF(msg, DST, len_in_bytes) {
    let DST_prime = concat(DST, i2osp(DST.length, 1));
    // console.log(bytesToHex(DST_prime))
    let msg_prime = concat(concat(msg, i2osp(len_in_bytes, 2)), DST_prime);
    // console.log(bytesToHex(msg_prime));
    // console.log(`Output length: ${len_in_bytes}`);
    return shake256(msg_prime, {dkLen: len_in_bytes});
}

async function hash_to_scalar(msg_octets, count, dst) {
    const len_in_bytes = count * expand_len;
    let t = 0;
    let have_scalars = false;
    let scalars = [];
    while (!have_scalars) {
        scalars = [];
        let msg_prime = concat(msg_octets, concat(i2osp(t, 1), i2osp(count, 4)));
        let uniform_bytes = expandMessageXOF(msg_prime, dst, len_in_bytes);
        have_scalars = true;
        for (let i = 0; i < count; i++) {
            let tv = uniform_bytes.slice(i * expand_len, (i + 1) * expand_len);
            // console.log(`length tv: ${tv.length}`);
            let scalar_i = os2ip(tv) % bls.CURVE.r;
            scalars[i] = scalar_i;
            if (scalar_i === 0n) {
                have_scalars = false;
            }
        }
        t++;
    }
    return scalars;
}

// Test vector data
const dst = hexToBytes("4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4d41505f4d53475f544f5f5343414c41525f41535f484153485f");
let test_msgs = [
    hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
    hexToBytes("87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6"),
    hexToBytes("96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"),
    hexToBytes("ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943"),
    hexToBytes("d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151"),
    hexToBytes("515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc"),
    hexToBytes("496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2"),
    hexToBytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91"),
    hexToBytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416"),
    hexToBytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80")
];

const expResult = [ // Expected results from the draft
0x7237d3bc7a74563dfa26ab4ea12636309b409844fdafd4ba3e8fb5ed9e963d46n,
0x3e03ad64244fe56a611b48803b49a3b2ee2c0e1560004754e7507289e1583dd3n,
0x514d242186e3a1a6a2d29da19476fbbf75b6ca5bb4b3c343952ab671febd4d26n,
0x1573b59bcf41e52c8379297dbc96b7eaa81e54d89d2bf706a646fa41eef299c7n,
0x1a03705148804a1241291f6a23828b6ae768b28f1d6a4fc9160be700449727e3n,
0x5370023423d8cd321d6ca6860d6d0a64c0c071dab14d4cdc203a2b4ad31c593cn,
0x5777409cb77f5ab83f9f66fe730f982c76af36af77dc87a50f0e5da0d6ba2cden,
0x6ea4014f9f3e7f109d31d691ea1b1a189e486f77186d73ceb7ff0eeccca19585n,
0x0950afe51240f19b2f8224a233c218b73c25b2a15d5f12f7910cd0a91e7505e0n,
0x6f7d4fe30cc68a3a92c47fcf2882cd8ddea82dcebcf59c5a23a8266a88a42d91n
];

// Verify test vectors
for (let i = 0; i < test_msgs.length; i++) {
    let msg = test_msgs[i];
    let stuff = await hash_to_scalar(msg, 1, dst);
    console.log(`Message: ${bytesToHex(msg)}`);
    console.log("Computed scalar in hex:");
    console.log(stuff[0].toString(16));
    console.log("Expected scalar in hex:");
    console.log(expResult[i].toString(16));
}

// Check expand_xof
let te = new TextEncoder(); 
let DST = "QUUX-V01-CS02-with-expander-SHAKE256";
let DST_bytes = te.encode(DST);
// hash    = SHAKE256
// k       = 256
let msg = new Uint8Array();
let len_in_bytes = 0x20;
// let DST_prime = hexToBytes("515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624");
// let msg_prime = hexToBytes("0020515555582d5630312d435330322d776974682d657870616e6465722d5348414b4532353624");
// let uniform_bytes = "2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8fed38c5ccc15ad76";
let result = await expandMessageXOF(msg, DST_bytes, len_in_bytes);
console.log(bytesToHex(result));
result = await expandMessageXOF(msg, DST_bytes, 0x80);
console.log(bytesToHex(result));