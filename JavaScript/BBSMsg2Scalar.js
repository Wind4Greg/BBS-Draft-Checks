/*

Want to implement and verify:

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

1. msg_for_hash = encode_for_hash(msg)
2. if msg_for_hash is INVALID, return INVALID
3. if length(dst) > 255, return INVALID
4. return hash_to_scalar(msg_for_hash, 1, dst)
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
```

*/

import {bls12_381 as bls} from '@noble/curves/bls12-381';
import { i2osp, os2ip, concat } from './myUtils.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const k = 128;
const expand_len = Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r))) + k) / 8);
console.log(`expand_len = ${expand_len}`);

async function hash_to_scalar(msg_octets, count, dst) {
    const len_in_bytes = count * expand_len;
    let t = 0;
    let have_scalars = false;
    let scalars = [];
    while (!have_scalars) {
        scalars = [];
        let msg_prime = concat(msg_octets, concat(i2osp(t, 1), i2osp(count, 4)));
        let uniform_bytes = await bls.utils.expandMessageXMD(msg_prime, dst, len_in_bytes);
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
const dst = hexToBytes("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4d41505f4d53475f544f5f5343414c41525f41535f484153485f");
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
0x622c851734b4c0e123583e8b3d889d01908fcf234a9b72ed56ee2bd81c3f89e3n,
0x1a3a33874bbb213c4f364c0cd0cb6e2385e2f3c82a73603f4f0fde0e966c0d86n,
0x4d04c0f1992243dd6a6b9916425e8d921b42e00e366dbbbe73e7089b8147ed82n,
0x075cbc093111b82bbd346358c2ccc96ff6227ae4357705aa48f4988262d5a951n,
0x24513fb9a0726efca9436535f4a436437705f59aaf9b677625b97bf4b99209b3n,
0x36c148fc8169b3f353380a71c0403b8ade704158279a675a753867e60b2a9e84n,
0x577c0cae7ba54d1ed988f186f02e9c76f51769748e2ca3188c37fd57e16a527an,
0x61974ca32bf2ebcf76ee0858962e8c663725f313054e8e75fc767425c31fc8f4n,
0x480a1932dff9d6c5f6f4fb9e9166579a12bbcd2ccb3dc2e9d16a469f85ac9f18n,
0x0d228e6a83b0428d2f77d714629c51eee96ec6f6acf57b61173cbde79d68929fn
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