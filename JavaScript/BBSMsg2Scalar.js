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
    0x360097633e394c22601426bd9f8d5b95f1c64f89689deee230e817925dee4724n,
    0x1e68fedccc3d68236c7e4ccb508ebb3da5d5de1864eac0a0f683de22752e6d28n,
    0x4d20cb09c2ac1e1c572e83f355b90ea996c7a6ab98a03a98098c1abeb8c7a195n,
    0x038f1892656f7753eb2be1ab3679dd0d0331fb5e7be0f72550dbe22b0f36df02n,
    0x144cb3d17379b746217a93910a8ca07ca7248be3d1972b562010a4e09a27b7f3n,
    0x5da7360f11d5133c6ed6e54c1a1fd230a2c9256d5b6be0b41219808bfc964d28n,
    0x100e944c0a82da79b062a9cc2b014d16b345b4e4624e7408106fe282da0635ccn,
    0x2004000723ef8997256f5f2a86cbef353c3034ab751092033fa0c0a844d639afn,
    0x68a1f58bb5aaa3bc89fba6c40ccd761879fdadf336565cef9812ed5dba5d56can,
    0x1aefbeb8e206723a37fc2e7f8eded8227d960bed44b7089fec0d7e6da93e5d38n
];

// Verify test vectors
for (let i = 0; i < test_msgs.length; i++) {
    let msg = test_msgs[i];
    // Need to "encode to hash" before feeding the message to hash to scalar
    // For a message in octets they use: el_octs = I2OSP(length(el), 8) || el
    let encode_for_hash = concat(i2osp(msg.length, 8), msg)
    let stuff = await hash_to_scalar(encode_for_hash, 1, dst);
    console.log(`Message: ${bytesToHex(msg)}`);
    console.log("Computed scalar in hex:");
    console.log(stuff[0].toString(16));
    console.log("Expected scalar in hex:");
    console.log(expResult[i].toString(16));
}