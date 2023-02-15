/* Random scalars and mock random scalars functions

random_scalars = calculate_random_scalars(count)

Inputs:

- count (REQUIRED), non negative integer. The number of pseudo random
                    scalars to return.

Parameters:

- get_random, a pseudo random function with extendable output, returning
              uniformly distributed pseudo random bytes.
- expand_len = ceil((ceil(log2(r))+k)/8), where r and k are defined by
                                          the ciphersuite.

Outputs:

- random_scalars, a list of pseudo random scalars,

Procedure:

1. for i in (1, ..., count):
2.     r_i = OS2IP(get_random(expand_len)) mod r
3. return (r_1, r_2, ..., r_count)

seeded_scalars = seeded_random_scalars(SEED, count)

Inputs:

- count (REQUIRED), non negative integer. The number of scalars to
                    return.
- SEED (REQUIRED), octet string. The random seed from which to generate
                   the scalars.

Parameters:

- expand_message, the expand_message operation defined by the
                  ciphersuite.
- expand_len = ceil((ceil(log2(r))+k)/8), where r and k are defined by
                                          the ciphersuite.
- dst = utf8(ciphersuite_id || "MOCK_RANDOM_SCALARS_DST_"), where
      ciphersuite_id is defined by teh ciphersuite.

Outputs:

- mocked_random_scalars, a list of "count" pseudo random scalars

Preconditions:

1. if count * expand_len > 65535, return INVALID

Procedure:

1. out_len = expand_len * count
2. v = expand_message(SEED, dst, out_len)
3. if v is INVALID, return INVALID

4. for i in (1, ..., count):
5.     start_idx = (i-1) * expand_len
6.     end_idx = i * expand_len - 1
7.     r_i = OS2IP(v[start_idx..end_idx]) mod r
8. return (r_1, ...., r_count)


 
 */
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import { hexToBytes } from '@noble/hashes/utils';
import { randomBytes } from '@noble/hashes/utils';
import { i2osp, concat, os2ip, numberToBytesBE} from './myUtils.js';
const EXPAND_LEN = 48;
const SEED_LEN = 48;
const CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
let te = new TextEncoder();
const DST = te.encode(CIPHERSUITE_ID + "MOCK_RANDOM_SCALARS_DST_");

export function calculate_random_scalars(count) {
    // 1. for i in (1, ..., count):
    // 2.     r_i = OS2IP(get_random(expand_len)) mod r
    // 3. return (r_1, r_2, ..., r_count)
    let scalars = [];
    for (let i = 0; i < count; i++) {
        let r_i = os2ip(randomBytes(EXPAND_LEN)) % bls.CURVE.r;
        scalars.push(r_i);
    }
    return scalars;
}

export async function seeded_random_scalars(seed, count) {
    // 1. out_len = expand_len * count
    let out_len = EXPAND_LEN * count;
    // 2. v = expand_message(SEED, dst, out_len)
    let v = await bls.utils.expandMessageXMD(seed, DST, out_len);
    // 3. if v is INVALID, return INVALID
    let scalars = [];
    // 4. for i in (1, ..., count):
    // 5.     start_idx = (i-1) * expand_len
    // 6.     end_idx = i * expand_len - 1
    // 7.     r_i = OS2IP(v[start_idx..end_idx]) mod r
    for (let i = 0; i < count; i++) {
        let tv = v.slice(i * EXPAND_LEN, (i + 1) * EXPAND_LEN);
        // console.log(`length tv: ${tv.length}`);
        let scalar_i = os2ip(tv) % bls.CURVE.r;
        scalars[i] = scalar_i;
    }
    // 8. return (r_1, ...., r_count)
    return scalars
}

let seed = hexToBytes("332e313431353932363533353839373933323338343632363433333833323739");
console.log("Calling seeded random scalars");
let ten_scalars = await seeded_random_scalars(seed, 10);

console.log(ten_scalars);
let hex_ten_scalars = ten_scalars.map(s=>s.toString(16));
console.log(hex_ten_scalars);
// console.log("Calling random scalars");
// two_scalars = calculate_random_scalars(2);
// console.log(two_scalars);