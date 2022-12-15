/* Check of noble BLS12-381 hash to curve and its use. Only check final output
    curve point P.

The BBS signature scheme uses the call "hash_to_curve_g1(v, generator_dst)".

From the hash to curve draft 
https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-bls12-381-g1-2

General Algorithm:

```
hash_to_curve(msg)

Input: msg, an arbitrary-length byte string.
Output: P, a point in G.

Steps:
1. u = hash_to_field(msg, 2)
2. Q0 = map_to_curve(u[0])
3. Q1 = map_to_curve(u[1])
4. R = Q0 + Q1              # Point addition
5. P = clear_cofactor(R)
6. return P
```

```
 J.9.1. BLS12381G1_XMD:SHA-256_SSWU_RO_

suite   = BLS12381G1_XMD:SHA-256_SSWU_RO_
dst     = QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_
```

Test vectors moved to code below. Everything is **verifying**.
*/

import * as bls from '@noble/bls12-381';

let te = new TextEncoder(); //  to go from string to uint8Array
let utf8decoder = new TextDecoder(); // to go from uint8Array to string

const testVectors = [
    {
        msg: te.encode(""),
        Px: 0x052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1n,
        Py: 0x08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265n,
     },

    {
        msg: te.encode("abc"),
        Px: 0x03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903n,
        Py: 0x0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885dn,
      },

    {
        msg: te.encode("abcdef0123456789"),
        Px: 0x11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98n,
        Py: 0x03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709n,
   }
];


for (let test of testVectors) {
    console.log(`Test message: ${utf8decoder.decode(test.msg)}`);
    console.log("Computed P:")
    const pCalc = await bls.PointG1.hashToCurve(test.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_',
    });
    const pCalcAff = pCalc.toAffine();
    console.log(pCalcAff[0].value);
    console.log(pCalcAff[1].value);
    console.log("P expected:");
    console.log(test.Px);
    console.log(test.Py);
}
