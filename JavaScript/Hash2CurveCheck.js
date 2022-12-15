/* Check of noble BLS12-381 hash to curve and its use. Checks all intermediate quantities
    specified in the drafts test vectors.

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
import { map_to_curve_simple_swu_3mod4, Fp, isogenyMapG1 } from '@noble/bls12-381/math';
import { sha256 } from '@noble/hashes/sha256';

let te = new TextEncoder(); //  to go from string to uint8Array
let utf8decoder = new TextDecoder(); // to go from uint8Array to string

const testVectors = [
    {
        msg: te.encode(""),
        Px: 0x052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1n,
        Py: 0x08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265n,
        u0: 0x0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564fn,
        u1: 0x019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9n,
        Q0x: 0x11a3cce7e1d90975990066b2f2643b9540fa40d6137780df4e753a8054d07580db3b7f1f03396333d4a359d1fe3766fen,
        Q0y: 0x0eeaf6d794e479e270da10fdaf768db4c96b650a74518fc67b04b03927754bac66f3ac720404f339ecdcc028afa091b7n,
        Q1x: 0x160003aaf1632b13396dbad518effa00fff532f604de1a7fc2082ff4cb0afa2d63b2c32da1bef2bf6c5ca62dc6b72f9cn,
        Q1y: 0x0d8bb2d14e20cf9f6036152ed386d79189415b6d015a20133acb4e019139b94e9c146aaad5817f866c95d609a361735en
    },

    {
        msg: te.encode("abc"),
        Px: 0x03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903n,
        Py: 0x0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885dn,
        u0: 0x0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951n,
        u1: 0x003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139n,
        Q0x: 0x125435adce8e1cbd1c803e7123f45392dc6e326d292499c2c45c5865985fd74fe8f042ecdeeec5ecac80680d04317d80n,
        Q0y: 0x0e8828948c989126595ee30e4f7c931cbd6f4570735624fd25aef2fa41d3f79cfb4b4ee7b7e55a8ce013af2a5ba20bf2n,
        Q1x: 0x11def93719829ecda3b46aa8c31fc3ac9c34b428982b898369608e4f042babee6c77ab9218aad5c87ba785481eff8ae4n,
        Q1y: 0x0007c9cef122ccf2efd233d6eb9bfc680aa276652b0661f4f820a653cec1db7ff69899f8e52b8e92b025a12c822a6ce6n
    },

    {
        msg: te.encode("abcdef0123456789"),
        Px: 0x11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98n,
        Py: 0x03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709n,
        u0: 0x062d1865eb80ebfa73dcfc45db1ad4266b9f3a93219976a3790ab8d52d3e5f1e62f3b01795e36834b17b70e7b76246d4n,
        u1: 0x0cdc3e2f271f29c4ff75020857ce6c5d36008c9b48385ea2f2bf6f96f428a3deb798aa033cd482d1cdc8b30178b08e3an,
        Q0x: 0x08834484878c217682f6d09a4b51444802fdba3d7f2df9903a0ddadb92130ebbfa807fffa0eabf257d7b48272410afffn,
        Q0y: 0x0b318f7ecf77f45a0f038e62d7098221d2dbbca2a394164e2e3fe953dc714ac2cde412d8f2d7f0c03b259e6795a2508en,
        Q1x: 0x158418ed6b27e2549f05531a8281b5822b31c3bf3144277fbb977f8d6e2694fedceb7011b3c2b192f23e2a44b2bd106en,
        Q1y: 0x1879074f344471fac5f839e2b4920789643c075792bec5af4282c73f7941cda5aa77b00085eb10e206171b9787c4169fn
    }
];

// Default hash_to_field options are for hash to G2 so need to set options.
// This is from the noble code:
// Base field F is GF(p^m)
// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
// m = 2 (or 1 for G1)
// k = 128
const options = {
    // DST: a domain separation tag
    DST: "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_",
    // p: the characteristic of F
    //    where F is a finite field of characteristic p and order q = p^m
    p: bls.CURVE.P,
    // m: the extension degree of F, m >= 1
    //     where F is a finite field of characteristic p and order q = p^m
    m: 1,
    // k: the target security level for the suite in bits
    k: 128,
    expand: true,
    hash: sha256,
};


for (let test of testVectors) {
    console.log(`Test message: ${utf8decoder.decode(test.msg)}`);
    let u = await bls.utils.hashToField(test.msg, 2, options);
    console.log("Computed hash to field u0, u1:")
    console.log(u[0][0]);
    console.log(u[1][0]);
    console.log("Expected u0, u1:");
    console.log(test.u0);
    console.log(test.u1);
    let [x0, y0] = map_to_curve_simple_swu_3mod4(new Fp(u[0][0])); // Q0 on iso curve
    let [x1, y1] = map_to_curve_simple_swu_3mod4(new Fp(u[1][0])); // Q1 on iso curve
    const [q0x, q0y] = isogenyMapG1(x0, x1);
    console.log("Computed Q0:");
    console.log(q0x.value);
    console.log(q0y.value);
    console.log("Expected Q0:");
    console.log(test.Q0x);
    console.log(test.Q0y);
    const [q1x, q1y] = isogenyMapG1(x1, y1);
    console.log("Computed Q1:");
    console.log(q1x.value);
    console.log(q1y.value);
    console.log("Expected Q1:");
    console.log(test.Q1x);
    console.log(test.Q1y);
    // These points and the addition are in the E' curve, section 6.6.3 says this is okay
    // when I try the addition in E I don't get the right result.
    const [x2, y2] = new bls.PointG1(x0, y0).add(new bls.PointG1(x1, y1)).toAffine();
    const [x3, y3] = isogenyMapG1(x2, y2);
    let P = new bls.PointG1(x3, y3).clearCofactor();
    let p = P.toAffine();
    console.log("Computed R:");
    console.log(x3.value, y3.value);
    console.log("Computed P:")
    console.log(p[0].value);
    console.log(p[1].value);
    // Or we can have noble do everything for us:
    const pAlt = await bls.PointG1.hashToCurve(test.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_',
    });
    const pAltAff = pAlt.toAffine();
    console.log("PAlt:");
    console.log(pAltAff[0].value);
    console.log(pAltAff[1].value);
    console.log("P expected:");
    console.log(test.Px);
    console.log(test.Py);
}
