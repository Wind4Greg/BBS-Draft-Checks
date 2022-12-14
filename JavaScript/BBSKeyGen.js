/*  Checking out the BBS recommended Key Generation approach using @noble/hashes library.

From the BBS draft:

> L is the integer given by ceil((3 * ceil(log2(r))) / 16).
> INITSALT is the ASCII string "BBS-SIG-KEYGEN-SALT-".

```
Procedure:

1. salt = INITSALT
2. SK = 0
3. while SK == 0:
4.     salt = hash(salt)
5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
7.     SK = OS2IP(OKM) mod r
8. return SK
```

Test vector for keygen from GitHub:

{
  "seed": "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579",
  "keyPair": {
    "publicKey": "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7",
    "secretKey": "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56"
  }
}
*/

import * as bls from '@noble/bls12-381';
import { extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Integer to Octet Stream borrowed from inside bls12-381
function i2osp(value, length) {
    if (value < 0 || value >= 1 << (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
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
let ikm_key_info = hexToBytes("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
let ikm = hexToBytes("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
console.log("IKM in bytes:")
console.log(ikm);
let bbsSalt = "BBS-SIG-KEYGEN-SALT-";
console.log(bbsSalt);
// He takes either UInt8Array or string, if string turns it into UTF-8 bytes
bbsSalt = sha256(bbsSalt);
console.log("Hashed BBS salt:")
console.log(bytesToHex(bbsSalt));
// uInt8Array  from string to check on salt and hashing
let saltCheck = new TextEncoder().encode("BBS-SIG-KEYGEN-SALT-");
console.log("Hashed Salt Check:");
console.log(bytesToHex(sha256(saltCheck)));

// console.log(bls.CURVE);
let r = bls.CURVE.r;
// L is the integer given by ceil((3 * ceil(log2(r))) / 16).
let L = Math.ceil((3 * Math.ceil(Math.log2(Number(r)))) / 16);
console.log(`L is: ${L}`);

// PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
// Different HKDF libraries vary in the order of arguments
let prk = extract(sha256, concat(ikm, i2osp(0, 1)), bbsSalt);
console.log("check concatenation:");
console.log(bytesToHex(concat(ikm, i2osp(0, 1))));
console.log("PRK:");
console.log(bytesToHex(prk));
// let prk = extract(sha256, bbsSalt, concat(ikm, i2osp(0, 1)));
// OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
let okm = expand(sha256, prk, concat(ikm_key_info, i2osp(L, 2)), L);
// let okm = expand(sha256, prk, i2osp(L, 2), L);
console.log("OKM:");
console.log(bytesToHex(okm));
// SK = OS2IP(OKM) mod r
let sk = bls.utils.mod(os2ip(okm), r);
console.log("SK as integer:");
console.log(sk);
console.log("SK as hex bytes:");
console.log(sk.toString(16));
