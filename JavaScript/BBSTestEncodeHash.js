/* Test out our encode for hash function */
// Things to try: "PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"

import * as bls from '@noble/bls12-381';
import { encode_to_hash } from './BBSEncodeHash.js';

import {bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { i2osp, os2ip, concat } from './myUtils.js';

// Try public key in G2 created from sk
console.log("Encode Public Key:");
let sk = hexToBytes("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56");
let pointPk = bls.PointG2.fromPrivateKey(sk);
let pk = pointPk.toRawBytes(true);
let pubKeyEl = {type: "PublicKey", value: pk};
let result = encode_to_hash([pubKeyEl]);
console.log(bytesToHex(pk));
console.log(bytesToHex(result));

console.log("\nEncode Non negative integer:");
let intEl = {type: "NonNegInt", value: 12};
result = encode_to_hash([intEl]);
console.log(bytesToHex(result));

console.log("\nEncode curve points:");
let g1El = {type: "GPoint", value: bls.PointG1.BASE};
let g2El = {type: "GPoint", value: bls.PointG2.BASE};
result = encode_to_hash([g1El, g2El]);
console.log(bytesToHex(result));
console.log(bytesToHex(concat(bls.PointG1.BASE.toRawBytes(true), bls.PointG2.BASE.toRawBytes(true))));

console.log("\nEncode scalar:");
let scalar = 0x47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56n;
let scalarEl = {type: "Scalar", value: scalar};
let scalarEl2 = {type: "Scalar", value: 3n};
result = encode_to_hash([scalarEl, scalarEl2]);
console.log(bytesToHex(result));

console.log("\nEncode plain octets:");
let octetThing = new Uint8Array([21, 12]);
let octetEl = {type: "PlainOctets", value: octetThing};
result = encode_to_hash([octetEl]);
console.log(bytesToHex(result));

console.log("\nEncode cipher id:");
let cipherId = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
let ciEl = {type: "CipherID", value: cipherId};
result = encode_to_hash([ciEl]);
console.log(bytesToHex(result));
console.log(bytesToHex(new TextEncoder().encode(cipherId)));

console.log("\nEncode general ASCII:");
let asciiEl = {type: "ASCII", value: "hello"};
result = encode_to_hash([asciiEl]);
console.log(bytesToHex(result));
console.log(bytesToHex(new TextEncoder().encode(asciiEl.value)));

console.log("\nEncode general ASCII and and integer:");
result = encode_to_hash([asciiEl, intEl]);
console.log(bytesToHex(result));
