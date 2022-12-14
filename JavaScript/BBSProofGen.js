/* BBS Proof Generation, from the draft:

proof = ProofGen(PK, signature, header, ph, messages, disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), octet string containing the presentation header. If not
                 supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of scalars. If not supplied, it defaults
                       to the empty array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- ciphersuite_id, ASCII string. The unique ID of the ciphersuite.
- P1, fixed point of G1, defined by the ciphersuite.

Definitions:

- L, is the non-negative integer representing the number of messages,
     i.e., L = length(messages). If no messages are supplied, the
     value of L MUST evaluate to zero (0).
- R, is the non-negative integer representing the number of disclosed
     (revealed) messages, i.e., R = length(disclosed_indexes). If no
     messages are disclosed, R MUST evaluate to zero (0).
- U, is the non-negative integer representing the number of undisclosed
     messages, i.e., U = L - R.
- prf_len = ceil(ceil(log2(r))/8), where r defined by the ciphersuite.

Outputs:

- proof, octet string; or INVALID.

Precomputations:

1. (i1, ..., iR) = disclosed_indexes
2. (j1, ..., jU) = range(1, L) \ disclosed_indexes
3. (msg_1, ..., msg_L) = messages
4. (msg_i1, ..., msg_iR) = (messages[i1], ..., messages[iR])
5. (msg_j1, ..., msg_jU) = (messages[j1], ..., messages[jU])
6. (Q_1, Q_2, MsgGenerators) = create_generators(L+2)
7. (H_1, ..., H_L) = MsgGenerators
8. (H_j1, ..., H_jU) = (MsgGenerators[j1], ..., MsgGenerators[jU])

Procedure:

1.  signature_result = octets_to_signature(signature)
2.  if signature_result is INVALID, return INVALID
3.  (A, e, s) = signature_result
4.  dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
5.  dom_for_hash = encode_for_hash(dom_array)
6.  if dom_for_hash is INVALID, return INVALID
7.  domain = hash_to_scalar(dom_for_hash, 1)
8.  (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(prf_len), 6)
9.  (m~_j1, ..., m~_jU) = hash_to_scalar(PRF(prf_len), U)
10. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
11. r3 = r1 ^ -1 mod r
12. A' = A * r1
13. Abar = A' * (-e) + B * r1
14. D = B * r1 + Q_1 * r2
15. s' = r2 * r3 + s mod r
16. C1 = A' * e~ + Q_1 * r2~
17. C2 = D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
18. c_array = (A', Abar, D, C1, C2, R, i1, ..., iR,
                       msg_i1, ..., msg_iR, domain, ph)
19. c_for_hash = encode_for_hash(c_array)
20. if c_for_hash is INVALID, return INVALID
21. c = hash_to_scalar(c_for_hash, 1)
22. e^ = c * e + e~ mod r
23. r2^ = c * r2 + r2~ mod r
24. r3^ = c * r3 + r3~ mod r
25. s^ = c * s' + s~ mod r
26. for j in (j1, ..., jU): m^_j = c * msg_j + m~_j mod r
27. proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
28. return proof_to_octets(proof)

*/


import * as bls from '@noble/bls12-381';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { i2osp, concat, os2ip, numberToBytesBE} from './myUtils.js';
import { encode_to_hash } from './BBSEncodeHash.js';
import { hash_to_scalar, messages_to_scalars, prepareGenerators, octets_to_sig } from './BBSGeneral.js';
import { randomBytes } from '@noble/hashes/utils';

import fs from 'fs';

const ciphersuite_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
// prf_len = ceil(ceil(log2(r))/8),
// let prf_len =  Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r)))) / 8); 
// console.log(`prf_len: ${prf_len}`);
const PRF_LEN = 32;

/*
    I'm starting from my signing code and creating the proof...
 */
async function proofGen(PK, signature, header, ph, messages, disclosed_indexes, generators) {
    // TODO: check indexes for correctness, i.e., bounds and such...
    let L = messages.length;
    let R = disclosed_indexes.length;
    let U = L - R;
    let allIndexes = [];
    for (let i = 0; i < L; i++) {
        allIndexes[i] = i; 
    }
    let tempSet = new Set(allIndexes);
    for (let dis of disclosed_indexes) {
        tempSet.delete(dis);
    }
    let undisclosed = Array.from(tempSet); // Contains all the undisclosed indexes
    // console.log(disclosed_indexes);
    // console.log(undisclosed);

    let {A, e, s} = octets_to_sig(signature); // Get curve point and scalars
    // check that we have enough generators for the messages
    if (messages.length > generators.H.length) {
        throw new TypeError('Sign: not enough generators! string');
    }
    // elemTypes:"PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"
    // dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    let dom_array = [
        {type: "PublicKey", value: PK}, {type: "NonNegInt", value: L},
        {type: "GPoint", value: generators.Q1},
        {type: "GPoint", value: generators.Q2},
    ];
    for (let i = 0; i < L; i++) {
        dom_array.push({type: "GPoint", value: generators.H[i]})
    }
    dom_array.push({type: "CipherID", value: ciphersuite_id});
    dom_array.push({type: "PlainOctets", value: header});
    // dom_for_hash = encode_for_hash(dom_array)
    let dom_for_hash = encode_to_hash(dom_array);
    let dst = new TextEncoder().encode(ciphersuite_id + "H2S_");
    let [domain] = await hash_to_scalar(dom_for_hash, 1, dst);
    // console.log(`domain: ${domain}`);
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1;
    B = B.add(generators.Q1.multiply(s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < messages.length; i++) {
        B = B.add(generators.H[i].multiply(messages[i]));
    }
    // 8.  (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(prf_len), 6)
    // 9.  (m~_j1, ..., m~_jU) = hash_to_scalar(PRF(prf_len), U)
    let [r1, r2, eTilde, r2Tilde, r3Tilde, sTilde] = await hash_to_scalar(randomBytes(PRF_LEN), 6, dst);
    let mTildeU = await hash_to_scalar(randomBytes(PRF_LEN), U, dst);
    // console.log(`r1: ${r1}`);
    // console.log(`B: ${B}`);
    // console.log(`m~U: ${mTildeU}`);
    // 11. r3 = r1 ^ -1 mod r
    let r3 = (new bls.Fr(r1)).invert();
    // 12. A' = A * r1
    let Aprime = A.multiply(r1);
    // 13. Abar = A' * (-e) + B * r1
    let negE = new bls.Fr(e).negate().value;
    let Abar = Aprime.multiply(negE).add(B.multiply(r1));
    // console.log(`e: ${e}, -e: ${negE}`);
    // console.log(`Aprime: ${Aprime}`);
    // console.log(`Abar: ${Abar}`);
    // 14. D = B * r1 + Q_1 * r2
    let D = B.multiply(r1).add(generators.Q1.multiply(r2));
    // console.log(`D: ${D}`);
    // 15. s' = r2 * r3 + s mod r
    let sPrime = new bls.Fr(r2).multiply(r3).add(new bls.Fr(s)).value;
    // console.log(`sPrime: ${sPrime}`);
    // 16. C1 = A' * e~ + Q_1 * r2~
    let C1 = Aprime.multiply(eTilde).add(generators.Q1.multiply(r2Tilde));
    // console.log(`C1: ${C1}`);
    // 17. C2 = D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let neg_r3Tilde = new bls.Fr(r3Tilde).negate().value;
    let C2 = D.multiply(neg_r3Tilde);
    // console.log(`C2 partial 1: ${C2}`);
    C2 = C2.add(generators.Q1.multiply(sTilde));
    // console.log(`C2 partial 2: ${C2}`);
    // console.log(`undisclosed: ${undisclosed}`);
    for (let j = 0; j < U; j++) {
        C2 = C2.add(generators.H[undisclosed[j]].multiply(mTildeU[j]));
        // console.log(`H[undisclosed[j]]: ${generators.H[undisclosed[j]]}, mTildeU[j]: ${mTildeU[j]}`);
        // console.log(`j = ${j}, C2 = ${C2}`);
    }
    // console.log(`C2: ${C2}`);
    // 18. c_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain, ph)
    // // elemTypes:"PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"
    let c_array = [{type: "GPoint", value: Aprime}, {type: "GPoint", value: Abar},
        {type: "GPoint", value: D}, {type: "GPoint", value: C1},
        {type: "GPoint", value: C2}, {type: "NonNegInt", value: R}
    ];
    for (let iR of disclosed_indexes) {
        c_array.push({type: "NonNegInt", value: iR});
    }
    for (let iR of disclosed_indexes) {
        c_array.push({type: "Scalar", value: messages[iR]});
    }
    c_array.push({type: "Scalar", value: domain});
    c_array.push({type: "PlainOctets", value: ph});
    // 19. c_for_hash = encode_for_hash(c_array)
    // 20. if c_for_hash is INVALID, return INVALID
    let c_for_hash = encode_to_hash(c_array);
    // 21. c = hash_to_scalar(c_for_hash, 1)
    let [c] = await hash_to_scalar(c_for_hash, 1, dst);
    // console.log(`c: ${c}`);
    // 22. e^ = c * e + e~ mod r
    // console.log(`type c: ${typeof(c)}, e: ${typeof(e)}, eTilde: ${typeof(eTilde)}`);
    let eHat = (new bls.Fr(c).multiply(e).add(new bls.Fr(eTilde))).value;
    // console.log(`eHat: ${eHat}`);
    // 23. r2^ = c * r2 + r2~ mod r
    let r2Hat = (new bls.Fr(c).multiply(r2).add(new bls.Fr(r2Tilde))).value;
    // console.log(`r2Hat: ${r2Hat}`);
    // 24. r3^ = c * r3 + r3~ mod r
    let r3Hat = (new bls.Fr(c).multiply(r3).add(new bls.Fr(r3Tilde))).value;
    // console.log(`r3Hat: ${r3Hat}`);
    // 25. s^ = c * s' + s~ mod r
    let sHat = (new bls.Fr(c).multiply(sPrime).add(new bls.Fr(sTilde))).value;
    // console.log(`sHat: ${sHat}`);
    // 26. for j in (j1, ..., jU): m^_j = c * msg_j + m~_j mod r
    let mHatU = [];
    for (let j = 0; j < U; j++) {
        let mHatj = new bls.Fr(c).multiply(messages[undisclosed[j]]).add(new bls.Fr(mTildeU[j])).value;
        mHatU.push(mHatj);
    }
    // console.log(`mHatU: ${mHatU}`);
    // 27. proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
    // 28. return proof_to_octets(proof)
    return proof_to_octets(Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU);
}

const OCTET_SCALAR_LENGTH = 32;

function proof_to_octets(Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU) {
    let octets = Aprime.toRawBytes(true);
    octets = concat(octets, Abar.toRawBytes(true));
    octets = concat(octets, D.toRawBytes(true));
    octets = concat(octets, numberToBytesBE(c, OCTET_SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(eHat, OCTET_SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(r2Hat, OCTET_SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(r3Hat, OCTET_SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(sHat, OCTET_SCALAR_LENGTH));
    for (let mHatj of mHatU) {
        octets = concat(octets, numberToBytesBE(mHatj, OCTET_SCALAR_LENGTH));
    }
    return octets;
}

// Some test messages in hex string format from draft
let hex_msgs = [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
    "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
    "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943",
    "d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151",
    "515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc",
    "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
]

let test_msgs = hex_msgs.map(hex => hexToBytes(hex)); // Convert to byte array
let msg_scalars = await messages_to_scalars(test_msgs); // hash to scalars
let gens = await prepareGenerators(test_msgs.length); // Generate enough for all msgs

let sk_bytes = hexToBytes("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56");
let pointPk = bls.PointG2.fromPrivateKey(sk_bytes);
let pk_bytes = pointPk.toRawBytes(true);
let header = hexToBytes("11223344556677889900aabbccddeeff");
// L = 10; // Try with all 10 messages
// // From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature004.json
let signature = hexToBytes("b9c68aa75ed3510d2c3dd06d962106b888073b9468db2bde45c42ed32d3a04ffc14e0854ce219b77ce845fe7b06e200f66f64cb709e83a367586a70dc080b0fe242444b7cfd08977d74d91be64b468485774792526992181bc8b2d40a913c9bf561b2eeb0e149bfb7dc05d3607903513");
let ph = new Uint8Array();
let disclosed_indexes = [0, 1, 2, 3, 6, 7, 8, 9];
let result = await proofGen(pk_bytes, signature, header, ph, msg_scalars, disclosed_indexes, gens);
// console.log(`result length: ${result.length}`);
// console.log(`expected length: ${3*48 + 5*32 + 32*(msg_scalars.length - disclosed_indexes.length)}`);
console.log("Proof");
console.log(bytesToHex(result));
// Create proof bundle: pk_bytes, header, ph, disclosed msgs, disclosed indexes, proof, total messages
let disclosedMsgs = hex_msgs.filter((msg, i) => disclosed_indexes.includes(i));
let proofBundle = {
    pk: bytesToHex(pk_bytes),
    header: bytesToHex(header),
    ph: bytesToHex(ph),
    disclosedIndexes: disclosed_indexes,
    disclosedMsgs: disclosedMsgs,
    totalMsgs: msg_scalars.length,
    proof: bytesToHex(result)
}

console.log(proofBundle);
fs.writeFileSync("proofSample.json", JSON.stringify(proofBundle, null, 2));
