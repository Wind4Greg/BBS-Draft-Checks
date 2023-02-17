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

- P1, fixed point of G1, defined by the ciphersuite.

Definitions:

- L, is the non-negative integer representing the number of messages.
- R, is the non-negative integer representing the number of disclosed
     (revealed) messages.
- U, is the non-negative integer representing the number of undisclosed
     messages, i.e., U = L - R.
- expand_len = ceil((ceil(log2(r))+k)/8), where r and k are defined by
                                          the ciphersuite.

Outputs:

- proof, octet string; or INVALID.

Deserialization:

1.  signature_result = octets_to_signature(signature)
2.  if signature_result is INVALID, return INVALID
3.  (A, e, s) = signature_result
4.  L = length(messages)
5.  R = length(disclosed_indexes)
6.  U = L - R
7.  (i1, ..., iR) = disclosed_indexes
8.  (j1, ..., jU) = range(1, L) \ disclosed_indexes
9.  (msg_1, ..., msg_L) = messages
10. (msg_i1, ..., msg_iR) = (messages[i1], ..., messages[iR])
11. (msg_j1, ..., msg_jU) = (messages[j1], ..., messages[jU])

Procedure:

1.  (Q_1, Q_2, MsgGenerators) = create_generators(L+2)
2.  (H_1, ..., H_L) = MsgGenerators
3.  (H_j1, ..., H_jU) = (MsgGenerators[j1], ..., MsgGenerators[jU])

4.  domain = calculate_domain(PK, Q_1, Q_2, L, (H_1, ..., H_L), header)
5.  if domain is INVALID, return INVALID
6.  for i in (1, ..., U+6):
7.      ell_i = OS2IP(get_random(expand_len)) mod r
8.  (r1, r2, e~, r2~, r3~, s~, m~_j1, ..., m~_jU) =
                                     (ell_1, ell_2, ..., ell_(6+U))
9.  B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
10. r3 = r1 ^ -1 mod r
11. A' = A * r1
12. Abar = A' * (-e) + B * r1
13. D = B * r1 + Q_1 * r2
14. s' = r2 * r3 + s mod r
15. C1 = A' * e~ + Q_1 * r2~
16. C2 = D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
17. c = calculate_challenge(A', Abar, D, C1, C2, (i1, ..., iR),
                                      (msg_i1, ..., msg_iR), domain, ph)
18. if c is INVALID, return INVALID
19. e^ = c * e + e~ mod r
20. r2^ = c * r2 + r2~ mod r
21. r3^ = c * r3 + r3~ mod r
22. s^ = c * s' + s~ mod r
23. for j in (j1, ..., jU): m^_j = c * msg_j + m~_j mod r
24. proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
25. return proof_to_octets(proof)

*/


import {bls12_381 as bls} from '@noble/curves/bls12-381';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { i2osp, concat, os2ip, numberToBytesBE} from './myUtils.js';
import { encode_to_hash } from './BBSEncodeHash.js';
import { hash_to_scalar, messages_to_scalars, prepareGenerators, octets_to_sig, calculate_random_scalars, seeded_random_scalars} from './BBSGeneral.js';
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
async function proofGen(PK, signature, header, ph, messages, disclosed_indexes, generators, rand_scalars=calculate_random_scalars) {
    // TODO: check indexes for correctness, i.e., bounds and such...
    let proofTrace = {};
    let L = messages.length;
    let R = disclosed_indexes.length;
    let U = L - R;
    proofTrace.L = L;
    proofTrace.U = U;
    proofTrace.disclosed = disclosed_indexes;
    let allIndexes = [];
    for (let i = 0; i < L; i++) {
        allIndexes[i] = i; 
    }
    let tempSet = new Set(allIndexes);
    for (let dis of disclosed_indexes) {
        tempSet.delete(dis);
    }
    let undisclosed = Array.from(tempSet); // Contains all the undisclosed indexes
    proofTrace.undisclosed = undisclosed;

    let {A, e, s} = octets_to_sig(signature); // Get curve point and scalars
    // check that we have enough generators for the messages
    if (messages.length > generators.H.length) {
        throw new TypeError('Sign: not enough generators! string');
    }
    proofTrace.A = bytesToHex(A.toRawBytes(true));
    proofTrace.e = e.toString(16);
    proofTrace.s = s.toString(16);
    // !!!!Still using old domain calculation procedure!!! MUST BE SAME AS SIGNATURE
    // New procedure:
    // 4.  domain = calculate_domain(PK, Q_1, Q_2, L, (H_1, ..., H_L), header)
    // elemTypes:"PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"
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
    proofTrace.domain = domain.toString(16);
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1;
    B = B.add(generators.Q1.multiply(s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < messages.length; i++) {
        B = B.add(generators.H[i].multiply(messages[i]));
    }
    // 8.  (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(prf_len), 6)
    // 9.  (m~_j1, ..., m~_jU) = hash_to_scalar(PRF(prf_len), U)
    proofTrace.B = bytesToHex(B.toRawBytes(true));
    let randScalars = await rand_scalars(6+U);
    proofTrace.randScalars = randScalars.map(s => s.toString(16));
    let [r1, r2, eTilde, r2Tilde, r3Tilde, sTilde, ...mTildeU] = randScalars;
    proofTrace.r1 = r1.toString(16);
    proofTrace.r2 = r2.toString(16);
    proofTrace.eTilde = eTilde.toString(16);
    proofTrace.r2Tilde = r2Tilde.toString(16);
    proofTrace.r3Tilde = r3Tilde.toString(16);
    proofTrace.sTilde = sTilde.toString(16);
    proofTrace.mTildeU = mTildeU.map(s => s.toString(16));
    // r3 = r1 ^ -1 mod r
    let r3 = bls.Fr.inv(bls.Fr.create(r1));
    proofTrace.r3 = r3.toString(16);
    // A' = A * r1
    let Aprime = A.multiply(r1);
    proofTrace.Aprime = bytesToHex(Aprime.toRawBytes(true));
    // 13. Abar = A' * (-e) + B * r1
    let negE = bls.Fr.neg(e);
    let Abar = Aprime.multiply(negE).add(B.multiply(r1));
    proofTrace.Abar = bytesToHex(Abar.toRawBytes(true));
    // D = B * r1 + Q_1 * r2
    let D = B.multiply(r1).add(generators.Q1.multiply(r2));
    proofTrace.D = bytesToHex(D.toRawBytes(true));
    // s' = r2 * r3 + s mod r 
    let sPrime = bls.Fr.add(bls.Fr.mul(r2, r3), s);
    proofTrace.sPrime = sPrime.toString(16);
    // C1 = A' * e~ + Q_1 * r2~
    let C1 = Aprime.multiply(eTilde).add(generators.Q1.multiply(r2Tilde));
    proofTrace.C1 = bytesToHex(C1.toRawBytes(true));
    // C2 = D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let neg_r3Tilde = bls.Fr.neg(r3Tilde);
    let C2 = D.multiply(neg_r3Tilde);
    // console.log(`C2 partial 1: ${C2}`);
    C2 = C2.add(generators.Q1.multiply(sTilde));
    for (let j = 0; j < U; j++) {
        C2 = C2.add(generators.H[undisclosed[j]].multiply(mTildeU[j]));
    }
    proofTrace.C2 = bytesToHex(C2.toRawBytes(true));
    // Note that the **R** parameter, number of revealed is not in the latest draft
    // c = calculate_challenge(A', Abar, D, C1, C2, **R**, (i1, ..., iR), (msg_i1, ..., msg_iR), domain, ph)
    // elemTypes:"PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"
    let c_array = [{type: "GPoint", value: Aprime}, {type: "GPoint", value: Abar},
        {type: "GPoint", value: D}, {type: "GPoint", value: C1},
        {type: "GPoint", value: C2},
        {type: "NonNegInt", value: disclosed_indexes.length}
    ];
    for (let iR of disclosed_indexes) {
        c_array.push({type: "NonNegInt", value: iR});
    }
    for (let iR of disclosed_indexes) {
        c_array.push({type: "Scalar", value: messages[iR]});
    }
    c_array.push({type: "Scalar", value: domain});
    c_array.push({type: "PlainOctets", value: ph});
    let c_for_hash = encode_to_hash(c_array);
    let [c] = await hash_to_scalar(c_for_hash, 1, dst);
    proofTrace.c = c.toString(16);
    // e^ = c * e + e~ mod r
    let eHat = bls.Fr.add(bls.Fr.mul(c, e), eTilde);
    proofTrace.eHat = eHat.toString(16);
    // r2^ = c * r2 + r2~ mod r
    let r2Hat = bls.Fr.add(bls.Fr.mul(c, r2), r2Tilde);
    proofTrace.r2Hat = r2Hat.toString(16);
    // r3^ = c * r3 + r3~ mod r
    let r3Hat = bls.Fr.add(bls.Fr.mul(c, r3), r3Tilde);
    proofTrace.r3Hat = r3Hat.toString(16);
    // s^ = c * s' + s~ mod r
    let sHat = bls.Fr.add(bls.Fr.mul(c, sPrime), sTilde);
    proofTrace.sHat = sHat.toString(16);
    // for j in (j1, ..., jU): m^_j = c * msg_j + m~_j mod r
    let mHatU = [];
    for (let j = 0; j < U; j++) {
        let mHatj = bls.Fr.add(bls.Fr.mul(c, messages[undisclosed[j]]), mTildeU[j]);
        mHatU.push(mHatj);
    }
    proofTrace.mHatU = mHatU.map(s => s.toString(16));
    // proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
    // return proof_to_octets(proof)
    let proof = proof_to_octets(Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU);
    proofTrace.proof = bytesToHex(proof);
    // To see a trace of the proof uncomment the lines below as desired:
    // console.log("Proof Trace:");
    // console.log(proofTrace);
    fs.writeFileSync("proofTrace.json", JSON.stringify(proofTrace, null, 2));
    // End tracing code
    return proof;
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

let sk_bytes = hexToBytes("4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7");
let pointPk = bls.G2.ProjectivePoint.fromPrivateKey(sk_bytes);
let pk_bytes = pointPk.toRawBytes(true);
let header = hexToBytes("11223344556677889900aabbccddeeff");
// L = 10; // Try with all 10 messages
// // From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature004.json
let signature = hexToBytes("b13ae29b49e313b1c0983056e80cfb8d84a81985ca7488557aaf9b923f1e67994cab0e5ab05c75ffcf3fde1c23207ce5218dcfec42e9cc0063ff488100f89ba08296ced4923052e597279e1f775b157c55ed6b32ba777c3eec754bda4ab096e4147f2587248ba47b22226aee2aeafd85");
let ph = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
let disclosed_indexes = [0, 2, 4, 6];

// If you want to check calculated proofs use the seeded random scalars
let seed = hexToBytes("332e313431353932363533353839373933323338343632363433333833323739");
let rand_scalar_func = seeded_random_scalars.bind(null, seed);
let result = await proofGen(pk_bytes, signature, header, ph, msg_scalars,
     disclosed_indexes, gens, rand_scalar_func);
// console.log(`result length: ${result.length}`);
// console.log(`expected length: ${3*48 + 5*32 + 32*(msg_scalars.length - disclosed_indexes.length)}`);
// console.log("Proof");
// console.log(bytesToHex(result));
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
