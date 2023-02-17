/* BBS Proof Verification, from the draft:

result = ProofVerify(PK, proof, header, ph,
                     disclosed_messages,
                     disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), octet string containing the presentation header. If not
                 supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of scalars. If not supplied,
                                 it defaults to the empty array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.

Definitions:

- R, is the non-negative integer representing the number of disclosed
     (revealed) messages.
- U, is the non-negative integer representing the number of undisclosed
     messages.
- L, is the non-negative integer representing the number of total,
     messages i.e., L = U + R.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1.  proof_result = octets_to_proof(proof)
2.  if proof_result is INVALID, return INVALID
3.  (A', Abar, D, c, e^, r2^, r3^, s^, commitments) = proof_result
4.  W = octets_to_pubkey(PK)
5.  if W is INVALID, return INVALID
6.  U  = length(commitments)
7.  R = length(disclosed_indexes)
8.  L = R + U
9.  (i1, ..., iR) = disclosed_indexes
10. (j1, ..., jU) = range(1, L) \ disclosed_indexes
11. (msg_i1, ..., msg_iR) = disclosed_messages
12. (m^_j1, ...., m^_jU) = commitments

Preconditions:

1. for i in (i1, ..., iR), if i < 1 or i > L, return INVALID
2. if length(disclosed_messages) != R, return INVALID

Procedure:

1.  (Q_1, Q_2, MsgGenerators) = create_generators(L+2)
2.  (H_1, ..., H_L) = MsgGenerators
3.  (H_i1, ..., H_iR) = (MsgGenerators[i1], ..., MsgGenerators[iR])
4.  (H_j1, ..., H_jU) = (MsgGenerators[j1], ..., MsgGenerators[jU])

5.  domain = calculate_domain(PK, Q_1, Q_2, L, (H_1, ..., H_L), header)
6.  if domain is INVALID, return INVALID
7.  C1 = (Abar - D) * c + A' * e^ + Q_1 * r2^
8.  T = P1 + Q_2 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
9.  C2 = T * c - D * r3^ + Q_1 * s^ + H_j1 * m^_j1 + ... + H_jU * m^_jU
10. cv = calculate_challenge(A', Abar, D, C1, C2, (i1, ..., iR),
                                      (msg_i1, ..., msg_iR), domain, ph)
11. if cv is INVALID, return INVALID
12. if c != cv, return INVALID
13. if A' == Identity_G1, return INVALID
14. if e(A', W) * e(Abar, -P2) != Identity_GT, return INVALID
15. return VALID

*/

import fs from 'fs';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { i2osp, concat, os2ip, numberToBytesBE } from './myUtils.js';
import { encode_to_hash } from './BBSEncodeHash.js';
import { hash_to_scalar, messages_to_scalars, prepareGenerators } from './BBSGeneral.js';

const ciphersuite_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
// prf_len = ceil(ceil(log2(r))/8),
// let prf_len =  Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r)))) / 8); 
// console.log(`prf_len: ${prf_len}`);
const PRF_LEN = 32;

/*
    
 */
async function proofVerify(PK, proof, L, header, ph, disclosed_messages, disclosed_indexes, generators) {
    let verifyTrace = {};
    let R = disclosed_indexes.length;
    let U = L - R;
    let allIndexes = [];
    for (let i = 0; i < L; i++) {
        allIndexes[i] = i;
    }
    verifyTrace.U = U;
    verifyTrace.L = L;
    verifyTrace.disclosed = disclosed_indexes;
    let tempSet = new Set(allIndexes);
    for (let dis of disclosed_indexes) {
        tempSet.delete(dis);
    }
    let undisclosed = Array.from(tempSet); // Contains all the undisclosed indexes
    verifyTrace.undisclosed = undisclosed;
    // (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1,...,m^_jU)) = proof_result
    let proof_result = octets_to_proof(proof, U);
    let { Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU } = proof_result;
    verifyTrace.proof = {};
    verifyTrace.proof.Aprime = bytesToHex(Aprime.toRawBytes(true));
    verifyTrace.proof.Abar = bytesToHex(Abar.toRawBytes(true));
    verifyTrace.proof.c = c.toString(16);
    verifyTrace.proof.eHat = eHat.toString(16);
    verifyTrace.proof.r2Hat = r2Hat.toString(16);
    verifyTrace.proof.r3Hat = r3Hat.toString(16);
    verifyTrace.proof.sHat = sHat.toString(16);
    verifyTrace.proof.mHatU =  mHatU.map(s => s.toString(16));
    // W = octets_to_pubkey(PK)
    let W = bls.G2.ProjectivePoint.fromHex(PK);
    verifyTrace.W = bytesToHex(W.toRawBytes(true));
    // !!!!Still using old domain calculation procedure!!! MUST BE SAME AS SIGNATURE
    // New procedure:
    // domain = calculate_domain(PK, Q_1, Q_2, L, (H_1, ..., H_L), header)
    let dom_array = [
        { type: "PublicKey", value: PK },{ type: "NonNegInt", value: L },
        { type: "GPoint", value: generators.Q1 },
        { type: "GPoint", value: generators.Q2 },
        
    ];
    for (let i = 0; i < L; i++) {
        dom_array.push({ type: "GPoint", value: generators.H[i] })
    }
    dom_array.push({type: "CipherID", value: ciphersuite_id});
    dom_array.push({ type: "PlainOctets", value: header });
    let dom_for_hash = encode_to_hash(dom_array);
    let dst = new TextEncoder().encode(ciphersuite_id + "H2S_");
    let [domain] = await hash_to_scalar(dom_for_hash, 1, dst);
    verifyTrace.domain = domain.toString(16);
    // C1 = (Abar - D) * c + A' * e^ + Q_1 * r2^
    let C1 = Abar.subtract(D).multiply(c).add(Aprime.multiply(eHat)).add(generators.Q1.multiply(r2Hat));
    verifyTrace.C1 = bytesToHex(C1.toRawBytes(true));
    // T = P1 + Q_2 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
    let T = generators.P1.add(generators.Q2.multiply(domain));
    for (let i = 0; i < R; i++) {
        T = T.add(generators.H[disclosed_indexes[i]].multiply(disclosed_messages[i]));
    }
    verifyTrace.T = bytesToHex(T.toRawBytes(true));
    // C2 = T * c - D * r3^ + Q_1 * s^ + H_j1 * m^_j1 + ... + H_jU * m^_jU
    let C2 = T.multiply(c).subtract(D.multiply(r3Hat)).add(generators.Q1.multiply(sHat));
    for (let j = 0; j < U; j++) {
        C2 = C2.add(generators.H[undisclosed[j]].multiply(mHatU[j]));
    }
    verifyTrace.C2 = bytesToHex(C2.toRawBytes(true));
    // Note that the **R** parameter, number of revealed is not in the latest draft
    // cv = calculate_challenge(A', Abar, D, C1, C2, **R**, (i1, ..., iR), (msg_i1, ..., msg_iR), domain, ph)
    let cv_array = [{ type: "GPoint", value: Aprime }, { type: "GPoint", value: Abar },
    { type: "GPoint", value: D }, { type: "GPoint", value: C1 }, { type: "GPoint", value: C2 },
    {type: "NonNegInt", value: disclosed_indexes.length}
    ];
    for (let index of disclosed_indexes) {
        cv_array.push({ type: "NonNegInt", value: index });
    }
    for (let msg of disclosed_messages) {
        cv_array.push({ type: "Scalar", value: msg });
    }
    cv_array.push({ type: "Scalar", value: domain });
    cv_array.push({ type: "PlainOctets", value: ph });
    let cv_for_hash = encode_to_hash(cv_array);
    let [cv] = await hash_to_scalar(cv_for_hash, 1, dst);
    verifyTrace.cv = cv.toString(16);
    let verify = true;
    if (c !== cv) {
        verifyTrace.message = "c is not equal to cv";
        verify = false;
    } else {
        // 18. if A' == Identity_G1, return INVALID
        if (Aprime.equals(bls.G1.ProjectivePoint.ZERO)) {
            verifyTrace.message = "Aprime is the identity in G1";
            verify = false;
        } else {
            // if e(A', W) * e(Abar, -P2) != Identity_GT, return INVALID else return VALID
            // Compute item in G2
            let negP2 = bls.G2.ProjectivePoint.BASE.negate();
            // Compute items in GT, i.e., Fp12
            let ptGT1 = bls.pairing(Aprime, W);
            let ptGT2 = bls.pairing(Abar, negP2);
            let result = bls.Fp12.mul(ptGT1, ptGT2)
            result = bls.Fp12.finalExponentiate(result); // See noble BLS12-381
            console.log(result);
            verify = bls.Fp12.eql(result, bls.Fp12.ONE);
            if (!verify) {
                verifyTrace.message = "Pairing check failed";
            }
        }
        verifyTrace.verify = verify;
        // To see a trace of the proof verification uncomment the lines below as desired:
        console.log("Proof Verification Trace:");
        console.log(verifyTrace);
        fs.writeFileSync("proofVerifyTrace.json", JSON.stringify(verifyTrace, null, 2));
        // End tracing code
        return verify;
    }
}


    const SCALAR_LENGTH = 32;
    const POINT_LENGTH = 48;

    function octets_to_proof(octets, U) {
        // recover (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1,...,m^_jU)) from octets
        let expected_length = 3 * POINT_LENGTH + 5 * SCALAR_LENGTH + U * SCALAR_LENGTH;
        if (octets.length !== expected_length) {
            throw new TypeError('octets_to_proof: bad proof length');
        }
        let index = 0;
        let Aprime_oct = octets.slice(0, POINT_LENGTH);
        let Aprime = bls.G1.ProjectivePoint.fromHex(Aprime_oct);
        index += POINT_LENGTH;
        let Abar_oct = octets.slice(index, index + POINT_LENGTH);
        let Abar = bls.G1.ProjectivePoint.fromHex(Abar_oct);
        index += POINT_LENGTH;
        let D_oct = octets.slice(index, index + POINT_LENGTH);
        let D = bls.G1.ProjectivePoint.fromHex(D_oct);
        index += POINT_LENGTH;
        let c = os2ip(octets.slice(index, index + SCALAR_LENGTH));
        if (c < 0n || c >= bls.CURVE.r) {
            throw new TypeError('octets_to_sig: bad c value');
        }
        index += SCALAR_LENGTH;
        let eHat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
        if (eHat < 0n || eHat >= bls.CURVE.r) {
            throw new TypeError('octets_to_sig: bad eHat value');
        }
        index += SCALAR_LENGTH;
        let r2Hat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
        if (r2Hat < 0n || r2Hat >= bls.CURVE.r) {
            throw new TypeError('octets_to_sig: bad r2Hat value');
        }
        index += SCALAR_LENGTH;
        let r3Hat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
        if (r3Hat < 0n || r3Hat >= bls.CURVE.r) {
            throw new TypeError('octets_to_sig: bad r3Hat value');
        }
        index += SCALAR_LENGTH;
        let sHat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
        if (sHat < 0n || sHat >= bls.CURVE.r) {
            throw new TypeError('octets_to_sig: bad sHat value');
        }
        index += SCALAR_LENGTH;
        let mHatU = [];
        for (let j = 0; j < U; j++) {
            let mHatj = os2ip(octets.slice(index, index + SCALAR_LENGTH));
            if (mHatj < 0n || mHatj >= bls.CURVE.r) {
                throw new TypeError('octets_to_sig: bad mHatj value');
            }
            mHatU.push(mHatj);
            index += SCALAR_LENGTH;
        }
        return { Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU };
    }

    // From draft
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
    let msg_scalars = await messages_to_scalars(test_msgs);
    let gens = await prepareGenerators(test_msgs.length); // Generate enough for alls

    // For testing proof generation I'm putting the results in a JSON file with the format:
    // {"pk": "",  "header": "", "ph": "", "disclosedIndexes": [], "disclosedMsgs": [],"totalMsgs": 10, "proof": ""}
    // All binary data is represented as hex strings
    

    let proofBundle = JSON.parse(fs.readFileSync("proofSample.json", { encoding: "utf8" }));
    let pk = hexToBytes(proofBundle.pk);
    let proof = hexToBytes(proofBundle.proof);
    let L = proofBundle.totalMsgs;
    let header = hexToBytes(proofBundle.header);
    let ph = hexToBytes(proofBundle.ph);

    // In the proof bundle messages are hex strings, need scalars
    let dis_msg_octets = proofBundle.disclosedMsgs.map(hex => hexToBytes(hex));
    let disclosed_msgs = await messages_to_scalars(dis_msg_octets);
    let disclosed_indexes = proofBundle.disclosedIndexes;
    console.log(proofBundle);
    let result = await proofVerify(pk, proof, L, header, ph, disclosed_msgs, disclosed_indexes, gens);
    console.log(`Proof verified: ${result}`);
