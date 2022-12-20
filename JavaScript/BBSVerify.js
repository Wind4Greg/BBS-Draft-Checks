/* BBS verify and related functions per the draft 

From the draft: 

result = Verify(PK, signature, header, messages)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of scalars. If not supplied, it defaults
                       to the empty array "()".

Parameters:

- ciphersuite_id, ASCII string. The unique ID of the ciphersuite.
- P1, fixed point of G1, defined by the ciphersuite.

Definitions:

- L, is the non-negative integer representing the number of messages to
     be signed e.g length(messages). If no messages are supplied as an
     input, the value of L MUST evaluate to zero (0).

Outputs:

- result, either VALID or INVALID.

Precomputations:

1. (msg_1, ..., msg_L) = messages
2. (Q_1, Q_2, H_1, ..., H_L) = create_generators(L+2)

Procedure:

1.  signature_result = octets_to_signature(signature)
2.  if signature_result is INVALID, return INVALID
3.  (A, e, s) = signature_result
4.  W = octets_to_pubkey(PK)
5.  if W is INVALID, return INVALID
6.  dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
7.  dom_for_hash = encode_for_hash(dom_array)
8.  if dom_for_hash is INVALID, return INVALID
9.  domain = hash_to_scalar(dom_for_hash, 1)
10. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
11. if e(A, W + P2 * e) * e(B, -P2) != Identity_GT, return INVALID
12. return VALID

*/


import * as bls from '@noble/bls12-381';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { i2osp, concat, os2ip, numberToBytesBE} from './myUtils.js';
import { encode_to_hash } from './BBSEncodeHash.js';

const ciphersuite_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
const k = 128;
const expand_len = Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r))) + k) / 8);

async function verify(PK, signature, header, messages, generators) {
    let {A, e, s} = octets_to_sig(signature); // Get curve point and scalars
    // W = octets_to_pubkey(PK)
    let W = bls.PointG2.fromHex(PK);
    // dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    let L = messages.length;
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
    let dom_for_hash = encode_to_hash(dom_array);
    let dst = new TextEncoder().encode(ciphersuite_id + "H2S_");
    let [domain] = await hash_to_scalar(dom_for_hash, 1, dst);
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1;
    B = B.add(generators.Q1.multiply(s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < messages.length; i++) {
        B = B.add(generators.H[i].multiply(messages[i]));
    }
    //  if e(A, W + P2 * e) * e(B, -P2) != Identity_GT, return INVALID otherwise return VALID
    // Compute items in G2
    let temp1G2 = W.add(bls.PointG2.BASE.multiply(e));
    let temp2G2 = bls.PointG2.BASE.negate();
    // Compute items in GT, i.e., Fp12
    let ptGT1 = bls.pairing(A, temp1G2);
    let ptGT2 = bls.pairing(B, temp2G2);
    let result = ptGT1.multiply(ptGT2).finalExponentiate(); // See noble BLS12-381
    return result.equals(bls.Fp12.ONE);
}

function octets_to_sig(sig_octets) {
    if (sig_octets.length !== 112) {
        throw new TypeError('octets_to_sig: bad signature length');
    }
    let A_oct = sig_octets.slice(0, 48);
    let A = bls.PointG1.fromHex(A_oct);
    let e = os2ip(sig_octets.slice(48, 80));
    if (e < 0n || e >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad e value');
    }
    let s = os2ip(sig_octets.slice(80, 112));
    if (s < 0n || s >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad s value');
    }
    return {A, e, s};
}

const OCTET_SCALAR_LENGTH = 32;

function signature_to_octets(A, e, s) {
    let octets = A.toRawBytes(true);
    octets = concat(octets, numberToBytesBE(e, OCTET_SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(s, OCTET_SCALAR_LENGTH));
    return octets;
}

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

async function messages_to_scalars(messages) {
    const dst = new TextEncoder().encode(ciphersuite_id + "MAP_MSG_TO_SCALAR_AS_HASH_");
    let scalars = [];
    for (let i = 0; i < messages.length; i++) {
        let msg = messages[i];
        // Need to "encode to hash" before feeding the message to hash to scalar
        // For a message in octets they use: el_octs = I2OSP(length(el), 8) || el
        let encode_for_hash = concat(i2osp(msg.length, 8), msg)
        let stuff = await hash_to_scalar(encode_for_hash, 1, dst);
        scalars.push(stuff[0]);
        // console.log(`Message: ${bytesToHex(msg)}`);
        // console.log("Computed scalar in hex:");
        // console.log(stuff[0].toString(16));
    }
    return scalars;
}

async function prepareGenerators(L) {
    // Compute P1, Q1, Q2, H1, ..., HL
    let generators = {H: []};
    let te = new TextEncoder(); // Used to convert string to uint8Array, utf8 encoding
    
    const seed_dst = te.encode(ciphersuite_id + "SIG_GENERATOR_SEED_");
    const gen_dst_string = ciphersuite_id + "SIG_GENERATOR_DST_";
    const k = 128
    const seed_len = Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r)) + k)) / 8);
    const gen_seed = te.encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MESSAGE_GENERATOR_SEED");
    let v = await bls.utils.expandMessageXMD(gen_seed, seed_dst, seed_len);
    let count = L + 2;
    let n = 1;
    for (let i = 0; i < count; i++) {
        v = await bls.utils.expandMessageXMD(concat(v, i2osp(n, 4)), seed_dst, seed_len);
        n = n + 1;
        let candidate = await bls.PointG1.hashToCurve(v, { DST: gen_dst_string });
        if (i === 0) {
            generators.Q1 = candidate;
        } else if (i === 1) {
            generators.Q2 = candidate;
        } else {
            generators.H.push(candidate);
        }
        // console.log("Candidate compressed generator point:");
        // console.log(bytesToHex(candidate.toRawBytes(true))); // true for compressed point
    }
    // Generate P1
    const gen_seed_P1 = te.encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED");
    v = await bls.utils.expandMessageXMD(gen_seed_P1, seed_dst, seed_len);
    v = await bls.utils.expandMessageXMD(concat(v, i2osp(1, 4)), seed_dst, seed_len);
    let candidate = await bls.PointG1.hashToCurve(v, { DST: gen_dst_string });
    generators.P1 = candidate;
    // console.log("P1 generator point:");
    // console.log(bytesToHex(candidate.toRawBytes(true))); // true for compressed point
    return generators;
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
let L = 1;
let gens = await prepareGenerators(test_msgs.length); // Generate enough for alls
// // console.log(gens);
let sk_bytes = hexToBytes("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56");
let pointPk = bls.PointG2.fromPrivateKey(sk_bytes);
let pk_bytes = pointPk.toRawBytes(true);
let header = hexToBytes("11223344556677889900aabbccddeeff");
// // From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature001.json
let expected = hexToBytes("acb90d6e4db7b6eb260f1ece4fd2c1b9b92f190c9bd2be900ad5a92b80cc23db9b6d3144447cbb5f7af7c615d9a6b9ee0ba0e713ad2b77feba7c40a18b02e50ffbe0ecb13849c1c6ed496f6a21300c145a1e7e0d4cb283607f6300e40ea411b6d6255967b3298765b22c6f1dc91fa5ab");
let verified = await verify(pk_bytes, expected, header, msg_scalars.slice(0,L), gens);
console.log(`Correct signature test one message, sig verified: ${verified}`);

verified = await verify(pk_bytes, expected, header, [msg_scalars[0]-1n], gens);
console.log(`Modified message signature test, sig verified: ${verified}`);

L = 10; // Try with all 10 messages
expected = hexToBytes("b9c68aa75ed3510d2c3dd06d962106b888073b9468db2bde45c42ed32d3a04ffc14e0854ce219b77ce845fe7b06e200f66f64cb709e83a367586a70dc080b0fe242444b7cfd08977d74d91be64b468485774792526992181bc8b2d40a913c9bf561b2eeb0e149bfb7dc05d3607903513");
verified = await verify(pk_bytes, expected, header, msg_scalars.slice(0,L), gens);
console.log(`Correct signature test 10 messages,  sig verified: ${verified}`);

verified = await verify(pk_bytes, expected, header, msg_scalars.slice(0,L-1), gens);
console.log(`Missing message signature test,  sig verified: ${verified}`);

