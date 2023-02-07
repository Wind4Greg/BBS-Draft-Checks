/* Functions used in multiple BBS signature operations */
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import { i2osp, concat, os2ip, numberToBytesBE} from './myUtils.js';
// These are really fixed for the ciphersuite
// const k = 128;
// const expand_len = Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r))) + k) / 8); // 48
// const seed_len = Math.ceil((Math.ceil(Math.log2(Number(bls.CURVE.r)) + k)) / 8); //48
const EXPAND_LEN = 48;
const SEED_LEN = 48;
const CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

async function hash_to_scalar(msg_octets, count, dst) {
    const len_in_bytes = count * EXPAND_LEN;
    let t = 0;
    let have_scalars = false;
    let scalars = [];
    while (!have_scalars) {
        let msg_prime = concat(msg_octets, concat(i2osp(t, 1), i2osp(count, 4)));
        let uniform_bytes = await bls.utils.expandMessageXMD(msg_prime, dst, len_in_bytes);
        have_scalars = true;
        for (let i = 0; i < count; i++) {
            let tv = uniform_bytes.slice(i * EXPAND_LEN, (i + 1) * EXPAND_LEN);
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
    const dst = new TextEncoder().encode(CIPHERSUITE_ID + "MAP_MSG_TO_SCALAR_AS_HASH_");
    let scalars = [];
    for (let i = 0; i < messages.length; i++) {
        let msg = messages[i];
        let stuff = await hash_to_scalar(msg, 1, dst);
        scalars.push(stuff[0]);
    }
    return scalars;
}

async function prepareGenerators(L) {
    // Compute P1, Q1, Q2, H1, ..., HL
    let generators = {H: []};
    let te = new TextEncoder(); // Used to convert string to uint8Array, utf8 encoding
    const seed_dst = te.encode(CIPHERSUITE_ID + "SIG_GENERATOR_SEED_");
    const gen_dst_string = CIPHERSUITE_ID + "SIG_GENERATOR_DST_";
    const gen_seed = te.encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MESSAGE_GENERATOR_SEED");
    let v = await bls.utils.expandMessageXMD(gen_seed, seed_dst, SEED_LEN);
    let count = L + 2;
    let n = 1;
    for (let i = 0; i < count; i++) {
        v = await bls.utils.expandMessageXMD(concat(v, i2osp(n, 4)), seed_dst, SEED_LEN);
        n = n + 1;
        let candidate = await bls.hashToCurve.G1.hashToCurve(v, { DST: gen_dst_string });
        if (i === 0) {
            generators.Q1 = candidate;
        } else if (i === 1) {
            generators.Q2 = candidate;
        } else {
            generators.H.push(candidate);
        }
    }
    // Generate P1
    const gen_seed_P1 = te.encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED");
    v = await bls.utils.expandMessageXMD(gen_seed_P1, seed_dst, SEED_LEN);
    v = await bls.utils.expandMessageXMD(concat(v, i2osp(1, 4)), seed_dst, SEED_LEN);
    let candidate = await bls.hashToCurve.G1.hashToCurve(v, { DST: gen_dst_string });
    generators.P1 = candidate;
    return generators;
}

function octets_to_sig(sig_octets) {
    if (sig_octets.length !== 112) {
        throw new TypeError('octets_to_sig: bad signature length');
    }
    let A_oct = sig_octets.slice(0, 48);
    let A = bls.G1.ProjectivePoint.fromHex(A_oct);
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

export {hash_to_scalar, messages_to_scalars, prepareGenerators, octets_to_sig};