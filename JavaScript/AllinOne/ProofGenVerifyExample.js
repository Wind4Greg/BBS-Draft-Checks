
import { proofGen, proofVerify, messages_to_scalars, prepareGenerators, hexToBytes, bytesToHex } from './BBSAllinOne.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';

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
let pointPk = bls.G2.ProjectivePoint.fromPrivateKey(sk_bytes);
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

// Verify proof
let pk = hexToBytes(proofBundle.pk);
let proof = hexToBytes(proofBundle.proof);
let L = proofBundle.totalMsgs;
let headerV = hexToBytes(proofBundle.header);
let phV = hexToBytes(proofBundle.ph);

// In the proof bundle messages are hex strings, need scalars
let dis_msg_octets = proofBundle.disclosedMsgs.map(hex => hexToBytes(hex));
let disclosed_msgs = await messages_to_scalars(dis_msg_octets);
let disclosed_indexesV = proofBundle.disclosedIndexes;
result = await proofVerify(pk, proof, L, headerV, phV, disclosed_msgs, disclosed_indexesV, gens);
console.log(`Proof verified: ${result}`);
