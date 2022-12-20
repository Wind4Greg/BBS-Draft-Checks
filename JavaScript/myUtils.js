// Some necessary utilities some borrowed others hacked

// Integer to Octet Stream borrowed from inside bls12-381 modified to handle larger
// length values
function i2osp(value, length) {
    // This check fails if length is 4 or greater since the integer raps around in the browser
    // See https://www.w3schools.com/js/js_bitwise.asp caveat on 32 bit integers
    // if (value < 0 || value >= 1 << (8 * length)) {
    //     throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    // }
    // This works for larger length values
    if (value < 0 || value >= 2 ** (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8; // zero fill right shift. Doesn't work with BigInt
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

// from noble but not exported
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
      throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
      const j = i * 2;
      const hexByte = hex.slice(j, j + 2);
      if (hexByte.length !== 2) throw new Error('Invalid byte sequence');
      const byte = Number.parseInt(hexByte, 16);
      if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
      array[i] = byte;
    }
    return array;
  }
  
  function numberToHex(num, byteLength){
    if (!byteLength) throw new Error('byteLength target must be specified');
    const hex = num.toString(16);
    const p1 = hex.length & 1 ? `0${hex}` : hex;
    return p1.padStart(byteLength * 2, '0');
  }
  
  function numberToBytesBE(num, byteLength) {
    const res = hexToBytes(numberToHex(num, byteLength));
    if (res.length !== byteLength) throw new Error('numberToBytesBE: wrong byteLength');
    return res;
  }

export { i2osp, os2ip, concat, numberToBytesBE };