/* 
    Implementation of encode_for_hash from draft section 4.4.6

They say:

* Points in G1 or G2 will be encoded using the point_to_octets_g* 
implementation for a particular ciphersuite.
* Non-negative integers will be encoded using I2OSP with an output length of 
8 bytes.
* Scalars will be zero-extended to a fixed length, defined by a particular 
ciphersuite.
* Octet strings will be zero-extended to a length that is a multiple of 8 bits. 
Then, the extended value is encoded directly.ASCII strings will be transformed 
into octet strings using UTF-8 encoding.

```
result = encode_for_hash(input_array)

Inputs:

- input_array, an array of elements to be hashed. All elements of this
               array that are octet strings MUST be multiples of 8 bits.

Parameters:

- octet_scalar_length, non-negative integer. The length of a scalar
    octet representation, defined by the ciphersuite.

Outputs:

- result, an octet string or INVALID.

Procedure:

1.  let octets_to_hash be an empty octet string.
2.  for el in input_array:
3.      if el is an ASCII string: el = utf8(el)
4.      if el is an octet string representing a public key:
5.          el_octs = el
6.      else if el is representing a utf8 encoded Ciphersuite ID:
7.          el_octs = el
8.      else if el is an octet string:
9.          if length(el) > 2^64 - 1, return INVALID
10.         el_octs = I2OSP(length(el), 8) || el
11.     else if el is a Point in G1: el_octs = point_to_octets_g1(el)
12.     else if el is a Point in G2: el_octs = point_to_octets_g2(el)
10.     else if el is a Scalar: el_octs = I2OSP(el, octet_scalar_length)
11.     else if el is a non-negative integer: el_octs = I2OSP(el, 8)
12.     else: return INVALID
13.     octets_to_hash = octets_to_hash || el_octs
14. return octets_to_hash
```

*/

import { i2osp, concat, numberToBytesBE } from './myUtils.js';

const SCALAR_LENGTH = 32;

const elemTypes = ["PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"];
/* 
    For my implementation the input element array will contain elements of the form
    {type: "an elemType", value: thingy}
*/
function encode_to_hash(elem_array) {
    let octets = new Uint8Array();
    for (let element of elem_array) {
        switch (element.type) {
            case "PublicKey":
                octets = concat(octets, element.value);
                break;
            case "NonNegInt":
                octets = concat(octets, i2osp(element.value, 8));
                break;
            case "GPoint":
                octets = concat(octets, element.value.toRawBytes(true));
                break;
            case "Scalar":
                octets = concat(octets, numberToBytesBE(element.value, SCALAR_LENGTH));
                break;
            case "PlainOctets":
                // TODO: check length
                octets = concat(octets, concat(i2osp(element.value.length, 8), element.value));
                break;
            case "CipherID":
                let te = new TextEncoder();
                octets = concat(octets, te.encode(element.value));
                break;
            case "ASCII":
                let temp = new TextEncoder().encode(element.value);
                temp = concat(i2osp(temp.length, 8), temp);
                octets = concat(octets, temp);
                break;
            default:
                throw new Error(`bad type to encode for hash: type=${element.type}`);
        }
    }
    return octets;
}

export {encode_to_hash};
