import sys
from hashlib import sha256

def xor(a,b):
    return bin(int(a,2) ^ int(b,2))

# preimage = '0b' + '1'*512
preimage = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
# print(preimage.hex())
digest_bytes = sha256(preimage).digest()
# digest_py = bin(int.from_bytes(digest_bytes, byteorder=sys.byteorder))
digest_py = int.from_bytes(digest_bytes, byteorder='big')
print("digest: {:0256b}".format(digest_py))

digest_h = int('0b1000011001100111111001110001100000101001010011101001111000001101111100011101001100000110000000001011101000111110111010110010000000011111011101100100101010101101001011011010110101110010011101001000011001000011111001001010001010000101111000011101000111110111', 2) #.to_bytes(256, byteorder=sys.byteorder)
print("digest_h: {:0256b}".format(digest_h))
digest_h_prime = int('0b1110111100001100011101001000110111110100110110100101000010101000110101101100010000111100000000010011111011011100001111001110011101101100100111011001111110101001101000010100010110001010110111100101011011101011100001101100000010100110010001001001001011010010', 2)

# print(xor(digest_py, digest_h))
# print(xor(digest_py, digest_h_prime))
print("XOR: {}".format(bin(digest_py ^ digest_h)))