from processing import *


# need a key and bytes

def eko_hmac(key: bytes, input: bytes) -> bytes:
    BLOCK_SIZE = 64
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    key = key.ljust(BLOCK_SIZE , b'\x00')
    i_key_pad = bytes([b ^ 0x36 for b in key])
    o_key_pad = bytes([b ^ 0x5c for b in key])
    return sha256(o_key_pad + sha256(i_key_pad + input))


    