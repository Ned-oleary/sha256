
# constants defined as part of SHA256
# these are just 'nothing up my sleeve constants' 
# they make clear that there's no backdoor
H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# constants defined as part of SHA256
# these are just 'nothing up my sleeve' constants
# they make clear that there's no backdoor
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def length_in_bits(input: bytes) -> int:
    return len(input) * 8


def is_64_bits_away_from_multiple_of_512(length: int) -> bool:
    return length % 512 == 448

def append_1_bit(input: bytes) -> bytes:
    return input + b'\x80'

def append_0_bit(input: bytes) -> bytes:
    return input + b'\x00'

def append_64_bit_integer(input: bytes, integer: int) -> bytes:
    return input + integer.to_bytes(8, 'big')


def pad_input(input: bytes) -> bytes:
    input_bit_length = length_in_bits(input)
    padded_input = append_1_bit(input) 
    while not is_64_bits_away_from_multiple_of_512(length_in_bits(padded_input)):
        padded_input = append_0_bit(padded_input)
    padded_input = append_64_bit_integer(padded_input, input_bit_length)
    return padded_input


def input_partition(input: bytes) -> list[bytes]:
    chunk_array = []
    for i in range(0, len(input), 64):
        chunk = input[i:i+64]
        chunk_array.append(chunk)
    return chunk_array


def right_shift(value: bytes, shifts: int) -> bytes:
    return value >> shifts


def left_shift(value: bytes, shifts: int) -> bytes:
        return value << shifts


def rotr(value: bytes, shifts: int) -> bytes:
     return right_shift(value, shifts) | left_shift(value, 32 - shifts) & 0xFFFFFFFF


def sha256_compress(chunk: bytes, H: list[bytes]) -> bytes:
    word_array = []
    for i in range(0, 64, 4): # every 32 bits
        four_bytes = chunk[i:i+4]
        word = int.from_bytes(four_bytes, 'big')
        word_array.append(word)

    for i in range(16, 64):
        s0 = rotr(word_array[i-15], 7) ^ rotr(word_array[i-15], 18) ^ right_shift(word_array[i-15], 3)
        s1 = rotr(word_array[i-2], 17) ^ rotr(word_array[i-2], 19) ^ right_shift(word_array[i-2], 10)
        new_word = (word_array[i-16] + s0 + word_array[i-7] + s1) & 0xFFFFFFFF
        word_array.append(new_word)

    a,b,c,d,e,f,g,h = H

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~ e) & g)
        temp1 = h + S1 + ch + K[i] + word_array[i]
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    return [
        (H[0] + a) & 0xFFFFFFFF,
        (H[1] + b) & 0xFFFFFFFF,
        (H[2] + c) & 0xFFFFFFFF,
        (H[3] + d) & 0xFFFFFFFF,
        (H[4] + e) & 0xFFFFFFFF,
        (H[5] + f) & 0xFFFFFFFF,
        (H[6] + g) & 0xFFFFFFFF,
        (H[7] + h) & 0xFFFFFFFF,
    ]
    

def sha256(input: bytes, H: list[bytes] = H) -> bytes:
    assert isinstance(input, bytes)
    padded_input = pad_input(input)
    for chunks in input_partition(padded_input):
          H = sha256_compress(chunks, H)
    return ''.join(f'{x:08x}' for x in H)
