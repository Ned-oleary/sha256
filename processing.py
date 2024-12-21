from constants import H, K

def length_in_bits(input: bytes) -> int:
    return len(input) * 8


def is_448_mod_512(length: int) -> bool:
    return length % 512 == 448


def pad_input(input: bytes) -> bytes:

    input_bit_length = length_in_bits(input)
    padded_input = input + b'\x80' # append 1 bit

    # append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512"
    while not is_448_mod_512(length_in_bits(padded_input)):
        padded_input += b'\x00'

    # append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    padded_input += input_bit_length.to_bytes(8, 'big')

    return padded_input


def message_partition(padded_input: bytes) -> list[bytes]:
    chunk_array = []
    for i in range(0, len(padded_input), 64):
        chunk = padded_input[i:i+64]
        chunk_array.append(chunk)
    return chunk_array


def right_shift(value: bytes, shifts: int) -> bytes:
    return value >> shifts


def left_shift(value: bytes, shifts: int) -> bytes:
        return value << shifts


def rotr(value: bytes, shifts: int) -> bytes:
     return right_shift(value, shifts) | left_shift(value, 32 - shifts) & 0xFFFFFFFF


def sha256_compress(chunk: bytes, H: list[bytes]) -> bytes:
    # create a 64-entry message schedule array w[0..63] of 32-bit words
    w_array = []
    for i in range(0, 64, 4):
        four_bytes = chunk[i:i+4]
        word = int.from_bytes(four_bytes, 'big')
        w_array.append(word)

    for i in range(16, 64):
        s0 = rotr(w_array[i-15], 7) ^ rotr(w_array[i-15], 18) ^ rotr(w_array[i-15], 3)
        s1 = rotr(w_array[i-2], 17) ^ rotr(w_array[i-2], 19) ^ rotr(w_array[i-2], 10)
        new_word = (w_array[i-16] + s0 + w_array[i-7] + s1) & 0xFFFFFFFF
        w_array.append(new_word)

    a,b,c,d,e,f,g,h = H

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~ e) & g)
        temp1 = h + S1 + ch + K[i] + w_array[i]
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
    for chunks in message_partition(padded_input):
          H = sha256_compress(chunks, H)
    return ''.join(f'{x:08x}' for x in H)
