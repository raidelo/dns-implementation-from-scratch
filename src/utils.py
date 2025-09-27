def get_bits(integer: int, left_padding: int | None = None) -> str:
    bits = bin(integer).replace("0b", "")
    if left_padding:
        return bits.zfill(left_padding)
    left_padding = 8
    while True:
        if len(bits) == left_padding:
            return bits
        elif len(bits) < left_padding:
            return bits.zfill(left_padding)
        else:
            left_padding += 8
