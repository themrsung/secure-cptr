"""Minimal QR Code encoder (byte mode, EC level M, versions 1-10).

Self-contained on purpose: cptr ships a locked dependency set, and the only
thing we need a QR code for is the TOTP `otpauth://` enrolment URI (~130
chars, comfortably inside version 8-M). Implements ISO/IEC 18004.

Output is an SVG string so the frontend can render it without a JS library.
"""

from __future__ import annotations

# ── Static tables (ISO/IEC 18004, level M only) ───────────────────

# version -> (ec_codewords_per_block, [(block_count, data_codewords_per_block)])
_EC_M: dict[int, tuple[int, list[tuple[int, int]]]] = {
    1: (10, [(1, 16)]),
    2: (16, [(1, 28)]),
    3: (26, [(1, 44)]),
    4: (18, [(2, 32)]),
    5: (24, [(2, 43)]),
    6: (16, [(4, 27)]),
    7: (18, [(4, 31)]),
    8: (22, [(2, 38), (2, 39)]),
    9: (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
}

# version -> alignment pattern centre coordinates
_ALIGN: dict[int, list[int]] = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
    7: [6, 22, 38],
    8: [6, 24, 42],
    9: [6, 26, 46],
    10: [6, 28, 50],
}

# Bits of padding after the interleaved codeword stream.
_REMAINDER = {1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0}

_EC_LEVEL_M_BITS = 0b00  # level M indicator used in the format string

# ── GF(256) arithmetic, primitive polynomial 0x11D ────────────────

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rs_generator(degree: int) -> list[int]:
    """Generator polynomial for `degree` error-correction codewords."""
    poly = [1]
    for i in range(degree):
        nxt = [0] * (len(poly) + 1)
        for j, c in enumerate(poly):
            nxt[j] ^= c
            nxt[j + 1] ^= _gf_mul(c, _EXP[i])
        poly = nxt
    return poly


def _rs_encode(data: list[int], ec_len: int) -> list[int]:
    gen = _rs_generator(ec_len)
    rem = [0] * ec_len
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for i, g in enumerate(gen[1:]):
            rem[i] ^= _gf_mul(g, factor)
    return rem


# ── Bit stream assembly ───────────────────────────────────────────


def _choose_version(length: int) -> int:
    for version in range(1, 11):
        ec_len, blocks = _EC_M[version]
        capacity = sum(count * size for count, size in blocks)
        header = 4 + (8 if version < 10 else 16)
        if (header + length * 8 + 7) // 8 <= capacity:
            return version
    raise ValueError("payload too large for a version-10 QR code")


def _build_codewords(data: bytes, version: int) -> list[int]:
    ec_len, blocks = _EC_M[version]
    total_data = sum(count * size for count, size in blocks)

    bits: list[int] = []

    def put(value: int, width: int) -> None:
        for i in range(width - 1, -1, -1):
            bits.append((value >> i) & 1)

    put(0b0100, 4)  # byte mode
    put(len(data), 8 if version < 10 else 16)
    for byte in data:
        put(byte, 8)

    # Terminator (up to four zero bits), then pad to a byte boundary.
    put(0, min(4, total_data * 8 - len(bits)))
    if len(bits) % 8:
        put(0, 8 - len(bits) % 8)

    codewords = [int("".join(str(b) for b in bits[i : i + 8]), 2) for i in range(0, len(bits), 8)]
    for pad in _cycle_pad(total_data - len(codewords)):
        codewords.append(pad)

    # Split into blocks, generate EC, then interleave both streams.
    data_blocks: list[list[int]] = []
    ec_blocks: list[list[int]] = []
    pos = 0
    for count, size in blocks:
        for _ in range(count):
            chunk = codewords[pos : pos + size]
            pos += size
            data_blocks.append(chunk)
            ec_blocks.append(_rs_encode(chunk, ec_len))

    result: list[int] = []
    for i in range(max(len(b) for b in data_blocks)):
        for block in data_blocks:
            if i < len(block):
                result.append(block[i])
    for i in range(ec_len):
        for block in ec_blocks:
            result.append(block[i])
    return result


def _cycle_pad(n: int) -> list[int]:
    pads = [0xEC, 0x11]
    return [pads[i % 2] for i in range(n)]


# ── Matrix construction ───────────────────────────────────────────


class _Matrix:
    __slots__ = ("size", "modules", "reserved")

    def __init__(self, size: int):
        self.size = size
        self.modules = [[0] * size for _ in range(size)]
        self.reserved = [[False] * size for _ in range(size)]

    def set(self, r: int, c: int, value: int, reserve: bool = True) -> None:
        self.modules[r][c] = value
        if reserve:
            self.reserved[r][c] = True


def _place_function_patterns(m: _Matrix, version: int) -> None:
    size = m.size

    def finder(top: int, left: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = top + r, left + c
                if not (0 <= rr < size and 0 <= cc < size):
                    continue
                inside = 0 <= r < 7 and 0 <= c < 7
                dark = inside and (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
                m.set(rr, cc, 1 if dark else 0)

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    # Timing patterns
    for i in range(8, size - 8):
        bit = 1 if i % 2 == 0 else 0
        m.set(6, i, bit)
        m.set(i, 6, bit)

    # Alignment patterns (skipped where they would overlap a finder)
    centres = _ALIGN[version]
    for r in centres:
        for c in centres:
            if (r, c) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    dark = max(abs(dr), abs(dc)) != 1
                    m.set(r + dr, c + dc, 1 if dark else 0)

    # Dark module
    m.set(size - 8, 8, 1)

    # Reserve format information areas
    for i in range(9):
        if not m.reserved[8][i]:
            m.set(8, i, 0)
        if not m.reserved[i][8]:
            m.set(i, 8, 0)
    for i in range(8):
        m.set(8, size - 1 - i, 0)
        m.set(size - 1 - i, 8, 0)

    # Version information (version 7 and above)
    if version >= 7:
        bits = _version_bits(version)
        for i in range(18):
            bit = (bits >> i) & 1
            r, c = i // 3, size - 11 + i % 3
            m.set(r, c, bit)
            m.set(c, r, bit)


def _version_bits(version: int) -> int:
    rem = version
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return (version << 12) | rem


def _format_bits(mask: int) -> int:
    data = (_EC_LEVEL_M_BITS << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def _place_data(m: _Matrix, codewords: list[int], version: int) -> None:
    size = m.size
    bits: list[int] = []
    for cw in codewords:
        for i in range(7, -1, -1):
            bits.append((cw >> i) & 1)
    bits.extend([0] * _REMAINDER[version])

    idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:  # skip the vertical timing column
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if m.reserved[row][c]:
                    continue
                m.modules[row][c] = bits[idx] if idx < len(bits) else 0
                idx += 1
        upward = not upward
        col -= 2


def _mask_condition(mask: int, r: int, c: int) -> bool:
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if mask == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def _apply_mask(m: _Matrix, mask: int) -> list[list[int]]:
    out = [row[:] for row in m.modules]
    for r in range(m.size):
        for c in range(m.size):
            if not m.reserved[r][c] and _mask_condition(mask, r, c):
                out[r][c] ^= 1
    return out


def _penalty(grid: list[list[int]]) -> int:
    size = len(grid)
    score = 0

    # Rule 1: runs of five or more same-coloured modules.
    for line in list(grid) + [list(col) for col in zip(*grid)]:
        run, prev = 1, line[0]
        for value in line[1:]:
            if value == prev:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run, prev = 1, value
        if run >= 5:
            score += 3 + (run - 5)

    # Rule 2: 2x2 blocks of one colour.
    for r in range(size - 1):
        for c in range(size - 1):
            if grid[r][c] == grid[r][c + 1] == grid[r + 1][c] == grid[r + 1][c + 1]:
                score += 3

    # Rule 3: finder-like 1:1:3:1:1 patterns with four light modules.
    a = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    b = list(reversed(a))
    for line in list(grid) + [list(col) for col in zip(*grid)]:
        for i in range(size - 10):
            window = line[i : i + 11]
            if window == a or window == b:
                score += 40

    # Rule 4: deviation from a 50% dark ratio.
    dark = sum(sum(row) for row in grid)
    ratio = dark * 100 / (size * size)
    score += 10 * (int(abs(ratio - 50)) // 5)
    return score


def _place_format(grid: list[list[int]], mask: int) -> None:
    size = len(grid)
    bits = _format_bits(mask)
    for i in range(15):
        bit = (bits >> i) & 1
        # Copy 1: up the left side of the top-left finder, then across.
        if i < 6:
            grid[i][8] = bit
        elif i == 6:
            grid[7][8] = bit
        elif i == 7:
            grid[8][8] = bit
        elif i == 8:
            grid[8][7] = bit
        else:
            grid[8][14 - i] = bit
        # Copy 2: along row 8 by the top-right finder, then down by the
        # bottom-left one.
        if i < 8:
            grid[8][size - 1 - i] = bit
        else:
            grid[size - 15 + i][8] = bit
    grid[size - 8][8] = 1  # dark module


def encode(data: str) -> list[list[int]]:
    """Encode `data` and return the final module matrix (1 = dark)."""
    payload = data.encode("utf-8")
    version = _choose_version(len(payload))
    codewords = _build_codewords(payload, version)

    matrix = _Matrix(17 + 4 * version)
    _place_function_patterns(matrix, version)
    _place_data(matrix, codewords, version)

    best, best_score = None, None
    for mask in range(8):
        grid = _apply_mask(matrix, mask)
        _place_format(grid, mask)
        score = _penalty(grid)
        if best_score is None or score < best_score:
            best, best_score = grid, score
    assert best is not None
    return best


def svg(data: str, *, scale: int = 6, quiet: int = 4) -> str:
    """Render `data` as a crisp, theme-agnostic SVG string.

    Dark modules use `currentColor` so the QR inherits the surrounding text
    colour and stays legible in both light and dark themes; the light modules
    are painted white because scanners need real contrast.
    """
    grid = encode(data)
    size = len(grid)
    dim = (size + quiet * 2) * scale

    paths: list[str] = []
    for r, row in enumerate(grid):
        c = 0
        while c < size:
            if row[c]:
                start = c
                while c < size and row[c]:
                    c += 1
                x = (start + quiet) * scale
                y = (r + quiet) * scale
                paths.append(f"M{x} {y}h{(c - start) * scale}v{scale}h-{(c - start) * scale}z")
            else:
                c += 1

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" '
        f'width="{dim}" height="{dim}" shape-rendering="crispEdges" role="img" '
        f'aria-label="TOTP enrolment QR code">'
        f'<rect width="{dim}" height="{dim}" fill="#fff"/>'
        f'<path fill="currentColor" d="{"".join(paths)}"/>'
        f"</svg>"
    )
