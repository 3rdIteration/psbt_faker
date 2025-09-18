import struct, hashlib
from .ripemd import ripemd160


def parse_origin_string(origin):
    """Parse an origin string of the form ``F23A9C1D/84h/1h/0h``.

    The fingerprint component is required and must be expressed as an eight
    character hexadecimal value. The derivation path portion is optional and
    may include hardened markers using either ``'`` or ``h`` suffixes. Leading
    ``m/`` prefixes are ignored. Returns a tuple of ``(fingerprint_bytes,
    derivation_path_or_None)``.
    """

    if origin is None:
        raise ValueError("missing origin")

    value = origin.strip()
    if not value:
        raise ValueError("empty origin")

    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]

    if not value:
        raise ValueError("empty origin")

    parts = value.split("/", 1)
    fingerprint = parts[0].strip()
    if len(fingerprint) != 8:
        raise ValueError("fingerprint must be 8 hex characters")
    try:
        xfp = bytes.fromhex(fingerprint)
    except ValueError as exc:
        raise ValueError("fingerprint must be hexadecimal") from exc

    path = None
    if len(parts) == 2:
        path = parts[1].strip()
        if path:
            if path[0] in "mM":
                if len(path) == 1:
                    path = None
                elif path[1] == "/":
                    path = path[2:]
            if path:
                path = path.rstrip("/")
        else:
            path = None

    return xfp, path

def str2ipath(s):
    # convert text to numeric path for BIP174
    for i in s.split('/'):
        if i == 'm': continue
        if not i: continue      # trailing or duplicated slashes

        if i[-1] in "'ph":
            assert len(i) >= 2, i
            here = int(i[:-1]) | 0x80000000
        else:
            here = int(i)
            assert 0 <= here < 0x80000000, here

        yield here

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return struct.pack('>I', xfp).hex().upper()

def str2path(xfp, s):
    # output binary needed for BIP-174
    p = list(str2ipath(s))
    return bytes.fromhex(xfp) + struct.pack('<%dI' % (len(p)), *p)

def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())