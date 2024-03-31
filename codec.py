from imports import *

def pad_ansix923(string_or_bytes, *args):
    del args
    string_or_bytes = tobytes(string_or_bytes)
    padder = ANSIX923(128).padder()
    return padder.update(string_or_bytes) + padder.finalize()


def pad_pkcs7(string_or_bytes, *args):
    del args
    string_or_bytes = tobytes(string_or_bytes)
    padder = PKCS7(128).padder()
    return padder.update(string_or_bytes) + padder.finalize()


def pad_pseudorandom(string_or_bytes, padding=16, algo='sha3_512'):
    string_or_bytes = tobytes(string_or_bytes)

    # if not isinstance(padding, int) or not 0 < padding < 256:
    #    raise ValueError('Padding must be a positive integer such that 0 < padding < 256.')

    len_mod = padding - (len(string_or_bytes) % padding)
    string_or_bytes += hashlib.new(algo, string_or_bytes).digest()[:len_mod]
    string_or_bytes += hashlib.new(algo, string_or_bytes).digest()[:padding]

    return string_or_bytes


def pad_random(string_or_bytes, padding=16):
    string_or_bytes = tobytes(string_or_bytes)

    if type(padding) is not int or not 0 < padding < 256:
        raise ValueError('Padding must be a positive integer such that 0 < padding < 256.')

    len_mod = padding - (len(string_or_bytes) % padding + 1)
    string_or_bytes += urandom(len_mod) + len_mod.to_bytes(1, 'little')

    return string_or_bytes


def pad_zero(string_or_bytes, padding=16):
    string_or_bytes = tobytes(string_or_bytes)

    if type(padding) is not int or 0 >= padding:
        raise ValueError('Padding must be a positive integer above 0')

    string_or_bytes += b'\x01'
    len_mod = len(string_or_bytes) % padding

    if len_mod != 0:
        string_or_bytes += b'\x00' * (padding - len_mod)

    return string_or_bytes


def tobytes(data, encoding='UTF-8'):
    if type(data) is bytes:
        return data
    elif not isinstance(data, (str, list, bytes, bytearray, int, float)):
        raise ValueError('Can only convert str, list, bytes-like object, or real number')
    elif isinstance(data, (bytearray, list)):
        data = bytes(data)
    elif isinstance(data, str):
        data = bytes(data, encoding)
    elif isinstance(data, int):
        data = data.to_bytes(data.bit_length() // 8 + 1, 'little')
    elif isinstance(data, float):
        data = bytes(data.hex(), 'UTF-8')

    return data


def unpad(_bytes, padding='zero'):
    padding = padding.lower()
    # _bytes = tobytes(_bytes)

    if padding == 'zero':
        return _bytes.rstrip(b'\x00')[:-1]
    elif padding == 'random':
        return _bytes[:-_bytes[-1] - 1]
    elif padding == 'pkcs7':
        unpadder = PKCS7(128).unpadder()
        try:
            return unpadder.update(_bytes) + unpadder.finalize()
        except ValueError:
            raise
    elif padding in ('ansi', 'ansix923'):
        unpadder = ANSIX923(128).unpadder()
        try:
            return unpadder.update(_bytes) + unpadder.finalize()
        except ValueError:
            raise
    else:
        raise ValueError('Padding must be PKCS7, ANSIX923, random, or zero (case insensitive)')
