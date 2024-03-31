def xor(a, *b):
    a = tobytes(a)
    r = a
    a_len = len(a)
    for _b in b:
        _b = tobytes(_b)
        for index, byte in enumerate(_b):
            i = index % a_len
            r = r[:i] + bytes([r[i] ^ byte]) + r[i+1:]

    return r


def digest(data, salt=b'', algo='sha3_512', rounds=1, **kwargs):
    data = tobytes(data)
    for _ in range(rounds):
        data = hashlib.new(algo, salt + data, **kwargs).digest()

    return data


def digest_dir(dir_path, salt=b'', buffersize=0xf5000, algo=sha512):
    """ Hash all files found within a specified directory, with recursion. Does not follow links """
    dir_path = pathlib.Path(dir_path)
    if not dir_path.exists() or not dir_path.is_dir():
        raise FileNotFoundError('Path must be a directory')

    main_algo = algo(salt)

    def _search(path: pathlib.Path):
        if path.is_dir():
            main_algo.update(path.name)
            for f in path.iterdir():
                _search(path.joinpath(f))
        elif path.is_file():
            main_algo.update(digest_file(path, salt, buffersize, algo))

    _search(dir_path)

    return main_algo.digest()


def digest_file(file_path, salt=b'', buffersize=0xf5000, algo=sha512):
    """ Digest the contents of a file using $algo, reading $buffersize bytes at a time """
    h = algo(salt)
    with open(file_path, 'rb') as f:
        data = f.read(buffersize)
        while data:
            h.update(data)
            data = f.read(buffersize)
        f.close()
    return h.digest()


def generate_password(length=12):
    return base64.b85encode(Crypter.urandom(length))[:length]


def shred(*paths, buffersize=0xf5000):

    for path in paths:
        path = _path.abspath(path)
        if not _path.exists(path) or _path.isdir(path):
            raise ValueError('No file at path "{}"'.format(_path))

        file_size = stat(path).st_size

        for r in range(2):
            # print('Pass {} (1-bits):'.format(r*2+1))
            total = 0
            f = open(path, 'wb+')
            while total < file_size:
                # print('\t{} bytes written'.format(total))
                f.write(b'\xff'*buffersize)
                f.flush()
                total += buffersize
            f.close()

            # print('Pass {} (0-bits):'.format(r*2+2))
            total = 0
            f = open(path, 'wb+')
            while total < file_size:
                # print('\t{} bytes written'.format(total))
                f.write(b'\x00'*file_size)
                f.flush()
                total += buffersize
            f.close()

        # print('Pass 5 (random):')
        total = 0
        f = open(path, 'wb+')
        while total < file_size:
            # print('\t{} bytes written'.format(total))
            f.write(urandom(file_size))
            f.flush()
            total += buffersize
        f.close()

        remove(path)


def run_length_decode(data, errors='strict', replace_with=b'\x3f'):
    if not isinstance(data, bytes):
        raise TypeError('Data must be in bytes.')
    elif not isinstance(errors, str):
        raise TypeError('Errors must be a string.')

    errors = errors.lower()

    if errors in ('strict', 'replace', 'ignore'):
        raise TypeError('Errors must be "strict", "replace", or "ignore".')

    r = []
    _index = 0

    while data:
        _len_len = data[0]
        _len = int.from_bytes(data[1:_len_len+1], 'little', signed=False)
        _index += _len_len + _len + 1

        try:
            data[_len_len+_len]
        except IndexError:
            if errors == 'strict':
                raise RunLengthDecodeError('Cannot decode bytes at position {}.'.format(_index-_len))
            elif errors == 'replace':
                r.append(replace_with)
            else:
                pass
            data = data[1:]
            continue

        r.append(data[_len_len+1:_len_len+1+_len])
        data = data[_len_len+_len+1:]

    return r


def run_length_encode(*data):
    r = b''
    for data in data:
        data = tobytes(data)
        _len = len(data)
        _len = _len.to_bytes(_len.bit_length()//8 + 1, 'little', signed=False)
        _len_len = len(_len)

        r += _len_len.to_bytes(1, 'little', signed=False) + _len + data

    return r


def named_field_run_length_encode(obj: dict={},**data):
    r = b''
    if not isinstance(obj, dict) or not all(map(lambda kv: isinstance(kv, str), dict.keys + dict.values)):
        raise TypeError("obj must be a dict with the format: {'strKey': 'strValue', ...}")
    
    for key in data:
        key = tobytes(key)
        k_len = len(key)
        k_len = k_len.to_bytes(1, 'little', signed=False)
        r += k_len + key + run_length_encode(data.get(str(key, 'UTF-8')))

    return r


def named_field_run_length_decode(data: bytes):
    if not isinstance(data, bytes):
        raise TypeError('Data must be in bytes.')

    r = {}
    while data:
        f_len = data[0]
        f = data[1:1+f_len]
        data = data[1+f_len:]

        _len_len = data[0]
        _len = int.from_bytes(data[1:_len_len + 1], 'little', signed=False)
        r[str(f, 'UTF-8')] = data[_len_len + 1:_len_len + 1 + _len]
        data = data[_len_len + _len + 1:]

    return r


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
