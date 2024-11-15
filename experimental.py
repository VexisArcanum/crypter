from crypter import *


"""
These functions are not well-tested and are not to be considered secure for production environments.
"""

def deep_hash(x, n=1):
    x = tobytes(x)
    for i in range(n):
        _i = i.to_bytes(i.bit_length()//8 + 1, 'little', signed=False)
        l = len(x)
        x = bytes(byt ^ x[i % l] for i, byt in enumerate(sha512(sha256(_i + x).digest() + x).digest()))
    return x


class KDF:
    def __index__(self, key, digest_size=64):
        if not isinstance(digest_size, int):
            raise ValueError('Digest size must be an integer.')

        key = tobytes(key)

        def scrypt(salt=None, n=2**14, r=8, p=1):
            if salt is None:
                salt = urandom(32)
            elif not isinstance(salt, bytes):
                raise TypeError('Salt must be bytes or None.')

            return salt, Scrypt(salt, digest_size, n, r, p, crypto_backend).derive(key)

        def pbkdf2(salt=None, algorithm='sha3_512', iterations=100_000):
            if salt is None:
                salt = urandom(32)
            elif not isinstance(salt, bytes):
                raise TypeError('Salt must be bytes or None.')

            return salt, hashlib.pbkdf2_hmac(algorithm, key, salt, iterations, digest_size)

        def _hash(salt=None, algorithm='sha3_512'):
            if salt is None:
                salt = urandom(32)
            elif not isinstance(salt, bytes):
                raise TypeError('Salt must be bytes or None.')

            return digest(key, salt, algorithm)

        self.scrypt = scrypt
        self.pbkdf2 = pbkdf2
        self.hash = _hash


class KeyFile:
    """ Handle plaintext or encrypted binary symmetric key files.
    """
    def __init__(self, path, encryption=False, password=None):
        self.file = open(path, 'rb')
        self.encrypted = encryption
        if encryption is True:
            if not password:
                raise ValueError('When encryption is True, user must supply a password')
            password = tobytes(password)
            self._salt = self.file.read(32)
            self._password = digest(password, self._salt, 'sha256')
            self._key = None
        else:
            self._key = self.file.read()

    def close(self):
        self.file.close()
        del self._key, self._password

    @property
    def key(self):
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
        if not self._key:
            self._key = aes_key_unwrap(self._password.digest(), self.file.read(), crypto_backend)
        return self._key

    @property
    def urlsafe_key(self):
        return base64.urlsafe_b64encode(self.key)

    @classmethod
    def new(cls, path, encryption=False, password=None):
        key = Crypter.urandom(64)

        if encryption is True:
            if not password:
                raise ValueError('When encryption is True, user must supply password')
            from cryptography.hazmat.primitives.keywrap import aes_key_wrap
            salt = urandom(32)
            _password = sha256(salt + tobytes(password)).digest()
            key = salt + aes_key_wrap(_password, key, crypto_backend)

        with open(path, 'wb+') as f:
            f.write(key)
            f.flush()
            f.close()

        return cls(path, encryption, password)


class KeySchedule:
    """
    From a password, create a KeySchedule object that can generate cryptographically strong keys of a desired length.

    The KeySchedule object is meant to sacrifice computational cost and time in exchange for security. Use the
    KeySchedule.new method to create a new schedule from a password. Additional options allow the user to modify the
    salt, iterations, and a value "_n". N is the number of bytes to be used in coordinates. The size of the schedule is
    static, and is determined by the formula 2**(8*_n) + 63. _n=1 results in a shedule of 256 + 63. The addition of 63
    bytes is to allow full range of coordinates (0-255:_n=1, 0-65535:_n=2, ...) for extractions of 64-byte chunks.

    The KeySchedule.extract(coordinate: bytes) method will return the raw value of the schedule at
    [coordinate:coordinate+64]. This data must be kept secret under normal conditions, because an attacker could
    reconstruct the full schedule if given enough chunks. Always use the KeySchedule.keygen method to generate keys.

    The KeySchedule.keygen method will return a tuple (coordinate, key). Additional options
    allow for the user to specify a salt, digest size, algorithm, and iterations when hashing the raw extraction. This
    data is suitable for cryptographic use.

    The KeySchedule.verify method can be used to verify that a key originated from the current schedule. Options mimic
    KeySchedule.keygen, since the method simply checks that the key matches the one generated with the given parameters.

    The KeySchedule.new classmethod creates a new KeySchedule object from a password. Additional options allow the user
    to configure a salt, iterations, and n, the coorinate length in bytes.

    The KeySchedule.from_file function allows the user to load a raw keyblock from a file. It's faster than using the
    .new method because it only reads the data, it doesn't run it through the KDF. Extraction speeds will not vary.
    """
    def __init__(self):
        self.n = None
        self.period = None
        self.salt = None
        self.raw = None

    def export(self, file_path, password, encryption='AES-256-CBC', overwrite=False):
        file_path = pathlib.Path(file_path)

        if file_path.exists() and overwrite is not True:
            raise FileExistsError('Path already exists. To ignore, use param overwrite=True.')

        if encryption is not None and password is not None:
            crypter = Crypter(password)
            hkdf_salt = urandom(64)
            _hkdf = PBKDF2HMAC(crypto_SHA512, 64, hkdf_salt, 100_000, crypto_backend)
            _hmac_salt = urandom(64)
            _hmac = hmac.new(_hkdf.derive(password), _hmac_salt, 'sha3_512')
            for i in range(0, self.period-64, 64):
                # data = crypter.hmac_encrypt(b''.join(self.extract(i*64) for i in range(self.period)),
                #                            _hkdf.derive(password))
                data = crypter.encrypt(self.extract(i))
                _hmac.update(data)
                file_path.write_bytes(data)

            # file_path.write_bytes(data)
        elif password is None:
            raise ValueError('Must specify a password when encrypting exported KeySchedule.')

    def extract(self, coordinate: int|bytes):
        """ Return raw data from schedule at coordinate [$coordinate:$coordinate+64]. WARNING: Do not share the values
         returned by this function. """
        coordinate = int.from_bytes(coordinate, 'little') if not isinstance(coordinate, int) else coordinate
        if coordinate + 64 > self.period:
            raise ValueError('Coordinate cannot exceed {}'.format(self.period - 63))
        return self.raw[coordinate:coordinate + 64]

    def keygen(self, coordinate=None, salt=None, digest_size=None, algo='sha3_512', iterations=100):
        """ Extract data from self.raw and hash using $algo for $iterations iterations. If $digest_size is smaller
        than that of $algo, then the output is truncated and XORed to produce the return value. If $digest_size is
        larger than that of $algo, then the digest is entended with the same round procedure, except the output extends
        the data instead of replacing it.
        """
        salt = salt or Crypter.urandom(16)

        if algo not in hashlib.algorithms_available:
            raise ValueError('Algo must be one of {}'.format(hashlib.algorithms_available))

        algo = hashlib.new(algo, salt)
        coordinate = urandom(self.n) if coordinate is None else coordinate

        k = self.extract(coordinate)
        #algo.update(k)
        #k = algo.digest()

        for _ in range(iterations):
            algo.update(k)
            k = algo.digest()


        if isinstance(digest_size, int):
            if digest_size < algo.digest_size:
                k = xor(k[digest_size:], k[:digest_size])
            else:
                _last = k
                while len(k) < digest_size:
                    algo.update(_last)
                    _last = algo.digest()
                    k += _last

        return coordinate + salt + k

    def verify(self, token, algo='sha3_512', iterations=100):
        """ Verify that a given key was derived from the current schedule. """
        coordinate = token[:self.n]
        salt = token[self.n:self.n+16]
        key = token[self.n+16:]

        return hmac.compare_digest(self.keygen(coordinate, salt, len(key), algo, iterations)[self.n+16:], key)

    @classmethod
    def new(cls, password, salt=None, n=1, scrypt_n=2**16):
        period = 2**(8*n) + 63
        container = cls()
        container.n = n
        container.period = period
        container.salt = salt = salt if salt is not None else urandom(64)
        kdf = Scrypt(salt, period, scrypt_n, 8, 1, crypto_backend)
        # kdf = PBKDF2HMAC(crypto_SHA512, period, salt, iterations, default_backend())
        container.raw = kdf.derive(tobytes(password))

        return container

    @classmethod
    def from_file(cls, path, n=1):
        path = pathlib.Path(path)
        period = 2**(8*n) + 63
        data = path.read_bytes()

        if len(data) < period:
            while len(data) < period:
                data += sha512(data).digest()
            data = data[:period]

        container = cls()
        container.n = n
        container.period = period
        container.salt = b''
        container.raw = data

        return container


class LamportSignatory:
    """ Implement the generation, signing, and verification functions according to the Lamport Signature scheme. """

    def __init__(self, short_private_key_len=4096):
        if not isinstance(short_private_key_len, (int, float)):
            raise ValueError('Short private key length must be int or float.')

        self.scrypt_salt = urandom(64)
        short_private_key = Crypter.urandom(short_private_key_len)
        private_key = Scrypt(self.scrypt_salt, 64*4096, 2**14, 8, 1, crypto_backend).derive(short_private_key)
        private_key = tuple(
            (
                private_key[i*64:(i+1)*64],
                private_key[(i+1)*64:(i+2)*64]
            ) for i in range(0, 2048, 2)
        )
        legacy_private_key = tuple((Crypter.urandom(64), Crypter.urandom(64)) for _ in range(2048))
        self.legacy_public_key = \
            tuple(map(lambda x: (sha512(x[0]).digest(), sha512(x[1]).digest()), legacy_private_key))

        def _digest(tree: (tuple, list), n=12):
            """ Tree digest for the private_key. Allows for shorter public keys and signatures. """
            # scrypt_args = (self.kdf_salt, 64, 2**6, 16, 1, crypto_backend)
            if n <= 0 or len(tree) < 1:
                return tree
            elif len(tree) == 1:
                return sha512(tree[0][0] + tree[0][1]).digest()
            _tree = []
            for leaf in tree:
                # scrypt = Scrypt(*scrypt_args)
                if len(_tree) == 0 or len(_tree[-1]) == 2:
                    _tree.append([sha512(leaf[0] + leaf[1]).digest()])
                else:
                    _tree[-1].append(sha512(leaf[0] + leaf[1]).digest())

            return _digest(_tree, n-1)

        self.short_public_key = _digest(private_key)
        # sha512(b''.join([x[0] + x[1] for x in _digest(private_key)])).digest()

        # from math import log2

        # def tree_div(tree: list, coordinates: tuple((int, int))):
        #     tree_len = len(tree)
        #     try:
        #         assert log2(tree_len).is_integer()
        #     except AssertionError:
        #         raise ValueError('Length of tree must be a power of 2.')

        #     coordinate_x, coordinate_y = coordinates
        #     tree_len_div = tree_len // 2
        #     x = tree[:tree_len_div] if coordinate_x < tree_len_div else tree[tree_len_div:]
        #     for i in range(tree_len_div):
        #         pass

        def sign(message, algo='sha3_512'):
            message = tobytes(message)
            md = hashlib.new(algo, message).digest()
            sig = b''

            for index, bit in enumerate(bin(int.from_bytes(md, 'little'))[2:]):
                sig += legacy_private_key[index][int(bit)]

            return sig

        def short_sign(message, algo='sha3_256', salt=None):
            """ Sign a message using a hash tree approach. Uses sha512 for tree hashing private key. Will use 1 randomly
            selected value from the hash tree. Signature will include:
                Private value determined by md
                Relevant intermediate tree

                :param message: Str|Bytes message to be signed
                :param algo: Str message hash algorithm name
                :param salt: Salt to use when digesting the message
            """
            message = tobytes(message)
            if not salt or not isinstance(salt, bytes):
                salt = urandom(64)
            md = hashlib.new(algo, salt + message).digest()

            coordinates = divmod(int.from_bytes(md, 'little'), 12)
            # print(coordinates)

            tree = _digest(private_key, coordinates[1]+1)
            # tree = [tree[i*64:(i+1)*64] for i in range(len(tree)//64)]

            digest_n = _digest_n = coordinates[0] % (len(tree) * 2)
            c0 = divmod(digest_n, 2)

            sig = tree[c0[0]][c0[1]]

            # halfway = len(tree) // 2

            def __digest(_tree):
                if len(_tree) == 1:
                    return _digest(tree)

                nonlocal _digest_n
                _halfway = len(_tree) // 2
                _digest_n /= 2
                _half_digest = _digest(_tree[:_halfway] if _digest_n > _halfway else _tree[_halfway:])
                # _half_digest = list(b''.join(x) for x in _half_digest)
                _tree = _tree[_halfway:] if digest_n > _halfway else _tree[:_halfway]

                return __digest(_tree) + _half_digest
                # return _half_digest + __digest(_tree) if _digest_n > _halfway \
                #    else __digest(_tree) + _half_digest

            if c0[1] == 0:
                sig += tree[c0[0]][1]
            else:
                sig += tree[c0[0]][0]

            # TODO: Reconstruct tree with only necessary values to confirm tree hash

            tree = __digest(tree)
            return salt+sig + tree    # b''.join(map(lambda x: x if isinstance(x, bytes) else b''.join(x), tree))

        self.sign = sign
        self.short_sign = short_sign

    @staticmethod
    def pretty_format(sig, header='SIGNATURE', width=64):
        from math import floor, ceil
        from re import sub

        try:
            assert len(header) <= width - 6
        except AssertionError:
            raise ValueError('Header cannot be longer than (width - 6) bytes.')

        header = header.upper()

        width0 = (width - len(header) - 6) / 2
        width1 = (width - len(header) - 2) / 2
        width_left = int(floor(width0))

        return '-'*width_left + 'BEGIN {}'.format(header) + '-'*int(ceil(width0)) + '\n' + \
               sub(r'[\w\d+/=]{,%d}' % width, lambda x: x.group() + '\n',
                   str(base64.b64encode(sig), 'UTF-8')) + \
               '-'*int(width_left) + 'END {}'.format(header) + '-'*int(ceil(width1)) + '\n'

    @staticmethod
    def short_verify(message, sig, public_key, algo='sha512'):
        # from math import log2

        message = tobytes(message)
        salt = sig[:64]
        sig = sig[64:]
        md = hashlib.new(algo, salt + message).digest()
        coordinates = divmod(int.from_bytes(md, 'little'), 12)
        digest_n = _digest_n = coordinates[0] % (len(sig) // 128)
        c0 = divmod(digest_n, 2)

        def _digest(tree: (tuple, list), n=12):
            """ Tree digest for the private_key. Allows for shorter public keys and signatures. """
            # scrypt_args = (self.kdf_salt, 64, 2**6, 16, 1, crypto_backend)
            if n <= 0 or len(tree) < 2:
                return tree
            _tree = []
            for leaf in tree:
                # scrypt = Scrypt(*scrypt_args)
                if len(_tree) == 0 or len(_tree[-1]) == 2:
                    _tree.append([sha512(leaf[0] + leaf[1]).digest()])
                else:
                    _tree[-1].append(sha512(leaf[0] + leaf[1]).digest())

            return _digest(_tree, n-1)

        def __digest(tree, n=_digest_n):
            if len(tree) < 2:
                return tree
            # nonlocal _digest_n
            _halfway = len(tree) // 2
            n /= 2
            _half_digest = _digest(tree[:_halfway] if n > _halfway else tree[_halfway:])
            _half_digest = list(b''.join(x) for x in _half_digest)
            tree = tree[_halfway:] if digest_n > _halfway else tree[:_halfway]

            return __digest(tree, n) + [b''.join(_half_digest)]

        _sig = [sig[i*64:(i+1)*64] for i in range(len(sig)//64)]

        salt = _sig[0]
        sig = _sig[1:2][::1 if c0[1] == 0 else -1]

    @staticmethod
    def unpretty_format(sig):
        return base64.b64decode(bytes(''.join(sig.splitlines()[1:-1]), 'UTF-8'))

    @staticmethod
    def verify(message, sig: bytes, public_key, algo='sha512'):
        message = tobytes(message)
        md = hashlib.new(algo, message).digest()

        _sig = b''
        for index, bit in enumerate(bin(int.from_bytes(md, 'little'))[2:]):
            _sig += public_key[index][int(bit)]

        sig = b''.join(map(lambda x: legacy_sha512(x).digest(), (sig[i * 64:(i + 1) * 64] for i in range(512))))

        return hmac.compare_digest(sig, _sig)


class MultiKeyWrapper:
    """
    Wrap multiple key components in one package using run_length_encode, random padding, and AES encryption.

    Useful for handling multiple key components such as IVs, salts, KeySchedule coordinates, or keys themselves.

    The MultiKeyWraper.update method adds an entry to the components table using the index $componenent of value $value.
    """

    def __init__(self):
        self.components = {}

    def update(self, component, value):
        """ Add component value to list of components. """
        self.components[component] = value

    def remove(self, component):
        """ Remove a component value from list of components. """
        del self.components[component]

    def wrap(self, wrapping_key=None):
        """ Return the encrypted contents of the components list via run_length_ and a Crypter object """
        # from marshal import dumps
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        wrapping_key = wrapping_key if wrapping_key is not None else Crypter.urandom(32)
        data = Crypter.urandom(16) + named_field_run_length_encode(**self.components)
        data = pad_random(data)
        return wrapping_key, aes_key_wrap(wrapping_key, data, default_backend())

    @classmethod
    def unwrap(cls, wrapping_key, data):
        # from marshal import loads
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
        """ Returns a MultiKeyWrapper object, using the decrypted data to populate the components list. """
        data = aes_key_unwrap(wrapping_key, data, default_backend())
        data = unpad(data[:16], 'random')
        container = cls()
        container.components = named_field_run_length_decode(data)
        return container


class RollingKey:
    """ Rolling key generation based on agreed-upon starting point; does not offer perfect forward secrecy
    Version 0:
        sha256/MD5/sha224 modes ('sha', 'legacy_md5', <other> respectively)

        Algorithm:
            Iter 0:    Hash(psk).digest()
            Iter 1:    Hash(Hash(psk).digest()).digest() or Hash(Iter 0).digest()
            ...
        Can derive all future keys from psk alone
    Version 1:
        sha512/MD5/sha256 modes ('sha', 'legacy_md5', <other> respectively)
    Proposed Version 2
        Use PBKDF2
        Add salt parameter to key generation to allow PFS assuming secure salt exchange

        Algorithm:
            Iter 0:    Hash([salt]+psk).digest()
            Iter 1:    Hash([salt]+Iter 0).digest()
            ...
        Can only derive keys when salt(s) is/are used in the proper iteration(s)
    """
    key = None
    i = 0

    def __init__(self, key, i=0, mode='sha'):
        key = bytes(key, 'UTF-8') if type(key) is not bytes else key
        self.key = sha512() if mode.lower() == 'sha' else legacy_md5() if mode.lower() == 'legacy_md5' else sha256()
        self.i = i

        for _ in range(self.i + 1):
            self.roll()

        key = urandom(len(key))
        del key

    def roll(self):
        self.i += 1
        self.key.update(self.key.digest())

    def get_key(self, mode='hex'):
        return self.key.hexdigest() if mode.lower() == 'hex' else self.key.digest() if mode.lower() == 'bytes' else\
               ValueError('Mode must be either "hex" or "bytes" (case insensitive)')

    def spawn_key(self, mode='hex'):
        spawn = self.get_key(mode)
        self.roll()
        return spawn


def smac(message, key, salt=None, mode='default', length=32):
    message = tobytes(message)
    key = tobytes(key)

    if mode not in ('default', 'fast', 'secure', 'extreme', 'overkill'):
        raise ValueError('Mode must be one of {}.'.format(('default', 'fast', 'secure', 'extreme', 'overkill')))

    params = [32, (2**14, 8, 1), (2**14, 8, 1)] if mode == 'default' else \
        [16, (2**12, 8, 1), (2**10, 8, 1)] if mode == 'fast' else \
        [32, (2**15, 16, 1), (2**14, 8, 1)] if mode == 'secure' else \
        [48, (2**17, 16, 2), (2**14, 12, 2)] if mode == 'extreme' else \
        [64, (2**18, 24, 4), (2**17, 18, 4)] if mode == 'overkill' else None

    if salt is None:
        salt = urandom(params[0])
    elif not isinstance(salt, bytes):
        raise TypeError('Salt must be bytes or None.')

    return salt + Scrypt(
        salt,
        length,
        *params[1],
        crypto_backend
    ).derive(Scrypt(salt, length * 2, *params[2], crypto_backend).derive(key) + message)


def worst_encryption_ever(message, password):
    message = tobytes(message)
    password = tobytes(password)
    key = hashlib.new('MD4', password).digest()[:5]

    cipher = crypto_base.Cipher(algorithms.ARC4(key), None, crypto_backend).encryptor()
    message = cipher.update(message) + cipher.finalize()

    return message


def worst_decryption_ever(message, password):
    password = tobytes(password)
    key = hashlib.new('MD4', password).digest()[:5]

    cipher = crypto_base.Cipher(algorithms.ARC4(key), None, crypto_backend).decryptor()
    message = cipher.update(message) + cipher.finalize()

    return message

