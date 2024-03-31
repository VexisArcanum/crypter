from codec import *
from constants import *
from imports import *
from util import *


class Crypter:
    """
        Higher level abstractions for cryptography (crypto) library's symmetric ciphers.

        The Crypter class handles all symmetric encryption/decryption options available through
        crypto.hazmat.primitives.ciphers.algorithms. It can perform a simple encrypt (AES, Blowfish, etc; CBC, ECB, etc)
        and return a bytes object to ensure confidentiality,  hmac_encrypt to ensure integrity, and a buffered_encrypt
        mode to conserve memory (default buffer ~1MB). Buffer size can be adjusted when instantiating the Crypter
        object.

        Only a password is needed to initialize a Crypter object that uses AES-256-CBC with a random IV. IV is assigned
        as 'crypter.iv_or_nonce'. It is prepended to all returned ciphertexts and indexed during decryption functions.
    """
    def __init__(self, password: (str, bytes), cipherspec: (str, tuple) = 'AES-256-GCM', iv_or_nonce: bytes = None,
                 padding='random', buffering: int = 0xf5000, kdf_salt=None, **kwargs):
        """
        Use this method to initialize a new Crypter object with the specified parameters. Defaults are: AES cipher with
        a 256 bit (32 byte) key and random IV. If a buffered method is used, the buffering parameter dictates how many
        bytes with be read, processed, and yielded (with padding) until all data is read from the buffer. The buffered
        methods are generators, and should be iterated over until all chunks are yielded. The IV is prepended to all
        encrypted messages and assigned to the iv_or_nonce property of an instance for easy retrieval if needed. IV is
        prepended to all messages. The key is derived from an appropriate algorithm using the user-supplied password.
        The key is derived using Scrypt with default params n=2**17, r=8, and p=1.

        :keyword password: Plaintext str or bytes-like object
        :keyword cipherspec: Str representation or tuple return value of Crypter.parse_cipherspec(representation)
        :keyword iv_or_nonce: Bytes object used with certain modes
        :keyword buffering: Int value to use with Crypter.buffered_encrypt and Crypter.buffered_decrypt
        :keyword kdf_salt: Bytes value to use with Scrypt KDF (default 64 random bytes)
        :keyword kwargs: These extra parameters MUST match for related encryption and decryption operations.
            :key scrypt_n:
        """
        self._kwargs = kwargs
        if not isinstance(cipherspec, tuple):
            cipherspec = Crypter.parse_cipherspec(cipherspec)
        elif len(cipherspec) != 3:
            raise ValueError('Cipherspec must be a string or 3-tuple return value of Crypter.parse_cipherspec().')
        _algo, key_size, cipher_mode = cipherspec
        self._cipher_mode = cipher_mode
        self.cipherspec = self.generate_cipherspec(_algo, key_size, cipher_mode)
        del cipherspec

        if (kdf_salt is not None) and (not isinstance(kdf_salt, bytes) or len(kdf_salt) > 64):
            raise TypeError('kdf_salt must be up to 64 bytes or None.')
        elif kdf_salt is None:
            # kdf_salt = urandom(64)
            kdf_salt = digest(password, algo='sha3_256')
        elif len(kdf_salt) < 64:
            pad_zero(kdf_salt, 64)

        password = tobytes(password)
        self.kdf_salt = kdf_salt
        key = Scrypt(self.kdf_salt,
                     key_size // 8,
                     kwargs.get('scrypt_n', 2 ** 16),
                     kwargs.get('scrypt_r', 8),
                     kwargs.get('scrypt_p', 1),
                     crypto_backend).derive(password)
        del password, key_size, kdf_salt

        _algo = _algo(key)
        del key

        self._padding = padding
        if padding == 'pkcs7':
            self.padding = pad_pkcs7
        elif padding == 'random':
            self.padding = pad_random
        elif padding == 'zero':
            self.padding = pad_zero
        elif padding in ('ansi', 'ansix923'):
            self.padding = pad_ansix923
        else:
            raise ValueError('Padding must be PKCS7, ANSI or ANSIX923, zero, or random (case insensitive).')
        del padding

        # zelf.metadata = run_length_encode()

        self.block_size_bytes = _algo.block_size // 8
        # if buffering % self.block_size_bytes != 0:
        #    raise ValueError(
        #        'Buffering must be a multiple of the cipher\'s block size ({}).'.format(self.block_size_bytes)
        #    )
        self.buffering = buffering
        del buffering

        if self._cipher_mode is not None and self._cipher_mode is not crypto_ECB:
            self.cipher_mode = self._cipher_mode(iv_or_nonce if iv_or_nonce is not None else
                                                 urandom(self.block_size_bytes)
                                                 )
        elif self._cipher_mode is not None:
            self.cipher_mode = cipher_mode()
        else:
            self.cipher_mode = crypto_ECB()
        del cipher_mode

        self.iv_or_nonce = self.cipher_mode.initialization_vector if \
            isinstance(self.cipher_mode, crypto_modes.ModeWithInitializationVector) else \
            self.cipher_mode.nonce if isinstance(self.cipher_mode, crypto_modes.ModeWithNonce) \
            else b''

        def buffered_encrypt(buffer: IOBase):
            f"""
            Conserve memory by reading only `{self.buffering}` bytes from $buffer at a time. Yields `{buffering}` size
            encrypted chunks for writing. Buffer must be readable, and can be read-only.

            Yields:
                IV or nonce or b''
                Encrypted bytes in `{self.buffering}` sized chunks
                Tag if cipher has tag or b''
            """
            if not buffer.readable():
                raise IOError('Buffer must be readable')

            algo = crypto_cipher(_algo, self.cipher_mode, crypto_backend)
            encryptor = algo.encryptor()

            data = buffer.read(self.buffering)
            # total = 0

            yield self.iv_or_nonce or b''

            padder = PKCS7(self.block_size_bytes * 8).padder()
            while data:
                yield encryptor.update(padder.update(data))
                data = buffer.read(self.buffering)

            yield encryptor.update(padder.finalize()) + encryptor.finalize() + (
                b'' if not isinstance(self.cipher_mode, crypto_ModeWithTag) else encryptor.tag)

            if self._cipher_mode is not crypto_ECB:
                self.iv_or_nonce = urandom(self.block_size_bytes)
                self.cipher_mode = self._cipher_mode(self.iv_or_nonce)

            # return total

        def buffered_decrypt(buffer: (IOBase, BytesIO)):
            """
            [See docstring for buffered_encrypt]
            Decrypts the contents of a buffer $buffersize bytes at a time.
            """
            if not buffer.readable():
                raise IOError('Buffer must be readable')

            _t = buffer.tell()

            if self._cipher_mode is not crypto_ECB and self._cipher_mode is not None:
                _iv = buffer.read(self.block_size_bytes)
                algo = crypto_cipher(_algo, self._cipher_mode(_iv), crypto_backend)
            else:
                algo = crypto_cipher(_algo, crypto_ECB(), crypto_backend)

            decryptor = algo.decryptor()
            unpadder = PKCS7(self.block_size_bytes * 8).unpadder()

            data = buffer.read(self.buffering + self.block_size_bytes)
            while data:
                yield unpadder.update(decryptor.update(data))
                data = buffer.read(self.buffering + self.block_size_bytes)
            yield unpadder.update(decryptor.finalize()) + unpadder.finalize()
            buffer.seek(_t)

        def hmac_encrypt(string_or_bytes: (str, bytes), hmac_key: (str, bytes)=None, salt: bytes=None,
                         hash_algo='sha3_512'):
            """
            Encrypt a $string_or_bytes instance using the native algorithm, and authenticate using HMAC-$hash_algo.
            Default settings generate a random salt and hmac_key for each use (transmission not handled, can be
            user-defined) and uses HMAC-SHA512.

            Returns a 2-tuple of bytestrings consisting of the HMAC key, and a message containing the  salt (length of
            HMAC digest), HMAC digest (variable), and the message in the form: b'[salt][hmac][message]'

            :param string_or_bytes: String or bytes instance
            :param hmac_key: String or bytes instance (must be kept secret to avoid MAC forging)
            :param salt: Bytes object; if None, defaults to 64 random bytes. Salt is padded with random bytes if its len
                is less than 64
            :param hash_algo: String representation of algorithm. Must be one of hashlib.algorithms_available.
            :return: Tuple Bytes HMAC key, Bytes concatenation of salt (HMAC digest size), HMAC (_algo().digest_size),
                and encrypted message.
            """
            if salt and not isinstance(salt, bytes):
                raise ValueError('Salt must be in bytes')

            hash_algo = hash_algo.lower()
            if hash_algo not in hashlib.algorithms_available:
                raise ValueError('Algo must be one of {}'.format(hashlib.algorithms_available))

            hash_algo = hashlib.new(hash_algo)
            digest_size = hash_algo.digest_size

            if salt is None:
                salt = urandom(digest_size)
            elif len(salt) < digest_size:
                salt = pad_random(salt, digest_size)
            elif len(salt) == digest_size:
                salt = salt
            else:
                raise ValueError('Salt cannot be longer than the digest of the algorithm ({})'.format(digest_size))

            hmac_key = hmac_key if hmac_key is not None else Crypter.urandom(digest_size)

            _hmac = hmac.new(hmac_key, salt, hash_algo.name)

            algo = crypto_base.Cipher(_algo, self.cipher_mode, crypto_backend)
            encryptor = algo.encryptor()

            string_or_bytes = self.padding(tobytes(string_or_bytes), self.block_size_bytes)

            if self._cipher_mode is not crypto_ECB and self._cipher_mode is not None:
                string_or_bytes = self.iv_or_nonce + encryptor.update(string_or_bytes) + encryptor.finalize()
                self.iv_or_nonce = urandom(self.block_size_bytes)
                self.cipher_mode = self._cipher_mode(self.iv_or_nonce)
            else:
                string_or_bytes = encryptor.update(string_or_bytes) + encryptor.finalize()
            
            if isinstance(self.cipher_mode, crypto_ModeWithTag):
                string_or_bytes = encryptor.tag + string_or_bytes

            _hmac.update(string_or_bytes)

            return hmac_key, b''.join((salt, _hmac.digest(), string_or_bytes))

        def hmac_decrypt(hmac_key: (str, bytes), _bytes: (str, bytes), hash_algo='sha3_512'):
            """
            Decrypt $string_or_bytes using $hmac_key with an instance of HMAC-$hash_algo to verify integrity of message.

            Returns the bytes representation of the plaintext message.

            :param hmac_key: String or bytes representation of HMAC key
            :param _bytes: String or bytes instance to be authenticated and decrypted
            :param hash_algo: String representation of hash algorithm used by the HMAC implementation.
            :return: Bytes plaintext
            """
            hash_algo = hash_algo.lower()
            _bytes = tobytes(_bytes)
            if hash_algo not in hashlib.algorithms_available:
                raise ValueError('Algo must be one of {}'.format(hashlib.algorithms_available))
            b'\x56\x41'

            _bsize = hashlib.new(hash_algo).digest_size

            salt = _bytes[:_bsize]
            _bytes_hmac = _bytes[_bsize:2*_bsize]
            # _iv = _bytes[2*digest_size:2*digest_size+16]
            _bytes = _bytes[2*_bsize:]

            _hmac = hmac.new(hmac_key, salt, hash_algo)
            _hmac.update(_bytes)
            if not hmac.compare_digest(_hmac.digest(), _bytes_hmac):
                raise AuthenticationError('HMAC could not be verified')

            if self._cipher_mode is not crypto_ECB:
                _tag = None
                if isinstance(self.cipher_mode, crypto_ModeWithTag):
                    _tag = _bytes[:16]
                    _bytes = _bytes[16:]
                _iv = _bytes[:self.block_size_bytes]
                _bytes = _bytes[self.block_size_bytes:]
                algo = crypto_base.Cipher(_algo, self._cipher_mode(_iv) if not _tag else
                                          self._cipher_mode(_iv, _tag), crypto_backend)
            else:
                algo = crypto_base.Cipher(_algo, crypto_ECB(), crypto_backend)
            decryptor = algo.decryptor()

            _bytes = decryptor.update(_bytes) + decryptor.finalize()

            if self._cipher_mode is not crypto_ECB:
                self.iv_or_nonce = urandom(self.block_size_bytes)
                self.cipher_mode = self._cipher_mode(self.iv_or_nonce)

            return unpad(_bytes, self._padding)

        def encrypt(string_or_bytes: (str, bytes, bytearray)):
            """ A simple encryption. Data is padded and encrypted in a single call to the update method.

            :param string_or_bytes: Str or bytes-like object.
            :return: Bytes concatenation of the IV (if it exists) and the encrypted message.
            """

            _iv = self.iv_or_nonce
            algo = crypto_base.Cipher(_algo, self.cipher_mode, crypto_backend)
            encryptor = algo.encryptor()

            string_or_bytes = self.padding(tobytes(string_or_bytes), self.block_size_bytes)
            string_or_bytes = encryptor.update(string_or_bytes) + encryptor.finalize()

            if self._cipher_mode is not crypto_ECB:
                self.iv_or_nonce = urandom(self.block_size_bytes)
                self.cipher_mode = self._cipher_mode(self.iv_or_nonce)



            return (encryptor.tag if isinstance(self.cipher_mode, crypto_ModeWithTag) else
                    b'') + _iv + string_or_bytes if _iv is not None else string_or_bytes

        def decrypt(_bytes):
            """ [See docstring for Crypter.encrypt]
            Decrypt the result of an encrypt() call.
            """

            if self._cipher_mode is not crypto_ECB:
                _tag = None
                if isinstance(self.cipher_mode, crypto_ModeWithTag):
                    _tag = _bytes[:16]
                    _bytes = _bytes[16:]

                _iv = _bytes[:self.block_size_bytes]
                _bytes = _bytes[self.block_size_bytes:]

                if _tag is not None:
                    algo = crypto_base.Cipher(_algo, self._cipher_mode(_iv, _tag), crypto_backend)
                else:
                    algo = crypto_base.Cipher(_algo, self._cipher_mode(_iv), crypto_backend)

            else:
                algo = crypto_base.Cipher(_algo, crypto_ECB(), crypto_backend)
            decryptor = algo.decryptor()

            _bytes = decryptor.update(_bytes) + decryptor.finalize()

            return unpad(_bytes, self._padding)


        self.hmac_encrypt = hmac_encrypt
        self.hmac_decrypt = hmac_decrypt
        self.encrypt = encrypt
        self.decrypt = decrypt
        self.buffered_encrypt = buffered_encrypt
        self.buffered_decrypt = buffered_decrypt

    def file_encrypt(self, file: FileIO):
        t = file.tell()
        if not file.readable() or not isinstance(file.read(1), bytes):
            raise IOError('File must be opened as rb or rb+.')
        else:
            file.seek(t)

        for chunk in self.buffered_encrypt(file):
            yield chunk
        file.seek(t)

    def file_decrypt(self, file: FileIO):
        t = file.tell()
        if not file.readable() or not isinstance(file.read(1), bytes):
            raise IOError('File must be opened as rb or rb+.')
        else:
            file.seek(t)

        for chunk in self.buffered_decrypt(file):
            yield chunk
        file.seek(t)

    @property
    def metadata(self):
        """ Returns an informative dict containing:
            KDF Salt
            Cipherspec
            Padding
            Buffering
            kwargs
        """
        return {
            'kdf_salt': self.kdf_salt,
            'cipherspec': self.cipherspec,
            'padding': self._padding,
            'buffering': self.buffering,
            'kwargs': named_field_run_length_encode(**self._kwargs)
        }

    @staticmethod
    def parse_cipherspec(string):
        """ Convert string "cipher-size-mode" to tuple (cipher, size, mode)
        "AES-256-CBC" -> (crypto_AES, 256, crypto_CBC)
        Accepted Ciphers:
            AES
            BLO    Blow    Blowfish
            CST    CAST    CAST5
            CML    CAM     Camellia
            DES    3DES    TripleDES
            IDE    IDEA
            SED    SEED

        Accepted Key Sizes:
            Variable (Validated for selected cipher and passed to KDF)

        Accepted Modes:
            CBC
            CFB
            CTR
            ECB
            OFB
            GCM
        """
        if isinstance(string, bytes):
            string = str(string, 'UTF-8')
        elif not isinstance(string, str):
            raise TypeError('String but me a str or bytes instance.')

        if string.count('-') == 2:
            cipher, key_size, mode = list(map(lambda x: x.casefold(), string.split('-')))
        elif string.count('-') == 1:
            cipher, key_size = list(map(lambda x: x.casefold(), string.split('-')))
            mode = None
        else:
            raise ValueError('Cipherspec must be formatted as {Cipher}-{Key Size}[-{Mode (ECB)}]. Ex: AES-256-CBC.')

        if cipher == 'aes':
            cipher = crypto_AES
        elif cipher in ('cml', 'cam', 'camellia'):
            cipher = crypto_Camellia
        elif cipher in ('des', '3des', 'tripledes'):
            cipher = crypto_3DES
        else:
            raise ValueError('Crypter does not support "{}" encryption.'.format(cipher.upper()))

        if not mode or mode == 'ecb':
            mode = crypto_ECB
        elif mode == 'cbc':
            mode = crypto_CBC
        elif mode == 'cfb':
            mode = crypto_CFB
        elif mode == 'ctr':
            mode = crypto_CTR
        elif mode == 'ofb':
            mode = crypto_OFB
        elif mode == 'gcm':
            mode = crypto_GCM
        else:
            raise ValueError('Crypter does not support "{}" mode.'.format(mode))

    
        key_size = int(key_size)
        if not (key_size / 8).is_integer():
            raise ValueError('Key size must be a multiple of 8 bits.')
        elif not int(key_size) in cipher.key_sizes:
            raise ValueError(f'Crypter does not support a key size of {key_size} bits. Only {cipher.key_sizes}.')

        return cipher, key_size, mode

    @staticmethod
    def generate_cipherspec(algorithm, key_size, mode):
        def _is(value1, value2):
            return value1 is value2 or isinstance(value1, value2)

        if key_size not in algorithm.key_sizes:
            raise ValueError(f'Algorithm does not support a key size of {key_size} bits.')

        return '-'.join((algorithm.name, str(key_size), mode.name))

    @staticmethod
    def urandom(n):
        """ Circumvents alleged CryptGenRandom flaw by calling urandom for 128KiB before and after retrieving data """
        assert(len(urandom(128*1024)) == 128*1024)
        y = urandom(n)
        assert(len(urandom(128*1024)) == 128*1024)
        return y


class RSAPrivateKey:
    """ Generate an RSA keypair of $bits length and $padding padded (applies to all operations) """
    def __init__(self, keypair: rsa.RSAPrivateKey, padding=PKCS1v15, exportable=False):
        self.pubkey = keypair.public_key()
        self.padding = padding

        def encrypt(message: (str, bytes)):
            key = urandom(32)
            iv = urandom(16)
            crypter = Crypter(key, 'AES-256-CBC', iv)
            hkey, message = crypter.hmac_encrypt(message, hash_algo='sha256')
            key = self.pubkey.encrypt(hkey + iv + key, padding())

            return key+message

        def decrypt(message: (str, bytes)):
            if not isinstance(message, (str, bytes)):
                return ValueError('Message must be a string or bytes instance')

            mdat, message = message[:256], message[256:]
            mdat = keypair.decrypt(mdat, padding())
            hkey, iv, ckey = mdat[:32], mdat[32:48], mdat[48:]    # mdat[:32], mdat[32:48], mdat[48:]

            crypter = Crypter(ckey, 'AES-256-CBC', iv)
            message = crypter.hmac_decrypt(hkey, message, hash_algo='sha256')

            return message

        def sign(data, algorithm='sha512', padding_=None):
            algorithm = algorithm.lower()
            if algorithm not in ('md5', 'sha1', 'sha224', 'sha256', 'sha512'):
                raise ValueError(
                    'Algorithm must be one of {}'.format(('md5', 'sha1', 'sha224', 'sha256', 'sha512'))
                )
            elif algorithm == 'md5':
                algorithm = crypto_MD5
            elif algorithm == 'sha1':
                algorithm = crypto_SHA1
            elif algorithm == 'sha224':
                algorithm = crypto_SHA224
            elif algorithm == 'sha256':
                algorithm = crypto_SHA256
            elif algorithm == 'sha512':
                algorithm = crypto_SHA512

            padding_ = padding_ or 0
            if not padding_:
                padding_ = padding
            elif padding_ not in ('oaep', 'pss', 'pkcs1', 'pkcs1v15'):
                raise ValueError('Padding must be one of {}'.format(('oaep', 'pss', 'pkcs1', 'pkcs1v15')))
            elif padding_ == 'oaep':
                padding_ = OAEP(MGF1(algorithm()), algorithm(), None)
            elif padding_ == 'pss':
                padding_ = PSS(MGF1(algorithm()), 64)
            elif padding_ == 'pkcs1v15':
                padding_ = PKCS1v15()

            return keypair.sign(data, padding_, algorithm())

        if exportable:
            def export_private_key(encoding: str='PEM', format_: str= 'PKCS8', password=None):
                if not isinstance(encoding, str) or not isinstance(format_, str):
                    raise ValueError('Encoding and format_ must be strings')
                elif password is not None:
                    password = tobytes(password)

                encoding = encoding.lower()
                format_ = format_.lower()

                if encoding == 'pem':    # or encoding not in ('pem', 'der', 'openssh'):
                    encoding = crypto_serial.Encoding.PEM
                elif encoding == 'der':
                    encoding = crypto_serial.Encoding.DER
                elif encoding == 'openssh':
                    encoding = crypto_serial.Encoding.OpenSSH
                else:
                    raise ValueError('Encoding must be one of {} (case insensetive).'.format(('PEM', 'DER', 'OpenSSH')))

                if format_ == 'pkcs8':    # or format_ not in ('pkcs8', 'traditionalopenssl', 'openssl'):
                    format_ = crypto_serial.PrivateFormat.PKCS8
                elif format_ in ('openssl', 'traditionalopenssl'):
                    format_ = crypto_serial.PrivateFormat.TraditionalOpenSSL
                else:
                    raise ValueError('Format must be one of {} (case insensetive).'.format(
                        ('PKCS8', 'OpenSSL', 'TraditionalOpenSSL')
                    ))

                return password, keypair.private_bytes(encoding, format_,
                                                       crypto_serial.BestAvailableEncryption(password) if
                                                       password is not None else crypto_serial.NoEncryption()
                                                       )
            self.export_private_key = export_private_key

        self.encrypt = encrypt
        self.decrypt = decrypt
        self.sign = sign

    @classmethod
    def generate_keypair(cls, bits=2048, public_exponent=65537, padding=PKCS1v15, exportable=False):
        return cls(rsa.generate_private_key(public_exponent, bits, default_backend()), padding, exportable)

    def export_public_key(self, encoding: str='PEM', _format: str= 'PKCS1'):
        """
        Return the public bytes of the current RSA keypair
        :param encoding: String 'PEM', 'DER', or 'OpenSSL'
        :param _format: String 'PKCS1', or 'OpenSSH'
        :return: Bytes public key
        """
        if not isinstance(encoding, str) or not isinstance(_format, str):
            return ValueError('Encoding and _format must be strings')
        encoding = encoding.lower()
        _format = _format.lower()

        if encoding == 'pem' or encoding not in ('pem', 'der', 'openssh'):
            encoding = crypto_serial.Encoding.PEM
        elif encoding == 'der':
            encoding = crypto_serial.Encoding.DER
        elif encoding == 'openssh':
            encoding = crypto_serial.Encoding.OpenSSH

        if _format == 'pkcs1' or _format not in ('pkcs1', 'openssh'):
            _format = crypto_serial.PublicFormat.PKCS1
        else:
            _format = crypto_serial.PublicFormat.OpenSSH

        return self.pubkey.public_bytes(encoding, _format)


def complex_authenticated_encrypt(message, key):
    message, key = tobytes(message), tobytes(key)
    schedule = KeySchedule.new(key)
    del key

    key_salts = [urandom(32) for _ in range(3)]
    keys = [schedule.keygen(salt=key_salts[i], digest_size=32) for i in range(3)]
    hmac_key_salts = [urandom(16) for _ in range(3)]
    hmac_keys = [schedule.keygen(salt=hmac_key_salts[i]) for i in range(3)]
    crypters = [Crypter(key[1]) for key in keys]
    for i, crypter in enumerate(crypters):
        hmac_salt = urandom(32)
        e = crypter.hmac_encrypt(message, hmac_keys[i][1], hmac_salt, 'sha256')[1]
        message = keys[i][0] + key_salts[i] + crypter.iv_or_nonce + hmac_key_salts[i] + hmac_keys[i][0] + e
    return schedule.salt + message


def complex_authenticated_decrypt(message, key):
    key = tobytes(key)
    s_salt, message = message[:64], message[64:]
    schedule = KeySchedule.new(key, s_salt)

    for _ in range(3):
        k_coord = message[0]
        k_salt = message[1:33]
        c_iv = message[33:49]
        hk_salt = message[49:65]
        hk_coord = message[65:66]

        crypter = Crypter(schedule.keygen(k_coord, k_salt, 32)[1], iv_or_nonce=c_iv)
        hmac_key = schedule.keygen(hk_coord, hk_salt)[1]
        message = crypter.hmac_decrypt(hmac_key, message[66:], 'sha256')

    return message


def simple_authenticated_encrypt(message, key):
    key = tobytes(key)

    c = Crypter(key)

    hk_salt = urandom(16)
    _hkdf = PBKDF2HMAC(crypto_SHA512, 64, hk_salt, 100_000, crypto_backend)
    hk = _hkdf.derive(key)

    message = c.hmac_encrypt(message, hk, hash_algo='sha256')[1]
    return hk_salt + c.kdf_salt + message


def simple_authenticated_decrypt(message, key):
    key = tobytes(key)

    c = Crypter(key, kdf_salt=message[16:80])
    hk_salt = message[:16]
    _hkdf = PBKDF2HMAC(crypto_SHA512, 64, hk_salt, 100_000, crypto_backend)
    hk = _hkdf.derive(key)

    return c.hmac_decrypt(hk, message[80:], 'sha256')


def file_encrypt(path, key, buffering=0xf5000):
    # path = _path.abspath(path)
    path = pathlib.Path(path)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError('No file at path "{}"'.format(path.group()))

    from shutil import move

    key = tobytes(key)

    c = Crypter(key, buffering=buffering)
    iv = c.iv_or_nonce
    scrypt_salt = c.kdf_salt

    _kdf_salt = urandom(64)
    _kdf = PBKDF2HMAC(crypto_SHA512, 64, _kdf_salt, 100_000, crypto_backend)
    _hmac_salt = urandom(64)
    _hmac = hmac.new(_kdf.derive(key), _hmac_salt + iv, legacy_sha512)

    str_path = str(path)

    move(str_path, str_path + '.tmp')

    with pathlib.Path(str_path).open('wb+') as f, pathlib.Path(str_path+'.tmp').open('rb+') as ft:
        f.write(b'\x00'*272)
        for chunk in c.buffered_encrypt(ft):
            _hmac.update(chunk)
            f.write(chunk)
            f.flush()
        ft.close()
        f.seek(0)

        _hmac = _hmac.digest()

        f.write(scrypt_salt + _kdf_salt + _hmac_salt + _hmac + iv)
        f.flush()
        f.close()

    shred(str_path + '.tmp', buffersize=buffering)


def file_decrypt(path, key, buffering=0xf5000):
    # path = _path.abspath(path)
    path = pathlib.Path(path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError('No file exists at path "{}"'.format(path.group()))

    from shutil import move

    key = tobytes(key)
    _iv = b''
    _scrypt_salt = b''

    with path.open('rb') as f:
        header = f.read(272)
        if len(header) < 272:
            raise EOFError('HMAC header is too short')

        _scrypt_salt = header[:64]
        _kdf_salt = header[64:128]
        _hmac_salt = header[128:192]
        _hmac_bytes = header[192:256]
        _iv = header[256:]

        _kdf = PBKDF2HMAC(crypto_SHA512, 64, _kdf_salt, 100_000, crypto_backend)

        _hmac = hmac.new(_kdf.derive(key), _hmac_salt + _iv, legacy_sha512)

        data = f.read(buffering)

        while data:
            _hmac.update(data)
            data = f.read(buffering)

        if not hmac.compare_digest(_hmac.digest(), _hmac_bytes):
            raise AuthenticationError('Cannot verify HMAC')

        f.close()

    str_path = str(path)
    move(str_path, str_path + '.tmp')

    with path.open('wb+') as f, pathlib.Path(str_path+'.tmp').open('rb') as ft:
        ft.seek(272)
        c = Crypter(key, iv_or_nonce=_iv, buffering=buffering, kdf_salt=_scrypt_salt)

        for chunk in c.buffered_decrypt(ft):
            f.write(chunk)
            f.flush()

        f.close()
        ft.close()

    remove(str_path + '.tmp')


def encrypt(message, key):
    c = Crypter(key)
    return c.encrypt(message)


def decrypt(message, key):
    
    c = Crypter(key)
    message = c.decrypt(message[64:])

    return message


def standard_encrypt(message, key):
    from time import time
    from struct import pack
    timestamp = pack('<d', time())

    message, key = tobytes(message), tobytes(key)
    crypter = Crypter(key, padding='pkcs7')

    hmac_key_salt = urandom(64)
    hmac_key = PBKDF2HMAC(crypto_SHA512, 64, hmac_key_salt, 100_000, crypto_backend).derive(key)
    message = crypter.kdf_salt + hmac_key_salt + crypter.hmac_encrypt(timestamp + message, hmac_key)[1]

    # _hmac = hmac.new(hmac_key, message, 'sha3_512').digest()
    return message


def standard_decrypt(message, key, expiry=None):
    if not isinstance(expiry, (type(None), int)):
        raise TypeError('Expiry must be an integer or None.')
    elif not isinstance(message, bytes):
        raise TypeError('Message must be in bytes.')
    from time import time
    from struct import unpack

    key = tobytes(key)
    scrypt_salt = message[:64]

    hmac_key_salt = message[64:128]
    hmac_key = PBKDF2HMAC(crypto_SHA512, 64, hmac_key_salt, 100_000, crypto_backend).derive(key)

    message = message[128:]
    crypter = Crypter(key, kdf_salt=scrypt_salt, padding='pkcs7')

    message = crypter.hmac_decrypt(hmac_key, message)
    timestamp, message = unpack('<d', message[:8])[0], message[8:]

    if expiry is None:
        return message
    elif time() > timestamp + expiry:
        raise ExpiryExceededError('Message age has exceeded expiration time.')
    else:
        return message


