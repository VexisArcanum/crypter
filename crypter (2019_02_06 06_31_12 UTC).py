# 5641
import base64
import hmac
import hashlib
import pathlib
# from base64 import b64encode, b64decode
from sha3 import sha3_256 as sha256, sha3_512 as sha512
from io import FileIO, IOBase, BytesIO
from os import urandom, remove, path as _path, stat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives import serialization as crypto_serial
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15, OAEP, MGF1, PSS
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import base as crypto_base
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.padding import PKCS7, ANSIX923
# TODO: Use function level imports for rarely-implemented modules


legacy_md5 = hashlib.md5
legacy_sha1 = hashlib.sha1
legacy_sha224 = hashlib.sha224
legacy_sha256 = hashlib.sha256
legacy_sha384 = hashlib.sha384
legacy_sha512 = hashlib.sha512

crypto_AES = algorithms.AES
crypto_Blowfish = algorithms.Blowfish
crypto_CAST5 = algorithms.CAST5
crypto_Camellia = algorithms.Camellia
crypto_3DES = algorithms.TripleDES
crypto_IDEA = algorithms.IDEA
crypto_SEED = algorithms.SEED

crypto_modes = crypto_base.modes
crypto_ModeWithIV = crypto_modes.ModeWithInitializationVector
crypto_MoveWithNonce = crypto_modes.ModeWithNonce
crypto_ModeWithTag = crypto_modes.ModeWithAuthenticationTag

crypto_CBC = crypto_modes.CBC
crypto_GCM = crypto_modes.GCM
crypto_ECB = crypto_modes.ECB
crypto_CFB = crypto_modes.CFB
crypto_CTR = crypto_modes.CTR
crypto_OFB = crypto_modes.OFB

crypto_hash = crypto_hashes.Hash
crypto_BLAKE2b = crypto_hashes.BLAKE2b
crypto_BLAKE2s = crypto_hashes.BLAKE2s
crypto_MD5 = crypto_hashes.MD5
crypto_SHA1 = crypto_hashes.SHA1
crypto_SHA224 = crypto_hashes.SHA224
crypto_SHA256 = crypto_hashes.SHA256
crypto_SHA384 = crypto_hashes.SHA384
crypto_SHA512 = crypto_hashes.SHA512

crypto_cipher = crypto_base.Cipher
crypto_backend = default_backend()


class AuthenticationError(Exception):
    pass


class RunLengthDecodeError(Exception):
    pass


class ExpiryExceededError(Exception):
    pass


class Crypter:
    """
        Higher level abstractions for cryptography (crypto) libary's symmetric ciphers.

        The Crypter class handles all symmetric encryption/decryption options available through
        crypto.hazmat.primitives.ciphers.algorithms. It can perform a simple encrypt (AES, Blowfish, etc; CBC, ECB, etc)
        and return a bytes object to ensure confidentiality,  hmac_encrypt to ensure integrity, and a buffered_encrypt
        mode to conserve memory (default buffer ~1MB). Buffersize can be adjusted when instantiating the Crypter
        object.

        Only a password is needed to initialize a Crypter object that uses AES-256-CBC with a random IV. IV is assigned
        as 'crypter.iv_or_nonce'. It is prepended to all returned ciphertexts and indexed during decryption functions.
    """
    # def __init__(self, key, keysize=256, cipher='aes', mode=None, iv_or_nonce=None):
    def __init__(self, password: (str, bytes), cipherspec: (str, tuple)='AES-256-CBC', iv_or_nonce: bytes=None,
                 padding='random', buffering: int=0xf5000, kdf_salt=None, **kwargs):
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
            kdf_salt = urandom(64)
        elif len(kdf_salt) < 64:
            pad_zero(kdf_salt, 64)

        password = tobytes(password)
        self.kdf_salt = kdf_salt
        key = Scrypt(self.kdf_salt,
                     key_size // 8,
                     kwargs.get('scrypt_n', 2 ** 17),
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
            self.cipher_mode.nonce if isinstance(self.cipher_mode, crypto_modes.ModeWithNonce) else b''

        def buffered_encrypt(buffer: (FileIO, IOBase)):
            """
            Conserve memory by reading only $crypter.buffering bytes from $buffer at a time. Yields $buffering size
            encrypted chunks for writing. Buffer must be readable, and can be read-only. Uses native algorithm, set when
            instantiating the Crypter object (default AES-256-CBC).

            Yields:
                IV or nonce
                Encrypted bytes in $buffering sized chunks
                Tag if isinstance(self.cipher_mode, crypto_ModeWithTag) else b''
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
                    _bytes = _bytes[:16]
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
            # elif self._cipher_mode is crypto_GCM:
            #     _tag = _bytes[:16]
            #     _iv = _bytes[16:16+self.block_size_bytes]
            #     _bytes = _bytes[16+self.block_size_bytes:]
            #     algo = crypto_base.Cipher(_algo, self._cipher_mode(_iv, _tag), crypto_backend)
            else:
                algo = crypto_base.Cipher(_algo, crypto_ECB(), crypto_backend)
            decryptor = algo.decryptor()

            _bytes = decryptor.update(_bytes) + decryptor.finalize()

            return unpad(_bytes, self._padding)

        # def raw_encrypt(string_or_bytes):
        #     encryptor = _algo.encryptor()
        #     return encryptor.update(self.padding(tobytes(string_or_bytes), self.block_size_bytes)) + encryptor.finalize()

        # def raw_decrypt(_bytes):
        #     decryptor = _algo.decryptor()
        #     return unpad(decryptor.update(_bytes) + decryptor.finalize(), self._padding)

        self.hmac_encrypt = hmac_encrypt
        self.hmac_decrypt = hmac_decrypt
        self.encrypt = encrypt
        self.decrypt = decrypt
        self.buffered_encrypt = buffered_encrypt
        self.buffered_decrypt = buffered_decrypt
        # self.raw_encrypt = raw_encrypt
        # self.raw_decrypt = raw_decrypt
        # self.file_encrypt = file_enrypt
        # self.file_decrypt = file_decrypt
        # self.roll_key = roll_key

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
        """ Returns an informative string containing:
            KDF Salt
            Cipherspec
            Padding
            Buffering
            kwargs
        """
        return named_field_run_length_encode(
            kdf_salt=self.kdf_salt,
            cipherspec=self.cipherspec,
            padding=self._padding,
            buffering=self.buffering,
            kwargs=named_field_run_length_encode(**self._kwargs)
        )

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
        elif cipher in ('blo', 'blow', 'blowfish'):
            cipher = crypto_Blowfish
        elif cipher in ('cst', 'cast', 'cast5'):
            cipher = crypto_CAST5
        elif cipher in ('cml', 'cam', 'camellia'):
            cipher = crypto_Camellia
        elif cipher in ('des', '3des', 'tripledes'):
            cipher = crypto_3DES
        elif cipher in ('ide', 'idea'):
            cipher = crypto_IDEA
        elif cipher in ('sed', 'seed'):
            cipher = crypto_SEED
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

        if not int(key_size) in cipher.key_sizes:
            raise ValueError('Cipher doesn\'t support a key size of {}, only {}.'.format(key_size, cipher.key_sizes))

        # if key_size == '128':
        #     return cipher, 16, mode
        # elif key_size == '160':
        #     return cipher, 20, mode
        # elif key_size == '192':
        #     return cipher, 24, mode
        # elif key_size == '256':
        #     return cipher, 32, mode
        # elif key_size == '384':
        #     return cipher, 48, mode
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

        # ra = rl = rm = ''
        # if _is(algorithm, crypto_AES):
        #     ra = 'AES'
        # elif _is(algorithm, crypto_Blowfish):
        #     ra = 'Blowfish'
        # elif _is(algorithm, crypto_Camellia):
        #     ra = 'Camellia'
        # elif _is(algorithm, crypto_3DES):
        #     ra = '3DES'
        # elif _is(algorithm, crypto_CAST5):
        #     ra = 'CAST5'
        # elif _is(algorithm, crypto_SEED):
        #     ra = 'SEED'
        # elif _is(algorithm, crypto_IDEA):
        #     ra = 'IDEA'
        # else:
        #     raise ValueError('Algorithm must be available through the module-level crypto_* constants.')

        if key_size not in algorithm.key_sizes:
            raise ValueError('Algorithm does not support a key size of {} bits.'.format(key_size))

        return '-'.join((algorithm.name, str(key_size), mode.name))

    @staticmethod
    def urandom(n):
        """ Circumvents alleged CryptGenRandom flaw by calling urandom for 128KiB before and after retrieving data """
        assert(len(urandom(128*1024)) == 128*1024)
        y = urandom(n)
        assert(len(urandom(128*1024)) == 128*1024)
        return y


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

    def extract(self, coordinate: (int, bytes)):
        """ Return raw data from schedule at coordinate [$coordinate:$coordinate+64]. WARNING: Do not share the values
         returned by this function. """
        coordinate = int.from_bytes(coordinate, 'little') if not isinstance(coordinate, int) else coordinate
        if coordinate + 64 > self.period:
            raise ValueError('Coordinate cannot exceed {}'.format(self.period - 63))
        return self.raw[coordinate:coordinate + 64]

    def keygen(self, coordinate=None, salt=None, digest_size=None, algo='sha512', iterations=1):
        """ Extract data from self.raw and hash using $algo for $iterations iterations. If $digest_size is smaller
        than that of $algo, then the output is truncated and XORed to produce the return value. If $digest_size is
        larger than that of $algo, then the digest is entended with the same round procedure, except the output extends
        the data instead of replacing it.
        """
        if salt is None:
            if self.salt:
                salt = self.salt
            else:
                salt = b''
        elif not isinstance(salt, bytes):
            raise TypeError('Salt must be in bytes.')

        if algo not in hashlib.algorithms_available:
            raise ValueError('Algo must be one of {}'.format(hashlib.algorithms_available))

        algo = hashlib.new(algo, salt)
        coordinate = urandom(self.n) if coordinate is None else coordinate

        k = self.extract(coordinate)
        algo.update(k)
        k = algo.digest()

        def _iter(_k, _i):
            if _i <= 0:
                return k
            algo.update(_k)
            return _iter(algo.digest(), _i-1)
        k = _iter(k, iterations)

        if isinstance(digest_size, int):
            if digest_size <= algo.digest_size:
                k = xor(k[digest_size:], k[:digest_size])
            else:
                _last = k
                while len(k) < digest_size:
                    algo.update(_last)
                    _last = algo.digest()
                    k += _last

        return coordinate, k

    def verify(self, n, key, salt=None, algo='sha512', iterations=1):
        """ Verify that a given key was derived from the current schedule. """
        return hmac.compare_digest(self.keygen(n, salt, len(key), algo, iterations)[1], key)

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


# class PasswordFile:
#     """ Handle password storage and comparison from a file format.
#     """
#     def __init__(self, path, password):
#         raise NotImplementedError
#         path = _path.abspath(path)
#         password = tobytes(password)
#
#         f = open(path, 'rb+')
#
#         salt = b64decode(f.readline().strip(b'\r\n'))
#         _password = b64decode(f.readline().strip(b'\r\n'))
#         _password = scrypt_dec(_password, password, 1)
#
#         self._file = f
#
#     @classmethod
#     def new(cls, path, password):
#         path = _path.abspath(path)
#         password = tobytes(password)
#         salt = urandom(64)
#         _password = scrypt_enc(Crypter.urandom(64), password, 1)
#
#         with open(path, 'wb+') as f:
#             f.write(b64encode(salt) + b'\n')
#             f.write(b64encode(_password) + b'\n')
#             f.flush()
#             f.close()
#
#         return cls(path, password)


class PrivateKeyGenerator:
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


class ProductKeyGenerator:
    """ Generate and validate product keys for programs """
    def __init__(self, secret, algo=crypto_SHA512, serial_func=lambda i: tobytes(i)):
        self._algo = crypto_hmac.HMAC(digest(secret), algo(), default_backend())
        self._generate_serial = serial_func
        self.serial = 0

    def generate(self, serial: int=None):
        serial = self._generate_serial(serial) if serial else self._generate_serial(self.serial + 1)
        self.serial += 1
        salt = urandom(6)
        algo = self._algo.copy()
        algo.update(salt + serial)
        return salt + algo.finalize() + serial

    def verify(self, tag):
        salt, key, serial = tag[:6], tag[6:70], tag[70:]
        algo = self._algo.copy()
        algo.update(salt + serial)
        return algo.finalize() == key


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


# def any_base_encode(x: int, data):
#     data = tobytes(data)
#     if x == 16:
#         return data.hex()
#     elif x == 32:
#         return base64.b32encode(data)
#     elif x == 64:
#         return base64.b32encode(data)
#     elif x == 85:
#         return base64.b85encode(data)
#
#     printable_chars = list(b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/')


def all_encrypt(message, key):
    message, key = tobytes(message), tobytes(key)

    key = Scrypt(
        PBKDF2HMAC(crypto_SHA512, 256, legacy_sha512(key).digest(), 100_000, crypto_backend),
        256,
        2**16,
        8,
        1,
        crypto_backend
    ).derive(key)

    aes = crypto_AES(key[:32])
    blo = crypto_Blowfish(key[32:80])
    cst = crypto_CAST5(key[80:96])
    cml = crypto_Camellia(key[96:128])
    ide = crypto_IDEA(key[128:144])
    sed = crypto_SEED(key[144:160])

    ciphers = [
        crypto_cipher(a, crypto_CBC(urandom(a.block_size)), crypto_backend)
        for a in (sed, ide, cml, cst, blo, aes)
    ]
    ivs = [c.mode.initialization_vector for c in ciphers]

    _hmac = hmac.new(key[160:224], b''.join(ivs), 'sha3_512')

    for c in ciphers:
        e = c.encryptor()
        message = e.update(pad_pkcs7(message)) + e.finalize()
        _hmac.update(
            hmac.new(sha512(message), message, 'sha3_512').digest()
        )

    return b''.join((_hmac.digest(), *ivs, message))


def all_decrypt(message, key):
    pass


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


# def _digest(data, salt=b'', algo=sha512):
#     """ Implement a hash function (sha512) using an optional salt and return
#     the digest [prepended by the b64 salt+b':']
#     """
#     if not isinstance(salt, bytes):
#         raise ValueError('Salt must be in bytes')
#
#     d = algo(b''.join((salt, tobytes(data)))).digest()
#
#     return d if len(salt) == 0 else b64encode(salt)+b':'+d


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


# def complex_authenticated_encrypt(message, key):
#    """
#    Encrypt a message using more complex encryption procedures.
#
#    Steps:
#        1) Instantiate a MultiKeyWrapper object
#        2) Generate new KeySchedule object using $key
#        3) Generate cipher key using KeySchedule object
#        4) Add cipher key coordinate and KeySchedule.salt to MultiKeyWrapper object
#        5) Instantiate a Crypter object with the derived key
#        6) Add cipher IV to MultiKeyWrapper
#        7) Derive HMAC key from KeySchedule
#        8) Add HMAC key coordinate to MultiKeyWrapper
#        9) Use the Crypter.hmac_encrypt method to perform an authenticated encryption on the data
#        10) Use MultiKeyWrapper.wrap method to wrap key components
#        11) Prepend wrapped key to message and return bytes
#
#    Pros:
#        KeySchedule KDF slows password attacks
#        HMAC=SHA512 provides integrity assurance
#        Some keys and all components are random, the rest are pseudorandom
#        Salts are random
#        Optimized for security and integrity
#
#    Cons:
#        KDF takes significantly longer than a simple hashing of the password
#        Encrypted data is significantly longer than when using other methods
#        MultiKeyWrapper wrapped ciphertext is subject to a known-plaintext attack due to marshalling
#
#    """
#    w = MultiKeyWrapper()
#    message, key = tobytes(message), tobytes(key)
#
#    s = KeySchedule.new(key)
#    coordinate, c_key = s.keygen(algo='sha256')
#
#    w.update('s_coord', coordinate)
#    w.update('s_salt', s.salt)
#    # w.update('c_key', c_key)
#
#    c = Crypter(c_key)
#    w.update('c_iv', c.iv_or_nonce)
#
#    h_coord, hmac_key = s.keygen()
#    w.update('h_coord', h_coord)
#    message = c.hmac_encrypt(message, hmac_key)[1]
#    # w.update('h_key', hmac_key)
#
#    w = w.wrap(sha256(key).digest())[1]
#    return w + message


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


def named_field_run_length_encode(**data):
    r = b''
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


def simple_authenticated_file_encrypt(path, key, buffering=0xf5000):
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


def simple_authenticated_file_decrypt(path, key, buffering=0xf5000):
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


def simple_encrypt(message, key):
    c = Crypter(key)
    return c.kdf_salt + c.encrypt(message)


# def complex_authenticated_decrypt(message, key):
#     key = tobytes(key)
#     keys, message = message[:168], message[168:]
#     keys = MultiKeyWrapper.unwrap(sha256(key).digest(), keys).components
#     s = KeySchedule.new(key, keys.get('s_salt'))
#
#     c = Crypter(s.keygen(keys.get('s_coord'), algo='sha256')[1], iv_or_nonce=keys.get('c_iv'))
#     message = c.hmac_decrypt(s.keygen(keys.get('h_coord'))[1], message)
#
#     return message


def simple_decrypt(message, key):
    if not isinstance(message, bytes):
        raise TypeError('Message must be in bytes')

    c = Crypter(key, kdf_salt=message[:64])
    message = c.decrypt(message[64:])

    return message


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


def _test_crypt(function1, function2, _tab=0, *args, **kwargs):
    from time import clock
    if not callable(function1) and callable(function2):
        raise ValueError("Functions must be callable.")

    print('\t'*_tab + "Function: {}".format(function1))
    time_0 = clock()
    r1 = function1(*args, **kwargs)
    time_1 = clock() - time_0
    print('\t'*(_tab+1) + "Time: {}".format(time_1))
    print('\t'*(_tab+1) + "Result Length: {}".format(len(r1)))
    print('\t'*(_tab+1) + "Result: {}".format(r1))
    print('\t'*_tab + "Function: {}".format(function2))
    time_0 = clock()
    r2 = function2(r1, **kwargs)
    time_2 = clock() - time_0
    print('\t' * (_tab + 1) + "Time: {}".format(time_2))
    print('\t' * (_tab + 1) + "Result Length: {}".format(len(r2)))
    print('\t' * (_tab + 1) + "Result: {}".format(r2))


def test(message="Hello world!", key='masterpass', **kwargs):
    from time import clock
    print("Crypter Test Vectors",
          "Message: {}".format(message),
          "Key: {}".format(key),
          "Misc: {}".format(kwargs),
          sep='\n')
    clock()
    c = Crypter(key)
    time_0 = clock()
    print("Object: {}".format(c), 'Time: {}'.format(time_0), '\n')
    print("Simple encrypt")
    print('\t', "Object.encrypt(Message) # Returns: Bytes iv+ciphertext")
    # time_0 = clock()
    # e = c.encrypt(message)
    # time_1 = clock() - time_0
    # print('\t\t Time: {}'.format(time_1))
    # print('\t\t', len(e), e)
    _test_crypt(c.encrypt, c.decrypt, 1, message)
    # print('\t', "Object.decrypt(Object.encrypt(Message)) # Returns: Bytes plaintext")
    # time_1 = clock()
    # d = c.decrypt(e)
    # time_2 = clock() - time_1
    # print('\t\t Time: {}'.format(time_2))
    # print('\t\t', len(d), d)
    print("HMAC-SHA3-512 Encrypt")
    time_2 = clock()
    e = c.hmac_encrypt(message)
    time_3 = clock() - time_2
    print('\t', "Object.hmac_encrypt(Message) # Returns Tuple (Bytes hmac_key, Bytes salt+hmac+iv+ciphertext)")
    print('\t\t Time: {}'.format(time_3))
    print('\t\t', len(e[1]), *e)

    time_3 = clock()
    d = c.hmac_decrypt(e[0], e[1])
    time_4 = clock() - time_3
    print('\t', "Object.hmac_decrypt(*Object.hmac_encrypt(Message))")
    print('\t\t Time: {}'.format(time_4))
    print('\t\t', len(d), d)
    print("Buffered Encrypt")
    time_45 = clock()
    b = BytesIO(tobytes(message))
    time_46 = clock() - time_45
    print('\t Buffering Time: {}'.format(time_46))
    time_4 = clock()
    e = b''.join(c.buffered_encrypt(b))
    time_5 = clock() - time_4
    print('\t', "Object.buffered_encrypt(BytesIO(Message)) # Yields Bytes ciphertext")
    print('\t\t Time: {}'.format(time_5))
    print('\t\t', len(e), e)
    time_5 = clock()
    d = b''.join(c.buffered_decrypt(BytesIO(e)))
    time_6 = clock() - time_5
    print('\t', "Object.buffered_decrypt(Object.buffered_encrypt(BytesIO(Message)))")
    print('\t\t Time: {}'.format(time_6))
    print('\t\t', len(d), d)


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


def type_preserve_encode(data, encoding='UTF-8'):
    _type = type(data)
    data = tobytes(data, encoding)

    import builtins
    builtins = list(filter(lambda x: isinstance(x, type), [eval(x) for x in dir(builtins)]))

    if _type not in builtins:
        raise TypeError('Data must be a builtin type.')

    _type = builtins.index(_type).to_bytes(1, 'little')


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


def deep_hash(x, n=1):
    x = tobytes(x)
    for i in range(n):
        _i = i.to_bytes(i.bit_length()//8 + 1, 'little', signed=False)
        l = len(x)
        x = bytes(byt ^ x[i % l] for i, byt in enumerate(sha512(sha256(_i + x).digest() + x).digest()))
    return x


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

