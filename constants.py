from imports import *


sha256 = hashlib.sha3_256
sha512 = hashlib.sha3_512

legacy_md5 = hashlib.md5
legacy_sha1 = hashlib.sha1
legacy_sha224 = hashlib.sha224
legacy_sha256 = hashlib.sha256
legacy_sha384 = hashlib.sha384
legacy_sha512 = hashlib.sha512

crypto_AES = algorithms.AES
crypto_Camellia = algorithms.Camellia
crypto_3DES = algorithms.TripleDES

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