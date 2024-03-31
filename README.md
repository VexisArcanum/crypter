# crypter
## Python "crypto-for-humans" library built on cryptography.io with secure defaults and flexible options for experts.

This library project started in 2016 and continued until 2019. At the time, all code was private, but constantly being tested. Much of this code is solid, but it was a hobby project and no third party review was performed. Use this code carefully.

Simplest options, utilizing secure defaults:
```
from crypter import encrypt, decrypt

key = "password"
encrypted = encrypt("Hello, world!", key)
decrypted = decrypt(encrypted, key)
```

Simplest example of the Crypter class:

```
from crypter import Crypter


crypter = Crypter("password") # encryption key derived using scrypt
encrypted = crypter.encrypt("Hello, world!") # includes salt in return value
decrypted = crypter.decrypt(encrypted) # returns plaintext
```
