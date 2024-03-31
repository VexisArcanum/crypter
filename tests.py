from crypter import *


def _test_crypt(function1, function2, _tab=0, *args, **kwargs):
    from time import time as clock
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

    _test_crypt(c.encrypt, c.decrypt, 1, message)

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
