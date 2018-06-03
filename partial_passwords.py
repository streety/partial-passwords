import base64
import bcrypt
import os
import shamir
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_partial_password(password, min_parts_required, 
                              work_factor,
                              salt_length=16):
    """Construct a shared secret using a password"""
    plen = len(password)
    salts = []
    keys = []
    ivs = []
    for i in range(plen):
        salts.append(os.urandom(salt_length))
        keys.append(bcrypt.kdf(password=password[i].encode('utf-8'),
                              salt=salts[i],
                              desired_key_bytes=32,
                              rounds=work_factor))
        ivs.append(os.urandom(16))
    secret, shares = shamir.make_random_shares(minimum=min_parts_required,
                                       shares=plen)
    encrypted = []
    for (x, y), key, iv in zip(shares, keys, ivs):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key),
                        modes.CBC(iv),
                        backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(y.to_bytes(32, byteorder="little")) + encryptor.finalize()
        encrypted.append(ct)
    output = []
    for salt, iv, ct in zip(salts, ivs, encrypted):
        output.append({'salt': salt, 'iv': iv, 'ct': ct[:16]})
    secret = base64.urlsafe_b64encode(secret.to_bytes(16, "little"))
    print(secret)
    hashed_secret = bcrypt.hashpw(secret, bcrypt.gensalt())
    return output, hashed_secret


def test_partial_password(password, p, hashed_secret, work_factor):
    """Check whether the characters supplied are correct for the password"""
    shares = []
    for k,v in password.items():
        key = bcrypt.kdf(password=v.encode('utf-8'),
                        salt=p[k]['salt'],
                        desired_key_bytes=32,
                        rounds=work_factor)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key),
                        modes.CBC(p[k]['iv']),
                        backend=backend)
        decryptor = cipher.decryptor()
        ct = p[k]['ct'] + (0).to_bytes(16, 'little')
        y = decryptor.update(ct) + decryptor.finalize()
        y = int.from_bytes(y[:16], byteorder='little')
        shares.append((k+1, y))

    secret = shamir.recover_secret(shares)
    secret = base64.urlsafe_b64encode(secret.to_bytes(16, "little"))
    if bcrypt.checkpw(secret, hashed_secret):
        return True
    else:
        return False



if __name__ == '__main__':
    print('Generating secret and shares')
    output, hashed_secret = generate_partial_password('password',
                          min_parts_required=3,
                          work_factor=50)
    print("Output:", output)
    print("Hashed secret:", hashed_secret)
    print('Attempting to check supplied passwords')
    start = time.time()
    result = test_partial_password({0:'p',1:'a',2:'s'}, output,
                      hashed_secret, work_factor=50)
    print("Run time is", time.time() - start, "s")
    print("Result is", result, "with correct password")
    start = time.time()
    result = test_partial_password({0:'p',1:'a',2:'t'}, output,
                      hashed_secret, work_factor=50)
    print("Run time is", time.time() - start, "s")
    print("Result is", result, "with incorrect password")
