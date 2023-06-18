import string
import secrets
import bcrypt

def check(a, b):
    return secrets.compare_digest(a, b)

def generatPass():
    alphabet = string.ascii_letters + string.digits + ".!$@"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(10))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in ".!$@" for c in password)):
            return password

def hashPass(password : str):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)

    return salt, hashed

if __name__ == '__main__':

    print(generatPass())
    print(secrets.token_urlsafe(32))
    print(secrets.token_hex(32))

    a = generatPass()
    b = generatPass()
    print(check(a, b))
    print(check(a, a))
    print(secrets.randbits(100*8))


    password = b"Test"
    salt, hash = hashPass(password)
    print(password)
    print(hash)
    print(salt)

