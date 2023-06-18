import copy
from Crypto.Cipher import AES
from Crypto.Cipher import DES

def LFSR(sirC : str, sirS : str):
    if len(sirC) != len(sirS):
        return

    L = len(sirC)
    sirC = list(sirC)
    sirS = list(sirS)
    sirSCopy = copy.copy(sirS)
    sirRes = ""

    while True:
        print(sirS)
        sirRes += sirS[-1]
        newS1 = -1

        for i in range(len(sirS)):
            if sirC[i] == "1":
                if newS1 == -1:
                    newS1 = int(sirS[i])
                else:
                    newS1 ^= int(sirS[i])

        if newS1 == -1:
            newS1 = 0

        sirS = [str(newS1)] + sirS[:-1]


        if sirS == sirSCopy:
            break
    print(sirRes)


if __name__ == '__main__':
    LFSR("0110", "1101")

    key = b'O cheie oarecare'
    data = b'testtesttesttesttesttesttesttesttesttesttesttest'
    cyper = AES.new(key, AES.MODE_ECB)
    val = cyper.encrypt(data)
    print(val)
    val = cyper.encrypt(data + data)
    print(val)
    # # ex 3-------------------------------
    # key1 = b'\x10\x00\x00\x00\x00\x00\x00\x00'
    # key2 = b'\x20\x00\x00\x00\x00\x00\x00\x00'
    #
    # cipher1 = DES.new(key1, DES.MODE_ECB)
    # cipher2 = DES.new(key2, DES.MODE_ECB)
    #
    # plaintext = "Provocare MitM!!"
    # ciphertext = cipher2.encrypt(cipher1.encrypt(plaintext))
    #
    # print(ciphertext)
