'''https://techtutorialsx.com/2018/04/09/python-pycrypto-using-aes-128-in-ecb-mode/'''
"""pip install pycryptodome"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time


def filter_mac(mac):
    a = "".join(str(mac).split(":"))
    a = a.upper()
    return a


def set_data(mac, constant):
    mac = filter_mac(mac)
    constant = filter_mac(constant)

    n = 6
    splitmac = [mac[i:i + n] for i in range(0, len(mac), n)]

    oui, eui48l = splitmac[0], splitmac[1]

    return str(eui48l + constant + oui)


def gid(mac):
    mac = filter_mac(mac)
    return mac[4:]


def encrypt(key, message, BLOCK_SIZE=128):
    cipher = AES.new(str(key).encode("utf8"), AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode("utf8"), BLOCK_SIZE))
    return ciphertext


def decrypt(key, ciphertext, BLOCK_SIZE=128):
    decipher = AES.new(str(key).encode("utf8"), AES.MODE_ECB)
    msg_dec = decipher.decrypt(ciphertext)
    msg_dec = (unpad(msg_dec, BLOCK_SIZE)).decode("utf8")
    return msg_dec


def foo():
    with open('MK.txt', 'r') as f:
        mk = f.read()
        f.close()
        print("masterkey:", mk)

    with open('k.txt', 'r') as f:
        constant = f.read()
        f.close()
        print("contant:", constant, '\n')

    with open('input.txt', 'r') as f:
        for line in f:
            print("MAC:", line.rstrip())
            data = set_data(line, constant)
            print("data in:", data)
            encryptedmsg = encrypt(mk, data).hex()
            print(encryptedmsg, '\n')

    '''a = 'ab:cd:ef:01:23:45'
    k = '5b:32:56:4b:4f:4f:48:2d:45:5d'
    print(set_data(a,k))'''


def main():
    with open('MK.txt', 'r') as f:
        mk = int(f.read(),16)
        f.close()
        print("masterkey:", mk, type(mk))

    with open('k.txt', 'r') as f:
        constant = f.read()
        f.close()
        print("contant:", constant,type(constant))

    with open('input.txt','r') as f:
        line = f.readline().rstrip()
        print("MAC:",line)
        data = set_data(line, constant)
        print('data:', data, 'type:', type(data),'\n')
        hexdata = int(data,16)
        print('hexdata:', hex(hexdata), 'type:', type(hexdata),'\n')
        '''hexdata = hex(hexdata)
        print('hexdata:', hexdata,'type:', type(hexdata),'\n')'''

    encrypt(mk,hexdata)




if __name__ == "__main__":
    main()
