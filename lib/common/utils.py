import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def _pad(s):
    try:
        return pad(s, AES.block_size, style='pkcs7')
    except Exception:
        return None
      
def AesDecrypt(key, data):
    key = hashlib.md5(key).hexdigest()[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB, use_aesni=True)
    dec = cipher.decrypt(data)
    return dec

def AesEncrypt(key, data):
    key = hashlib.md5(key).hexdigest()[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB, use_aesni=True)
    data = _pad(data)
    return cipher.encrypt(data)

def md5(data):
    return hashlib.md5(data).hexdigest()

def md5hash16(data):
    return hashlib.md5(data).hexdigest()[:16]

