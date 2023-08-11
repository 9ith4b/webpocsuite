from abc import ABC, abstractmethod
import base64, random, string
from utils import AesEncrypt
import subprocess


class Payload(ABC):
    @abstractmethod
    def generate(self):
        pass

def randstr(length):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

class JspPayload(Payload):
    def generate(self, cmd, bin="cmd.exe", output='payload.bin'):
        if bin == "cmd.exe":
            cmd = f'java -cp asm-9.0.jar;. com.txws.CMD "{bin}" "{cmd}" "{output}"'
        else:
            cmd = f'java -cp asm-9.0.jar:. com.txws.CMD "{bin}" "{cmd}" "{output}"'

        try:
            subprocess.check_call(cmd, shell=True)
        except Exception as e:
            raise e

        with open(f"{output}", 'rb') as f:
            payload = f.read()
        payload = AesEncrypt(b'sky', payload)
        return base64.b64encode(payload)
    
    
if __name__ == '__main__':
    print(randstr(10))
