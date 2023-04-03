import json
import base64
from typing import TypedDict

import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Keydata(TypedDict):
    private_key: str
    public_key: str

class SignedData(TypedDict):
    data: str
    b64_signature: str


def write_json_to_qrcode(data: SignedData, file_path: str):
    print(f'Writing to qr code file "{file_path}".')
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.ERROR_CORRECT_M,
    )
    qr.add_data(data)
    img = qr.make_image(fill_color="red", back_color="black")
    img.save(file_path)

def write_json_to_file(data: SignedData | Keydata, file_path: str):
    print(f'Writing to json file "{file_path}".')
    with open(file_path, "w") as file:
        file.write(json.dumps(data))

def read_json_from_file(file_path: str):
    print(f'Reading json from file "{file_path}".')
    with open(file_path, "r") as file:
        return json.load(file)

class Keypair:
    def __init__(self, keypair_file_path):
        self.keypair_file_path = keypair_file_path
        self.keydata: Keydata = {
            "private_key": "",
            "public_key": "",
        }

    def read_from_json(self):
        print(f'Reading keypairs.')
        try:
            self.keydata = read_json_from_file(self.keypair_file_path)
        except IOError:
            print(f'"{self.keypair_file_path}" does not exist, using previous Keydata.')

    def write_to_json(self):
        print(f'Serializing keypair.')
        write_json_to_file(self.keydata, self.keypair_file_path)
        
    def sign(self, private_key_pass: str, data: str) -> SignedData:
        print(f'Signing data "{data}" with key".')
        result : SignedData = {
            'data': data,
            'b64_signature': ""
        }
        try:
            private_key = serialization.load_pem_private_key(
                self.keydata['private_key'].encode(),
                password=private_key_pass.encode()
            )

            signature = private_key.sign( # type: ignore
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ), # type: ignore
                hashes.SHA256() # type: ignore
            )

            result['b64_signature'] = base64.b64encode(signature).decode()

        except Exception as e:
            print(f'Abort: private key decoding failed": {e}')
            
        return result
    

    def verify(self, signed_data: SignedData) -> bool:
        data = signed_data["data"]
        b64_signature = signed_data["b64_signature"]

        print(f'Verifying data "{data}" with key.')

        try:
            public_key = serialization.load_pem_public_key(self.keydata['public_key'].encode())
            signature = base64.b64decode(b64_signature)

            public_key.verify( # type: ignore
                signature,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ), # type: ignore
                hashes.SHA256() # type: ignore
            )

            print(f'Verification sucessful.')
            return True
        except:
            print(f'Abort: verification failed.')
            
        return False

    def generate_new_keypair(self, private_key_pass: str):
        print(f'Generating new Keypair')

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        encrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass.encode())
        )

        pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.keydata = {
            'private_key': encrypted_pem_private_key.decode(),
            'public_key': pem_public_key.decode()
        }