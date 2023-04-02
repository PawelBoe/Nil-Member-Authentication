import argparse
import json
import base64
from typing import TypedDict

import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Keypair(TypedDict):
    private_key: str
    public_key: str

class SignedData(TypedDict):
    keyname: str
    data: str
    b64_signature: str


def write_json_to_qrcode(data: SignedData, file_path: str):
    print(f'Writing to qr code file "{file_path}".')
    img = qrcode.make(data)
    img.save(file_path)

def write_json_to_file(data: SignedData | dict[str, Keypair], file_path: str):
    print(f'Writing to json file "{file_path}".')
    with open(file_path, "w") as file:
        file.write(json.dumps(data))

def read_json_from_file(file_path: str):
    print(f'Reading json from file "{file_path}".')
    with open(file_path, "r") as file:
        return json.load(file)

class Keypairs:
    def __init__(self):
        self.keypairs: dict[str, Keypair] = {}

    def read_from_json(self, file_path: str):
        print(f'Reading keypairs.')
        try:
            self.keypairs = read_json_from_file(file_path)
        except IOError:
            self.keypairs = {}
            print(f'"{file_path}" does not exist, using empty Keypairs.')

    def write_to_json(self, file_path: str):
        print(f'Serializing keypairs.')
        write_json_to_file(self.keypairs, file_path)
        
    def sign(self, keyname: str, private_key_pass: str, data: str) -> SignedData:
        print(f'Signing data "{data}" with key "{keyname}".')
        result : SignedData = {
            'data': data,
            'keyname': "",
            'b64_signature': ""
        }

        if keyname not in self.keypairs:
            print(f'Abort: keypair with name "{keyname}" does not exists.')
        else:
            try:
                private_key = serialization.load_pem_private_key(
                    self.keypairs[keyname]['private_key'].encode(),
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
                result['keyname'] = keyname

            except Exception as e:
                print(f'Abort: private key decoding failed": {e}')
            
        return result
    

    def verify(self, signed_data: SignedData) -> bool:
        keyname = signed_data["keyname"]
        data = signed_data["data"]
        b64_signature = signed_data["b64_signature"]

        print(f'Verifying data "{data}" with key "{keyname}".')

        if keyname not in self.keypairs:
            print(f'Abort: keypair with name "{keyname}" does not exists.')
        else:
            try:
                public_key = serialization.load_pem_public_key(self.keypairs[keyname]['public_key'].encode())
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

    def generate_new_keypair(self, keyname: str, private_key_pass: str):
        print(f'Generating new Keypair "{keyname}"')

        if keyname in self.keypairs:
            print(f'Abort: keypair with name "{keyname}" already exists.')
        else:
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

            self.keypairs[keyname] = {
                'private_key': encrypted_pem_private_key.decode(),
                'public_key': pem_public_key.decode()
            }


def parse_args():
    parser = argparse.ArgumentParser(prog='Nil StudentInnenkeller Key and Certificate Generator', description='Generate Keypairs and Certificates for Nil Membership Cards', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--keypairs_file', help='The file where you store generated keypairs.', default='./keypairs.json')
    subparsers = parser.add_subparsers(help='Mode Options', dest='command')
    subparsers.required = True

    parser_keygen = subparsers.add_parser('keygen', help='Generate a new Keypair')
    parser_keygen.add_argument('-n', '--keyname', help='New Keypair Name', required=True)
    parser_keygen.add_argument('-p', '--password', help='New Keypair Password', required=True)

    parser_keygen = subparsers.add_parser('signJson', help='Sign data and save as json file')
    parser_keygen.add_argument('-n', '--keyname', help='Keypair name to sign data with', required=True)
    parser_keygen.add_argument('-p', "--password", help='Password for keypair', required=True)
    parser_keygen.add_argument('-m', "--message", help='Message to be signed', required=True)
    parser_keygen.add_argument('-o', "--output_file", help='Output json file for signed data', required=True)

    parser_keygen = subparsers.add_parser('signQrCode', help='Sign data and save as qr code png file')
    parser_keygen.add_argument('-n', '--keyname', help='Keypair Name to sign data with', required=True)
    parser_keygen.add_argument('-p', "--password", help='Password for keypair', required=True)
    parser_keygen.add_argument('-m', "--message", help='Message to be signed', required=True)
    parser_keygen.add_argument('-o', "--output_file", help='Output png file for qr code with signed data', required=True)

    parser_keygen = subparsers.add_parser('verifyJson', help='Verify saved and signed message in json format')
    parser_keygen.add_argument('-i', "--input_file", help='Input json file with signed data', required=True)

    args = parser.parse_args()
    return args


class Command(TypedDict):
    keypairs_file: str

class KeygenCommand(Command):
    keyname: str
    password: str

class SignJsonCommand(Command):
    keyname: str
    password: str
    message: str
    output_file: str

class SignQrCodeCommand(Command):
    keyname: str
    password: str
    message: str
    output_file: str

class VerifyJsonCommand(Command):
    input_file: str


def run_keygen(command: KeygenCommand):
    keypairs = Keypairs()
    keypairs.read_from_json(command["keypairs_file"])
    keypairs.generate_new_keypair(command["keyname"], command['password'])
    keypairs.write_to_json(command["keypairs_file"])

def run_signJson(command: SignJsonCommand):
    keypairs = Keypairs()
    keypairs.read_from_json(command["keypairs_file"])
    signed_data = keypairs.sign(command['keyname'], command['password'], command["message"])
    write_json_to_file(signed_data, command['output_file'])

def run_signQrCode(command: SignQrCodeCommand):
    keypairs = Keypairs()
    keypairs.read_from_json(command["keypairs_file"])
    signed_data = keypairs.sign(command['keyname'], command['password'], command["message"])
    write_json_to_qrcode(signed_data, command['output_file'])

def run_verifyJson(command: VerifyJsonCommand):
    keypairs = Keypairs()
    keypairs.read_from_json(command["keypairs_file"])
    signed_data = read_json_from_file(command['input_file'])
    keypairs.verify(signed_data)

def run_command(args: dict):
    {
        "keygen": lambda: run_keygen(KeygenCommand(**args)),
        "signJson": lambda: run_signJson(SignJsonCommand(**args)),
        "signQrCode": lambda: run_signQrCode(SignQrCodeCommand(**args)),
        "verifyJson": lambda: run_verifyJson(VerifyJsonCommand(**args)),
    }.get(args.get("command", ""), lambda: None)()


def main():
    args = vars(parse_args())
    run_command(args)


if __name__ == '__main__':
    main()