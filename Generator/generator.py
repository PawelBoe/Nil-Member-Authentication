import argparse
import json
import base64

import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def writeJsonToQrCode(data: str, file_path: str):
    print(f'Writing to qr code file "{file_path}".')
    img = qrcode.make(data)
    img.save(file_path)

def writeJsonToFile(data: str, file_path):
    print(f'Writing to json file "{file_path}".')
    with open(file_path, "w") as file:
        file.write(json.dumps(data))

def readJsonFromFile(file_path: str):
    print(f'Reading json from file "{file_path}".')
    with open(file_path, "r") as file:
        return json.load(file)

class Keypairs:
    def __init__(self):
        self.keypairs = {}

    def readFromJson(self, file_path: str):
        print(f'Reading keypairs.')
        try:
            self.keypairs = readJsonFromFile(file_path)
        except IOError:
            self.keypairs = {}
            print(f'"{file_path}" does not exist, using empty Keypairs.')

    def writeToJson(self, file_path: str):
        print(f'Serializing keypairs.')
        writeJsonToFile(self.keypairs, file_path)
        
    def sign(self, keyname: str, private_key_pass: str, data: str):
        print(f'Signing data "{data}" with key "{keyname}".')
        result ={
            'data': data,
            'keyname': None,
            'b64_signature': None
        }

        if keyname not in self.keypairs:
            print(f'Abort: keypair with name "{keyname}" does not exists.')
        else:
            try:
                private_key = serialization.load_pem_private_key(
                    self.keypairs[keyname]['private_key'].encode(),
                    password=private_key_pass.encode()
                )

                signature = private_key.sign(
                    data.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                result['b64_signature'] = base64.b64encode(signature).decode()
                result['keyname'] = keyname

            except Exception as e:
                print(f'Abort: private key decoding failed": {e}')
            
        return result
    
    def verify(self, signed_data):
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

                public_key.verify(
                    signature,
                    data.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                print(f'Verification sucessful.')
                return True
            except:
                print(f'Abort: verification failed.')
            
        return False

    def generateNewKeypair(self, keyname: str, private_key_pass: str):
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


def main():
    parser = argparse.ArgumentParser(prog='Nil StudentInnenkeller Key and Certificate Generator', description='Generate Keypairs and Certificates for Nil Membership Cards', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--keypairs', help='The file where you store generated keypairs.', default='./keypairs.json')
    subparsers = parser.add_subparsers(help='Mode Options', dest='command')
    subparsers.required = True

    parser_keygen = subparsers.add_parser('keygen', help='Generate a new Keypair')
    parser_keygen.add_argument('-n', '--name', help='New Keypair Name', required=True)
    parser_keygen.add_argument('-p', '--password', help='New Keypair Password', required=True)

    parser_keygen = subparsers.add_parser('signJson', help='Sign data and save as json file')
    parser_keygen.add_argument('-n', '--name', help='Keypair name to sign data with', required=True)
    parser_keygen.add_argument('-p', "--password", help='Password for keypair', required=True)
    parser_keygen.add_argument('-m', "--message", help='Message to be signed', required=True)
    parser_keygen.add_argument('-o', "--output", help='Output json file for signed data', required=True)

    parser_keygen = subparsers.add_parser('signQrCode', help='Sign data and save as qr code png file')
    parser_keygen.add_argument('-n', '--name', help='Keypair Name to sign data with', required=True)
    parser_keygen.add_argument('-p', "--password", help='Password for keypair', required=True)
    parser_keygen.add_argument('-m', "--message", help='Message to be signed', required=True)
    parser_keygen.add_argument('-o', "--output", help='Output png file for qr code with signed data', required=True)

    parser_keygen = subparsers.add_parser('verifyJson', help='Verify saved and signed message in json format')
    parser_keygen.add_argument('-i', "--input", help='Input json file with signed data', required=True)

    args = parser.parse_args()
    config = vars(args)

    keypairs = Keypairs()
    keypairs.readFromJson(config['keypairs'])

    if config['command'] == 'keygen':
        keypairs.generateNewKeypair(config['name'], config['password'])
        keypairs.writeToJson(config['keypairs'])

    elif config['command'] == 'signJson':
        signed_data = keypairs.sign(config['name'], config['password'], config["message"])
        writeJsonToFile(signed_data, config['output'])

    elif config['command'] == 'signQrCode':
        signed_data = keypairs.sign(config['name'], config['password'], config["message"])
        writeJsonToQrCode(signed_data, config['output'])

    elif config['command'] == 'verifyJson':
        signed_data = readJsonFromFile(config['input'])
        keypairs.verify(signed_data)

if __name__ == '__main__':
    main()