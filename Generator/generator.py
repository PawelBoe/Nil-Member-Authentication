import argparse
from datetime import date
import json
import base64
from typing import TypedDict
import tkinter as tk
from tkinter import ttk

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


def parse_args():
    parser = argparse.ArgumentParser(prog='Nil StudentInnenkeller Key and Certificate Generator', description='Generate Keypairs and Certificates for Nil Membership Cards', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--keypairs_file', help='The file where you store generated keypairs.', default='./keydata.json')
    subparsers = parser.add_subparsers(help='Mode Options', dest='command')
    subparsers.required = True

    parser_keygen = subparsers.add_parser('keygen', help='Generate a new Keypair')
    parser_keygen.add_argument('-p', '--password', help='New Keypair Password', required=True)

    parser_keygen = subparsers.add_parser('signJson', help='Sign data and save as json file')
    parser_keygen.add_argument('-p', "--password", help='Password for keypair', required=True)
    parser_keygen.add_argument('-m', "--message", help='Message to be signed', required=True)
    parser_keygen.add_argument('-o', "--output_file", help='Output json file for signed data', required=True)

    parser_keygen = subparsers.add_parser('signQrCode', help='Sign data and save as qr code png file')
    parser_keygen.add_argument('-p', "--password", help='Password for keypair', required=True)
    parser_keygen.add_argument('-m', "--message", help='Message to be signed', required=True)
    parser_keygen.add_argument('-o', "--output_file", help='Output png file for qr code with signed data', required=True)

    parser_keygen = subparsers.add_parser('verifyJson', help='Verify saved and signed message in json format')
    parser_keygen.add_argument('-i', "--input_file", help='Input json file with signed data', required=True)

    parser_keygen = subparsers.add_parser('gui', help='Open a graphical user interface to generate keypairs and qr codes')

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
    keypair = Keypair(command["keypairs_file"])
    keypair.read_from_json()
    keypair.generate_new_keypair(command['password'])
    keypair.write_to_json()

def run_signJson(command: SignJsonCommand):
    keypair = Keypair(command["keypairs_file"])
    keypair.read_from_json()
    signed_data = keypair.sign(command['password'], command["message"])
    write_json_to_file(signed_data, command['output_file'])

def run_signQrCode(command: SignQrCodeCommand):
    keypair = Keypair(command["keypairs_file"])
    keypair.read_from_json()
    signed_data = keypair.sign(command['password'], command["message"])
    write_json_to_qrcode(signed_data, command['output_file'])

def run_verifyJson(command: VerifyJsonCommand):
    keypair = Keypair(command["keypairs_file"])
    keypair.read_from_json()
    signed_data = read_json_from_file(command['input_file'])
    keypair.verify(signed_data)

class App(tk.Frame):
    def __init__(self, keypair: Keypair, master=None):
        super().__init__(master)
        self.pack()
        self.keypair = keypair
        self.create_widgets()

    def create_widgets(self):
        self.winfo_toplevel().title("Nil Zertifikat Generator")
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        # First tab
        self.tab1 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text="Zertifikat erstellen")

        self.name_label = ttk.Label(self.tab1, text="Name")
        self.name_label.pack(side="top")

        self.name_entry = ttk.Entry(self.tab1)
        self.name_entry.pack(side="top")

        self.status_label = ttk.Label(self.tab1, text="Status")
        self.status_label.pack(side="top")

        self.status_entry = ttk.Entry(self.tab1)
        self.status_entry.pack(side="top")

        self.comment_label = ttk.Label(self.tab1, text="Komentar")
        self.comment_label.pack(side="top")

        self.comment_entry = ttk.Entry(self.tab1)
        self.comment_entry.pack(side="top")

        self.personal_info_submit_button = ttk.Button(self.tab1, text="Zertifikat erstellen", command=self.submit_certificate)
        self.personal_info_submit_button.pack(side="top", pady=10)

        self.password_label = ttk.Label(self.tab1, text="Passwort für installierten Schlüssel")
        self.password_label.pack(side="top")

        self.password_entry = ttk.Entry(self.tab1)
        self.password_entry.pack(side="top")

        self.canvas = tk.Canvas(self.tab1)
        self.canvas.pack(side="top")

        # Second tab
        self.tab2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab2, text="Schlüssel")

        self.public_key_text = tk.Label(self.tab2, text=self.keypair.keydata["public_key"])
        self.public_key_text.pack()

        self.private_key_text = tk.Label(self.tab2, text=self.keypair.keydata["private_key"])
        self.private_key_text.pack()

        self.info_text = tk.Label(self.tab2, text="Der installierte Schlüssel kann aus Sicherheitsgründen nur manuell über die Kommandozeilen-Version dieses Programs geändert werden.")
        self.info_text.pack()

    def submit_certificate(self):
        name = self.name_entry.get()
        status = self.status_entry.get()
        comment = self.comment_entry.get()
        creation_date = date.today()
        password = self.password_entry.get()

        data = f"{{name: {name}, status: {status}, comment: {comment}, creation_date: {creation_date}}}"
        filename = f"QrCode_{name}_{status}_{comment}_{creation_date}.png".replace(" ", "")

        signed_data = self.keypair.sign(password, data)
        write_json_to_qrcode(signed_data, filename)


def run_gui(command: Command):
    keypair = Keypair(command["keypairs_file"])
    keypair.read_from_json()

    root = tk.Tk()
    app = App(keypair, master=root)
    app.mainloop()

def run_command(args: dict):
    {
        "keygen": lambda: run_keygen(KeygenCommand(**args)),
        "signJson": lambda: run_signJson(SignJsonCommand(**args)),
        "signQrCode": lambda: run_signQrCode(SignQrCodeCommand(**args)),
        "verifyJson": lambda: run_verifyJson(VerifyJsonCommand(**args)),
        "gui": lambda: run_gui(Command(**args)),
    }.get(args.get("command", ""), lambda: None)()


def main():
    args = vars(parse_args())
    run_command(args)


if __name__ == '__main__':
    main()