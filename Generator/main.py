import argparse
from typing import TypedDict

from Gui import start_gui
from Crypto import Keypair, read_json_from_file, write_json_to_file, write_json_to_qrcode


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

def run_gui(command: Command):
    keypair = Keypair(command["keypairs_file"])
    keypair.read_from_json()
    start_gui(keypair)

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