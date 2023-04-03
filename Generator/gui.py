import tkinter as tk
from tkinter import ttk
from datetime import date

from Crypto import Keypair, write_json_to_qrcode

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

def start_gui(keypair: Keypair):
    root = tk.Tk()
    app = App(keypair, master=root)
    app.mainloop()