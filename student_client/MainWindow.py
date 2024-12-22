import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from GenerateCertificateRequestWindow import GenerateCertificateRequest
from functions import (
    upload_certificate,
    sign_file,
    encrypt_file,
    upload_inst_certificate,
    decrypt_file,
    verify_file,
)
import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)


from certificates.Certificate import load_certificate_from_path
from cryptography.x509.oid import NameOID


class MainWindow:
    def __init__(self, root):
        self.name = "-"
        self.matricle = "-"
        self.institute = "-"

        self.allowed_file_types = "*.pdf;*.docx;*.xls;*.ppt;*.txt;*.zip;*.rar;*.7z"

        self.root = root
        self.root.title("Student-Manager")
        self.root.geometry("450x635")
        self.root.configure(bg="#f0f8ff")

        # Title Label
        title_label = tk.Label(
            root,
            text="Student-Manager",
            font=("Arial", 16, "bold"),
            bg="#f0f8ff",
            fg="#333",
        )
        title_label.pack(pady=10)

        # Frame for form
        self.data_frame = tk.Frame(root, bg="#f0f8ff")

        tk.Label(
            self.data_frame,
            text="Name:",
            bg="#f0f8ff",
            anchor="w",
            font=("Arial", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")
        self.name_label = tk.Label(
            self.data_frame,
            text="-",
            bg="#f0f8ff",
            anchor="w",
        )
        self.name_label.grid(row=0, column=1, sticky="w")

        tk.Label(
            self.data_frame,
            text="Matrikelnummer:",
            bg="#f0f8ff",
            anchor="w",
            font=("Arial", 10, "bold"),
        ).grid(row=1, column=0, sticky="w")
        self.matricle_label = tk.Label(
            self.data_frame,
            text="-",
            bg="#f0f8ff",
            anchor="w",
        )
        self.matricle_label.grid(row=1, column=1, sticky="w")

        tk.Label(
            self.data_frame,
            text="Institut:",
            bg="#f0f8ff",
            anchor="w",
            font=("Arial", 10, "bold"),
        ).grid(row=2, column=0, sticky="w")
        self.institute_label = tk.Label(
            self.data_frame,
            text="-",
            bg="#f0f8ff",
            anchor="w",
        )
        self.institute_label.grid(row=2, column=1, sticky="w")

        self.data_frame.pack(pady=10, padx=20)

        self.button_main_frame = tk.Frame(root, bg="#f0f8ff")
        self.button_main_frame.pack(pady=10)

        tk.Button(
            self.button_main_frame,
            text="Datei signieren",
            command=self.call_sign_file,
            bg="#2196f3",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=0, column=0, padx=10, pady=5)

        tk.Button(
            self.button_main_frame,
            text="Datei verschlüsseln",
            command=lambda: self.call_encrypt_file(use_inst_cert=True),
            bg="#2196f3",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=1, column=0, padx=10, pady=5)

        tk.Button(
            self.button_main_frame,
            text="Datei entschlüsseln",
            command=self.call_decrypt_file,
            bg="#2196f3",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=2, column=0, padx=10, pady=5)

        tk.Button(
            self.button_main_frame,
            text="Dateisignatur prüfen",
            command=lambda: self.call_verify_file(check_with_inst=False),
            bg="#2196f3",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=3, column=0, padx=10, pady=5)

        self.button_second_frame = tk.Frame(root, bg="#f0f8ff")
        self.button_second_frame.pack(pady=10)

        tk.Button(
            self.button_second_frame,
            text="Dateisignatur prüfen (Institut)",
            command=lambda: self.call_verify_file(check_with_inst=True),
            bg="#ff6666",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=0, column=0, padx=10, pady=5)

        tk.Button(
            self.button_second_frame,
            text="Datei verschlüsseln (Institut)",
            command=lambda: self.call_encrypt_file(use_inst_cert=False),
            bg="#ff6666",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=1, column=0, padx=10, pady=5)

        self.button_third_frame = tk.Frame(root, bg="#f0f8ff")
        self.button_third_frame.pack(pady=10)

        tk.Button(
            self.button_third_frame,
            text="Zertifikat-Anfrage generieren",
            command=self.open_generateWindow,
            bg="#424242",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=0, column=0, padx=10, pady=5)

        tk.Button(
            self.button_third_frame,
            text="Zertifikat hochladen",
            command=self.call_upload_certificate,
            bg="#424242",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=1, column=0, padx=10, pady=5)

        tk.Button(
            self.button_third_frame,
            text="Institut Zertifikat hochladen",
            command=self.call_upload_inst_certificate,
            bg="#424242",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=2, column=0, padx=10, pady=5)

    def call_upload_certificate(self):
        upload_certificate()

    def call_upload_inst_certificate(self):
        upload_inst_certificate()

    def open_generateWindow(self):
        gen_cert = tk.Tk()
        app = GenerateCertificateRequest(gen_cert)
        gen_cert.mainloop()
        pass

    def call_sign_file(self):
        if self.name == "-" or self.matricle == "-":
            messagebox.showerror(
                title="Fehler", message="Bitte laden Sie zuerst Ihr Zertifikat hoch!"
            )
            return

        open_path = filedialog.askopenfilename(
            filetypes=[("Ausgewählte Dateien", self.allowed_file_types)],
            title="Hochladen",
        )

        if open_path:
            suffix = f"{self.name.replace(' ', '-').lower()}_{self.matricle}"

            sign_file(open_path, suffix)

    def call_encrypt_file(self, use_inst_cert=True):
        open_path = filedialog.askopenfilename(
            filetypes=[("Ausgewählte Dateien", self.allowed_file_types)],
            title="Hochladen",
        )

        if open_path:
            encrypt_file(open_path, use_inst_cert)

    def call_verify_file(self, check_with_inst):
        open_path = filedialog.askopenfilename(
            filetypes=[("Ausgewählte Dateien", self.allowed_file_types)],
            title="Hochladen",
        )

        if open_path:
            verify_file(open_path, check_with_inst)

    def call_decrypt_file(self):
        open_path = filedialog.askopenfilename(
            filetypes=[("Veschlüsselte Dateien", "*.enc")],
            title="Hochladen",
        )

        if open_path:
            suffix = f"{self.name.replace(' ', '-').lower()}_{self.matricle}"

            decrypt_file(open_path, suffix)
        pass

    def update_loop(self):

        def loop(self):
            self.update_user_data()

            self.root.after(
                500, loop, self
            )  # Schedule the update function to run every 1000 milliseconds (1 second)

        loop(self)  # Start the update process

    def update_user_data(self):

        student_cert_path = os.path.join(script_dir, "data", "cert.cert")

        if os.path.exists(student_cert_path):

            cert = load_certificate_from_path(student_cert_path)

            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value
            common_name = common_name.split("_")
            self.name = common_name[0].replace("-", " ")
            self.matricle = common_name[1]

        else:
            self.name = "-"
            self.matricle = "-"

        inst_cert_path = os.path.join(script_dir, "data", "inst_cert.cert")

        if os.path.exists(inst_cert_path):

            try:
                cert = load_certificate_from_path(inst_cert_path)
                self.institute = cert.subject.get_attributes_for_oid(
                    NameOID.ORGANIZATION_NAME
                )[0].value

            except:
                self.institute = "-"

        else:
            self.institute = "-"

        self.name_label["text"] = self.name
        self.matricle_label["text"] = self.matricle
        self.institute_label["text"] = self.institute
