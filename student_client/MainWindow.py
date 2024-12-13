import tkinter as tk
from GenerateCertificateWindow import GenerateCertificate
from shared_util.Config import Config


class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Student-Manager")
        self.root.geometry("400x350")
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
            text="E-Mail:",
            bg="#f0f8ff",
            anchor="w",
            font=("Arial", 10, "bold"),
        ).grid(row=2, column=0, sticky="w")
        self.mail_label = tk.Label(
            self.data_frame,
            text="-",
            bg="#f0f8ff",
            anchor="w",
        )
        self.mail_label.grid(row=2, column=1, sticky="w")

        self.button_frame = tk.Frame(root, bg="#f0f8ff")
        self.button_frame.pack(pady=10)

        tk.Button(
            self.button_frame,
            text="Zertifikat generieren",
            command=self.open_generateWindow,
            bg="#2196f3",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=0, column=0, padx=10, pady=10)

        sign_button = tk.Button(
            self.button_frame,
            text="Dokument signieren",
            command=self.open_signWindow,
            bg="#2196f3",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=1, column=0, padx=10, pady=10)

        sign_button = tk.Button(
            self.button_frame,
            text="Dokument verschlüsseln",
            command=self.open_encryptWindow,
            bg="#2196f3",
            fg="white",
            font=("Arial", 14, "bold"),
            relief="flat",
        ).grid(row=2, column=0, padx=10, pady=10)

    def open_generateWindow(self):
        gen_cert = tk.Tk()
        app = GenerateCertificate(gen_cert)
        gen_cert.mainloop()
        pass

    def open_signWindow(self):
        pass

    def open_encryptWindow(self):
        pass

    def update_loop(self):

        def loop(self):
            self.update_user_data()

            self.root.after(
                500, loop, self
            )  # Schedule the update function to run every 1000 milliseconds (1 second)

        loop(self)  # Start the update process

    def update_user_data(self):
        name = Config.get("USERDATA", "name", "", folder="student_client")
        email = Config.get("USERDATA", "email", "", folder="student_client")
        matricle = Config.get("USERDATA", "matriclenr", "", folder="student_client")

        if "" in (name, email, matricle):
            return

        self.name_label["text"] = name
        self.mail_label["text"] = email
        self.matricle_label["text"] = matricle

        self.button_frame.pack_forget()
        self.data_frame.pack(padx=10, pady=10)
        self.button_frame.pack(padx=10, pady=10)
