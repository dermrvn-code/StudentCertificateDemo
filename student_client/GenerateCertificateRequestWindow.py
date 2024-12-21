from tkinter import messagebox, filedialog
import tkinter as tk
from functions import generate_certificate_request


class GenerateCertificateRequest:
    def __init__(self, root):
        self.root = root
        self.root.title("Student Certificate Generator")
        self.root.geometry("300x220")
        self.root.configure(bg="#f0f8ff")

        # Title Label
        title_label = tk.Label(
            root,
            text="Anfrage generieren...",
            font=("Arial", 16, "bold"),
            bg="#f0f8ff",
            fg="#333",
        )
        title_label.pack(pady=10)

        # Frame for form
        form_frame = tk.Frame(root, bg="#f0f8ff")
        form_frame.pack(pady=10, padx=20)

        tk.Label(form_frame, text="Name:", bg="#f0f8ff", anchor="w").grid(
            row=0, column=0, sticky="w"
        )
        self.name_entry = tk.Entry(form_frame, width=30)
        self.name_entry.grid(row=0, column=1, pady=5)

        tk.Label(form_frame, text="Matrikelnr:", bg="#f0f8ff", anchor="w").grid(
            row=1, column=0, sticky="w"
        )
        self.matricle_entry = tk.Entry(form_frame, width=30)
        self.matricle_entry.grid(row=1, column=1, pady=5)

        # Button Frame
        button_frame = tk.Frame(root, bg="#f0f8ff")
        button_frame.pack(pady=10)

        generate_button = tk.Button(
            button_frame,
            text="Anfrage generieren",
            command=self.request_certificate,
            bg="#2196f3",
            fg="white",
            font=("Arial", 10, "bold"),
            relief="flat",
        )
        generate_button.grid(row=0, column=0, padx=10)

        # Status Label
        self.status_label = tk.Label(
            root,
            text="",
            bg="#f0f8ff",
            fg="#333",
            font=("Arial", 10),
        )
        self.status_label.pack(pady=10)

        # Data storage
        self.private_key = None
        self.public_key = None
        self.certificate = None

    def request_certificate(self):

        # Get student information
        name = self.name_entry.get()
        matriclenr = int(self.matricle_entry.get())

        if not name or not matriclenr:
            messagebox.showwarning("Warnung", "Bitte alle Felder ausfüllen!")
            return

        request_bytes = generate_certificate_request(name, matriclenr)

        if request_bytes:
            name = name.replace(" ", "-")
            save_path = filedialog.asksaveasfilename(
                initialfile=f"{name}_{matriclenr}.csr",
                defaultextension=".csr",
                filetypes=[("Zertifikatanfrage", "*.csr"), ("Alle Dateien", "*.*")],
                title="Anfrage speichern",
            )
            messagebox.showinfo(title="Erfolgreich", message="Anfrage gespeichert")
            self.root.destroy()
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(request_bytes)
        else:
            messagebox.showerror(
                title="Error", message="Fehler beim Erstellen der Anfrage!"
            )
