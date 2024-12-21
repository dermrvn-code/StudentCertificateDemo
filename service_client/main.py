import os
import sys
from flask import Flask, redirect, request, render_template
import ssl

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from functions import generate_certificate
from certificates.Certificate import load_certificate_bytes_from_path

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")


@app.route("/upload_file", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        file = request.files["file"]
        matriculation_number = request.form["matriculation_number"]
        file_name = request.form["file_name"]
        if file:
            upload_folder = os.path.join(script_dir, "uploads")
            os.makedirs(upload_folder, exist_ok=True)
            new_file_name = f"{matriculation_number}_{file_name}"
            file_ext = os.path.splitext(file.filename)[1]
            new_file_name += file_ext
            file_path = os.path.join(upload_folder, new_file_name)
            file.save(file_path)
            return redirect("../")
    return render_template("upload_file.html")


@app.route("/upload_request", methods=["GET", "POST"])
def upload_request():
    if request.method == "POST":
        file = request.files["file"]
        if file:
            cert_bytes = generate_certificate(file.read())
            response = app.response_class(
                response=cert_bytes,
                status=200,
                headers={
                    "Content-Disposition": "attachment; filename=certificate.crt",
                },
            )
            return response
    return render_template("upload_request.html")


@app.route("/download_cert", methods=["GET"])
def download_cert():
    cert_bytes = load_certificate_bytes_from_path(
        os.path.join(script_dir, "certs", "cert_campusofficehshl.crt")
    )
    print(cert_bytes)
    response = app.response_class(
        response=cert_bytes,
        status=200,
        headers={
            "Content-Disposition": "attachment; filename=InstituteCertificate.crt",
        },
    )
    return response


if __name__ == "__main__":
    # SSL context for HTTPS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    folder = os.path.join(script_dir, "certs")
    context.load_cert_chain(
        certfile=os.path.join(folder, "cert_campusofficehshl.crt"),
        keyfile=os.path.join(folder, "cert_private_campusofficehshl.key"),
        password=open(os.path.join(folder, "passphrase_campusofficehshl.txt")).read(),
    )
    app.run(host="localhost", port=443, ssl_context=context)
