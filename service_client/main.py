import os
import sys
from flask import Flask, request, render_template
import ssl

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from functions import generate_certificate

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")


@app.route("/upload_request", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        file = request.files["file"]
        if file:
            cert_bytes = generate_certificate(file.read())
            response = app.response_class(
                response=cert_bytes,
                status=200,
                mimetype="application/x-x509-ca-cert",
                headers={
                    "Content-Disposition": "attachment; filename=certificate.crt",
                },
            )
            return response
    return render_template("upload_request.html")


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
