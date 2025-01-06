import os

import shutil


def clear_certificates():
    folder = [
        "service_client/certs",
        "service_client/student_certs",
        "service_client/uploads",
        "student_client/data",
    ]
    script_dir = os.path.dirname(os.path.abspath(__file__))

    for path in folder:
        path = os.path.join(script_dir, path)
        shutil.rmtree(path)


if __name__ == "__main__":
    clear_certificates()
