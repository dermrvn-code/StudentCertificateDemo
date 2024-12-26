<!-- @format -->

<h1 align="center">Demonstrator for Student Certificates</h1>

<p align="center">
  <a href="https://python.org/downloads/release/python-3123/">
  <a href="https://python.org/downloads/release/python-3123/">
    <img src="https://img.shields.io/badge/-Python_3.12.3-3776AB?style=for-the-badge&logo=python&logoColor=white">
  </a>
  <img src="https://img.shields.io/badge/Status-Tech_Demo-red?style=for-the-badge">
</p>

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Installation

To install the Student Certificate Demo, follow these steps:

1. Clone the repository:

   ```shell
   git clone https://github.com/dermrvn-code/StudentCertificateDemo
   ```

2. Install the required dependencies:

   ```shell
   py install.py
   ```

Now everything is successfully installed and the Student Certificate Demo can be used.

## Usage

To use the Student Certificate Demo, follow these steps:

1. Start the environment:

   In every new terminal session, you need to start the environment by running the following command:

   ```shell
   start_env.bat
   ```

2. Generate all certificates:

   ```shell
   py service_client\generate_certificate.py
   ```

3. Start the student-client:

   ```shell
   py student_client\main.py
   ```

4. Start the service-client:

   ```shell
   py service_client\main.py
   ```

5. Generate the certificate request in the student-client

6. Upload the certificate request in the service-client and download the certificates

7. Upload both the personal and the public institution certificate in the student-client

8. Have fun with the Student Certificate Demo!

[(Back to top)](#table-of-contents)
