import ssl
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_server_cert(hostname, port):
    conn = ssl.create_connection((hostname, port))
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sock = context.wrap_socket(conn, server_hostname=hostname)
    cert = sock.getpeercert(True)
    cert = ssl.DER_cert_to_PEM_cert(cert)
    return cert

def main():
    if len(sys.argv) < 2:
        print("[*] Usage: {} Ip [Port]".format(sys.argv[0]))
        sys.exit(1)
    host = sys.argv[1]
    if len(sys.argv) == 3:
        port = sys.argv[2]
    else:
        port = 636
    try:
        cert = get_server_cert(host,int(port))
        cert_decoded = x509.load_pem_x509_certificate(cert.encode("utf-8"), default_backend())
        print("[+] Serial Number: {}".format(cert_decoded.serial_number))
    except Exception as e:
        print("[!] Get serialnumber error: {}".format(e))


if __name__ == "__main__":
    main()

