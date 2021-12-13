import datetime
import logging
import os
import pathlib
import socket
import sys
from multiprocessing import Process

import requests
import uvicorn
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import CertificateSigningRequest, Certificate
from cryptography.x509.oid import NameOID
from fastapi import FastAPI

# Define the log format
log_format = u'[%(asctime)s] %(levelname)-8s %(name)-12s %(lineno)d %(funcName)s - %(message)s'
log_date_format = '%Y-%m-%d:%H:%M:%S'

# show all messages below in order of seriousness
log_level = logging.DEBUG  # shows all
# log_level = logging.INFO  # shows info and below
# log_level = logging.WARNING
# log_level = logging.ERROR
# log_level = logging.CRITICAL

logging.basicConfig(
    # Define logging level
    level=log_level,
    # Define the date format
    datefmt=log_date_format,
    # Declare the object we created to format the log messages
    format=log_format,
    # Force this log handler to take over the others that may have been declared in other modules
    # see: https://github.com/python/cpython/blob/3.8/Lib/logging/__init__.py#L1912
    force=True,
    # Declare handlers
    handlers=[
        # logging.FileHandler(config.logfile, encoding='UTF-8'),
        logging.StreamHandler(sys.stdout),
    ]
)

log = logging.getLogger(__name__)


class CertTools:

    def __init__(self, location: pathlib.Path | None, common_name: str = 'localhost', prefix: str = 'dev'):

        self.common_name = common_name
        self.prefix = prefix

        if location is None:
            self.location = pathlib.Path.cwd() / prefix
        else:
            self.location = location / prefix

        if self.location.exists() is False:
            pathlib.Path.mkdir(self.location, parents=True)
            log.info(f'Making the folder to store the certs in: {self.location}')

        self.cert: x509.Certificate | None = None
        self.private_key: ec.EllipticCurvePrivateKey | None = None
        self.public_key: ec.EllipticCurvePublicKey | None = None
        self.cert_file: pathlib.Path = self.location / f'{self.common_name}_cert.pem'
        self.private_key_file: pathlib.Path = self.location / f'{self.common_name}_private_key.pem'
        self.public_key_file: pathlib.Path = self.location / f'{self.common_name}_public_key.pem'
        self.csr: x509.CertificateSigningRequest | None = None
        self.csr_file: pathlib.Path = self.location / f'{self.common_name}_csr.pem'
        self.cert_p12_file = self.location / f'{common_name}_cert.p12'

    def _hash(self) -> hashes:
        return hashes.SHA512()

    def create_private_key(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        log.info(f'Private key created: name: {ec.SECP256R1.name} - size: {ec.SECP256R1.key_size}')
        return None

    def save_private_key(self):
        """
        Save the private key, is there isn't one create it first
        save the data in a file without encryption
        """
        if self.private_key is None:
            log.critical(f'No private key exist for common name: {self.common_name}')
            sys.exit(-1)

        if self.private_key_file.exists():
            log.warning(f'Overwriting existing private key file: {self.private_key_file}')

        with open(self.private_key_file, "wb") as f:
            f.write(self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.NoEncryption()))
        log.info(f'Private key saved to file: {self.private_key_file}')
        return self.private_key_file

    def save_csr(self):
        """ save csr to file .p12 extension """
        if self.csr is None:
            log.critical(f'No csr found for common name: {self.common_name}')
            sys.exit(-1)

        if self.csr_file.exists():
            log.warning(f'Overwriting existing certificate signing request file: {self.csr_file}')

        with open(self.csr_file, 'wb') as f:
            f.write(self.csr.public_bytes(encoding=serialization.Encoding.PEM))

        log.info(f'csr saved to file: {self.csr_file}')
        return self.csr_file

    def create_self_signed_cert(self, cert_age: int = 10):
        """
        create a self signed cert, certificate age in days
        """

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"UK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Province"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])

        self.cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=cert_age)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.DNSName(u"127.0.0.1"),
                x509.DNSName(socket.getfqdn()),
            ]
            ),
            critical=False,
            # Sign our certificate with our private key
        ).sign(self.private_key, hashes.SHA256())

        return None

    def create_root_cert(self, cert_age=100):
        """
        Creating a root certificate, just a self signed cert with a longer validity age (in days)
        Must use other instance of the CertTool2 for each layer and Cert in the hierarchy of the PKI infrastructure
        """
        b = x509.CertificateBuilder()
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"UK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"West Mid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nowhere"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organisation"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])

        self.cert = b.serial_number(x509.random_serial_number()) \
            .issuer_name(name) \
            .subject_name(name) \
            .public_key(self.private_key.public_key()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=cert_age)) \
            .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), True
        ) \
            .sign(self.private_key, self._hash(), default_backend())
        return None

    def save_cert(self):
        """ Write our certificate out to disk. """

        if self.cert_file.exists():
            log.warning(f'Overwriting existing cert file: {self.cert_file}')

        with open(self.cert_file, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
        log.info(f'saved cert: {self.common_name} to file: {self.cert_file}')
        return self.cert_file

    def create_csr(self) -> None:
        """
        Create a certificate signing request that will to be need to be sent to the CA to be signed
        """
        log.info(f'CSR for: {self.common_name}')
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"UK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"West Mid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nowhere"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organisation"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])
        b = x509.CertificateSigningRequestBuilder()
        req = b.subject_name(name).sign(self.private_key, self._hash(), default_backend())
        self.csr = req
        return None

    def sign_certificate(self, csr):
        """
        Authority signs the csr from the leaf with their private key issuing the certificate
        path_len=0 means this cert can only sign itself, not other certs
        """
        # for full list of oid see:
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772812(v=ws.10)?redirectedfrom=MSDN
        log.info(f'{self.cert.subject} is signing the certificate for {csr.subject} csr')

        b = x509.CertificateBuilder()
        b = b.subject_name(csr.subject) \
            .issuer_name(self.cert.subject) \
            .public_key(csr.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        b = b.add_extension(x509.SubjectAlternativeName(
            [
                x509.DNSName(u'localhost'),  # apparently must have a san matching the common name
                x509.DNSName(u'cryptography.io'),
                x509.DNSName(u'parrot.cryptography.io'),
                x509.DNSName(socket.getfqdn()),
            ]
        ), critical=False)
        cert = b.sign(self.private_key, self._hash(), default_backend())

        return cert

    def save_cert_as_p12(self,
                         p12_name: str = 'my_client',
                         name: str = 'my_client',
                         ):
        """
        PKCS12 is a binary format described in RFC 7292. It can contain certificates, keys, and more.
        PKCS12 files commonly have a pfx or p12 file suffix.
        https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/?highlight=p12
        >> https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/?highlight=p12#cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates
        https://blog.mozilla.org/security/2020/04/14/expanding-client-certificates-in-firefox-75/
        https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.KeySerializationEncryption
        PKCS12 is a binary format described in RFC 7292. It can contain certificates, keys, and more.
        PKCS12 files commonly have a pfx or p12 file suffix.
        openssl pkcs12 -info -in keyStore.p12

        encryption_algorithm:
        Union[RSAPrivateKey, EllipticCurvePrivateKey,
              DHPrivateKey, DSAPrivateKey, NoEncryption],
        """
        if self.private_key is None:
            log.critical(f'Unable to create a p12 file for: {self.common_name} - {name}, no private key')
            sys.exit(-1)

        if self.cert is None:
            log.critical(f'Unable to create a p12 file for: {self.common_name} - {name}, no cert')
            sys.exit(-1)

        p12_name_bytes = bytes(p12_name, 'UTF-8')
        password = b'1234'
        encryption_algorithm = serialization.BestAvailableEncryption(password)
        # encryption_algorithm = serialization.NoEncryption() # did not work

        log.info(f'Client cert in p12 file has password: {password}')

        cas = None  # cas: Union[None, List[x509.Certificate]] = None,

        with open(self.cert_p12_file, "wb") as f:
            f.write(
                pkcs12.serialize_key_and_certificates(
                    p12_name_bytes,
                    self.private_key,
                    self.cert,
                    cas,
                    encryption_algorithm))
            log.info(f'Cert pkcs12 format: {self.cert_p12_file}')

        return self.cert_p12_file


app = FastAPI()


@app.get("/")
async def read_main():
    return {"message": "Hello World - bingo - bang"}


def tls_server(cert_file: pathlib.Path, private_key_file: pathlib.Path):
    host = 'localhost'
    port = 5001
    log.info(f'Running TLS server: {host}:{port}')
    uvicorn.run(app,
                host=host,
                port=port,
                log_level="debug",
                ssl_keyfile=private_key_file,
                ssl_certfile=cert_file,
                )


def mtls_server(cert_file: pathlib.Path,
                private_key_file: pathlib.Path,
                ca_cert_file: pathlib.Path):
    host = 'localhost'
    port = 5002
    log.info(f'Running MTLS server: {host}:{port}')
    uvicorn.run(app,
                host=host,
                port=port,
                log_level="debug",
                ssl_keyfile=private_key_file,
                ssl_certfile=cert_file,
                ssl_ca_certs=ca_cert_file,
                ssl_cert_reqs=2,
                )


def tls_web_server_process(cert_path, private_key_path):
    log.info(f'Starting TLS server process: {cert_path}')
    p = Process(target=tls_server, args=(cert_path, private_key_path,), daemon=True)
    p.start()
    log.info(f'TLS Server process started with cert: {cert_path}')
    yield p
    p.kill()  # Cleanup after test
    log.info('TLS Server process stopped')
    return


def mtls_web_server_process(cert_path, private_key_path, ca_cert_file):
    log.info(f'Starting MTLS server process: {cert_path}')
    p = Process(target=mtls_server, args=(cert_path, private_key_path, ca_cert_file,), daemon=True)
    p.start()
    log.info(f'MTLS Server process started with cert: {cert_path}')
    yield p
    p.kill()  # Cleanup after test
    log.info('MTLS Server process stopped')
    return


def run_a_server(host='localhost', port=5000):
    log.info(f'Starting server: http://{host}:{port} with no TLS')
    uvicorn.run(app,
                host=host,
                port=port,
                log_level="debug",
                )


def test_self_signed_server(tmp_path):
    log.info('creating certs')
    common_name = 'localhost'
    cert_tool = CertTools(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool.create_private_key()
    cert_tool.create_self_signed_cert(100)
    cert_tool.save_cert()
    cert_tool.save_private_key()
    assert cert_tool.save_cert().exists()
    assert cert_tool.save_private_key().exists()
    log.info('running web server with certs')
    web_server_process_handle = tls_web_server_process(cert_tool.cert_file, cert_tool.private_key_file)
    next(web_server_process_handle)  # use next to use the yielded iterator
    log.info('testing the web server and certs')
    r = requests.get('https://localhost:5001', verify=cert_tool.cert_file, )
    assert r.status_code == 200
    assert r.json() == {'message': 'Hello World - bingo - bang'}
    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


def test_ca_signed_server(tmp_path):
    log.info('creating ca signed certs')

    cert_tool_root = CertTools(location=tmp_path, common_name='root cert', prefix='pytest')
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()
    assert cert_tool_root.save_cert().exists()

    common_name = 'localhost'
    cert_tool_leaf = CertTools(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool_leaf.create_private_key()

    cert_tool_leaf.create_csr()
    assert isinstance(cert_tool_leaf.csr, CertificateSigningRequest)
    assert str(cert_tool_leaf.csr.subject) == f'<Name(C=UK,ST=West Mid,L=Nowhere,O=My Organisation,CN={common_name})>'

    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)
    assert isinstance(cert_tool_leaf.cert, Certificate)
    assert str(cert_tool_leaf.cert.subject) == f'<Name(C=UK,ST=West Mid,L=Nowhere,O=My Organisation,CN={common_name})>'
    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()
    assert cert_tool_leaf.save_cert().exists()
    assert cert_tool_leaf.save_private_key().exists()
    log.info('running web server with certs')
    web_server_process_handle = tls_web_server_process(cert_tool_leaf.cert_file, cert_tool_leaf.private_key_file)
    next(web_server_process_handle)  # use next to use the yielded iterator
    log.info('testing the web server and certs')
    r = requests.get('https://localhost:5001', verify=cert_tool_root.cert_file, )
    assert r.status_code == 200
    assert r.json() == {'message': 'Hello World - bingo - bang'}
    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


def test_ca_signed_server_with_mtls(tmp_path):
    log.info('creating ca signed certs with mtls client')
    # root ca
    cert_tool_root = CertTools(location=tmp_path, common_name='root cert', prefix='pytest')
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()
    assert cert_tool_root.save_cert().exists()
    # leaf server cert
    common_name = 'localhost'
    cert_tool_leaf = CertTools(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool_leaf.create_private_key()
    cert_tool_leaf.create_csr()
    assert isinstance(cert_tool_leaf.csr, CertificateSigningRequest)
    assert str(cert_tool_leaf.csr.subject) == f'<Name(C=UK,ST=West Mid,L=Nowhere,O=My Organisation,CN={common_name})>'
    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)
    assert isinstance(cert_tool_leaf.cert, Certificate)
    assert str(cert_tool_leaf.cert.subject) == f'<Name(C=UK,ST=West Mid,L=Nowhere,O=My Organisation,CN={common_name})>'
    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()
    assert cert_tool_leaf.save_cert().exists()
    assert cert_tool_leaf.save_private_key().exists()

    # create client cert
    common_name = 'client_cert'
    cert_tool_client = CertTools(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool_client.create_private_key()

    cert_tool_client.create_csr()
    assert isinstance(cert_tool_client.csr, CertificateSigningRequest)
    assert str(cert_tool_client.csr.subject) == f'<Name(C=UK,ST=West Mid,L=Nowhere,O=My Organisation,CN={common_name})>'

    cert_tool_client.cert = cert_tool_root.sign_certificate(cert_tool_client.csr)
    assert isinstance(cert_tool_client.cert, Certificate)
    assert str(cert_tool_client.cert.subject) == \
           f'<Name(C=UK,ST=West Mid,L=Nowhere,O=My Organisation,CN={common_name})>'
    cert_tool_client.save_cert()
    cert_tool_client.save_private_key()
    assert cert_tool_client.save_cert().exists()
    assert cert_tool_client.save_private_key().exists()

    log.info('running web server with certs')
    web_server_process_handle = mtls_web_server_process(cert_tool_leaf.cert_file,
                                                        cert_tool_leaf.private_key_file,
                                                        cert_tool_root.cert_file)
    next(web_server_process_handle)  # use next to use the yielded iterator
    log.info('testing the web server and certs, with mutual TLS client cert')
    r = requests.get('https://localhost:5002',
                     verify=cert_tool_root.cert_file,
                     # cert - tuple order must match client_cert then client_key
                     cert=(cert_tool_client.cert_file, cert_tool_client.private_key_file))
    assert r.status_code == 200
    assert r.json() == {'message': 'Hello World - bingo - bang'}
    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


def ca_certs_tls_recipe() -> None:
    log.info('creating ca signed certs')
    cert_location = pathlib.Path(os.getcwd()) / 'certs'
    prefix = 'dev'
    cert_tool_root = CertTools(location=cert_location, common_name='root cert', prefix=prefix)
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()

    common_name = 'localhost'
    cert_tool_leaf = CertTools(location=cert_location, common_name=common_name, prefix=prefix)
    cert_tool_leaf.create_private_key()

    cert_tool_leaf.create_csr()

    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)

    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()

    log.info('running web server with certs')
    web_server_process_handle = tls_web_server_process(cert_tool_leaf.cert_file, cert_tool_leaf.private_key_file)
    next(web_server_process_handle)  # use next to use the yielded iterator

    url = 'https://localhost:5001'
    log.info(f'testing the web server and certs: open url: {url}')
    log.info(f'.. import ca cert into your web browser as trusted: {cert_location}')

    r = requests.get(url, verify=cert_tool_root.cert_file, )
    if r.json() == {'message': 'Hello World - bingo - bang'}:
        log.info('local test passed')
    else:
        log.error('local test failed')

    input("\n\nPress Enter to continue...\n\n")

    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


def ca_certs_mtls_recipe() -> None:
    log.info('creating ca signed certs with mtls client')
    cert_location = pathlib.Path(os.getcwd()) / 'certs'
    prefix = 'dev_mtls'

    # root ca
    cert_tool_root = CertTools(location=cert_location, common_name='root cert', prefix=prefix)
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()
    assert cert_tool_root.save_cert().exists()
    # leaf server cert
    common_name = 'localhost'
    cert_tool_leaf = CertTools(location=cert_location, common_name=common_name, prefix=prefix)
    cert_tool_leaf.create_private_key()
    cert_tool_leaf.create_csr()

    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)

    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()

    # create client cert
    common_name = 'client_cert'
    cert_tool_client = CertTools(location=cert_location, common_name=common_name, prefix=prefix)
    cert_tool_client.create_private_key()

    cert_tool_client.create_csr()

    cert_tool_client.cert = cert_tool_root.sign_certificate(cert_tool_client.csr)

    cert_tool_client.save_cert()
    cert_tool_client.save_private_key()
    cert_tool_client.save_cert_as_p12()

    log.info('running web server with certs')
    web_server_process_handle = mtls_web_server_process(cert_tool_leaf.cert_file,
                                                        cert_tool_leaf.private_key_file,
                                                        cert_tool_root.cert_file)
    next(web_server_process_handle)  # use next to use the yielded iterator
    url = 'https://localhost:5002'
    log.info(f'testing the web server and certs, with mutual TLS client cert: open {url}')
    log.info(f'load the client cert with password 1234: {cert_tool_client.cert_file} into the browser ')
    log.info(f'load the ca cert into the browsers list of trusted root certs: {cert_tool_root.cert_file}')
    r = requests.get(url,
                     verify=cert_tool_root.cert_file,
                     # cert - tuple order must match client_cert then client_key
                     cert=(cert_tool_client.cert_file, cert_tool_client.private_key_file))

    if r.json() == {'message': 'Hello World - bingo - bang'}:
        log.info('local test passed')
    else:
        log.error('local test failed')

    input("\n\nPress Enter to continue...\n\n")

    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


if __name__ == "__main__":
    ca_certs_tls_recipe()
    # ca_certs_mtls_recipe()
