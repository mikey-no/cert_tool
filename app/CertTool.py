import base64
import datetime
import json
import logging
import pathlib
import shutil
import socket
import sys
from multiprocessing import Process
from types import NoneType
from typing import List

import requests
import uvicorn
from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key
from cryptography.x509 import CertificateSigningRequest, Certificate
from cryptography.x509.oid import NameOID
from fastapi import FastAPI

sys.path.append(str(pathlib.Path().cwd()))

log = logging.getLogger(__name__)

proxies = {
    "http": None,
    "https": None,
}


class CertTool:
    def __init__(
        self,
        location: pathlib.Path | None = pathlib.Path.cwd(),
        common_name: str | None = "localhost",
        prefix: str | None = "dev",
        use_private_key_encryption: bool = False,
        private_key_encryption_password: bytes | str | None = None,
    ):

        if common_name is None:
            self.common_name = (
                socket.getfqdn()
            )  # may be replaced by calling self.set_common_name
        else:
            self.set_common_name(common_name)

        if prefix is None:
            self.set_prefix("default")
        else:
            self.set_prefix(prefix)

        # TODO: remove self.use_private_key_encryption replace with a check for password
        #  is not len 0
        self.use_private_key_encryption = use_private_key_encryption

        if isinstance(private_key_encryption_password, str):
            self.private_key_encryption_password = bytes(
                private_key_encryption_password, encoding="utf-8"
            )
        else:
            self.private_key_encryption_password = private_key_encryption_password

        if self.use_private_key_encryption:
            # log.debug("Private key will be encrypted")
            pass
        else:
            log.info("Private key will not be encrypted")

        self.location: pathlib.Path | None = (
            None  # wait to set this until set_location is called
        )
        self.set_location(location)

        self.cert: x509.Certificate | None = None
        self.private_key: ec.EllipticCurvePrivateKey | None = None
        self.public_key: ec.EllipticCurvePublicKey | None = None
        self.csr: x509.CertificateSigningRequest | None = None

        self._set_file_names()

        # OID Named things - details for the subject and issuer of certificates
        self.COUNTRY_NAME = "UK"
        self.STATE_OR_PROVINCE_NAME = "West Mid"
        self.LOCALITY_NAME = "Nowhere"
        self.ORGANIZATION_NAME = "My Organisation"
        self.ORGANIZATIONAL_UNIT_NAME = "My Organisation Unit"
        self.cert_tool_info: dict = {}

    def set_common_name(self, common_name: str):
        """must set the common_name, prefix and location for a valid CertTool operation"""
        self.common_name = common_name.replace(" ", "_").replace(".", "-")
        # log.debug('set file names')
        # self._set_file_names()

    def set_prefix(self, prefix: str):
        """must set the common_name, prefix and location for a valid CertTool operation"""
        prefix.replace(" ", "_")
        self.prefix = prefix

    def set_location(self, location: pathlib.Path | str | None = None):
        """must set the common_name, prefix and location for a valid CertTool operation"""

        if self.prefix is None:
            log.critical(f"Setting the location before the prefix is set")
            sys.exit(-1)

        if isinstance(location, str):
            log.debug(f"location supplied: {location}")
            self.location = pathlib.Path(location)
        elif isinstance(location, pathlib.Path):
            log.debug(f"location supplied: {location}")
            self.location = location
        elif isinstance(location, type(None)):
            self.location = pathlib.Path.cwd() / "certs" / self.prefix
            log.debug(f"no location supplied using the default: {self.location}")
        else:
            log.critical(f"Invalid location type: {type(location)}")
            sys.exit(-1)

        if self.location.exists():
            log.info(f"Location found, re-using: {self.location} ~ {self.prefix}")
        else:
            try:
                pathlib.Path.mkdir(self.location, parents=True)
                log.info(f"Making the folder to store the certs in: {self.location}")
            except Exception as e:
                log.critical(
                    f"Trying to create the cert tool files in an invalid location: {location} -  {e}"
                )
                sys.exit(-1)

    def _set_file_names(self):
        """Helper method to allow the file names to be set each time a
        value like, location, common name or prefix is provided
        It would not be expected to work until value have been set for all, and why
        the exception is ignored.
        """
        if self.prefix is None or self.common_name is None or self.location is None:
            log.warning("Unable to set the file names")
            return None
        try:
            # log.debug("Setting file names")
            self.cert_file: pathlib.Path = (
                self.location / f"{self.common_name}_cert.pem"
            )
            self.private_key_file: pathlib.Path = (
                self.location / f"{self.common_name}_private_key.pem"
            )
            self.public_key_file: pathlib.Path = (
                self.location / f"{self.common_name}_public_key.pem"
            )
            self.csr_file: pathlib.Path = self.location / f"{self.common_name}_csr.pem"
            self.cert_p12_file = self.location / f"{self.common_name}_cert.p12"
            self.cert_tool_info_file: pathlib.Path = (
                self.location / f"{self.common_name}_cert_tool_info.json"
            )
        except Exception as e:
            pass

    def _hash(self) -> hashes:
        return hashes.SHA512()

    def _key_type(self):
        return ec.SECP256R1()

    def create_private_key(self):
        """
        create a private key just in memory, but if one is not already on the disk, try load that first
        if a private key is created then also create the corresponding public key
        """
        if self.load_private_key(password=self.private_key_encryption_password):
            log.info(
                f"Not created a new private key: {self.common_name}, have one in a file"
            )
        else:
            self.private_key = ec.generate_private_key(
                self._key_type(), default_backend()
            )
            self.public_key = self.private_key.public_key()
            log.info(
                f"Private key created for common name: {self.common_name}, ec type: {ec.SECP256R1.name}"
            )
        return None

    def save_private_key(self, password: str | bytes | None = None):
        """
        Save the private key
        if with a password it then uses the cryptography modules creators best available encryption method
        if the encryption changes then you would not be able to decrypt your private key
        """
        if self.private_key is None:
            log.critical(f"No private key exist for common name: {self.common_name}")
            sys.exit(-1)

        if self.use_private_key_encryption and password is None:
            log.critical(
                f"No password supplied for private key with common name: {self.common_name}"
            )
            sys.exit(-1)

        if self.private_key_file.exists():
            backup_file = (
                self.private_key_file.parent / f"{self.private_key_file.name}.bak"
            )
            log.info(
                f"Making a backup of private key: {self.common_name} in:  {backup_file}"
            )
            shutil.copy(self.private_key_file, backup_file)

        if self.use_private_key_encryption:
            with open(self.private_key_file, "wb") as f:
                if isinstance(password, str):
                    password_bytes = bytes(password, encoding="utf-8")
                else:
                    password_bytes = password
                encryption_algorithm = serialization.BestAvailableEncryption(
                    password=password_bytes
                )
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=encryption_algorithm,
                    )
                )
        else:
            with open(self.private_key_file, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

        log.info(
            f"Private key: {self.common_name} saved to file: {self.private_key_file}"
        )
        return self.private_key_file

    def load_private_key(self, password: str | bytes | None = None) -> bool:
        """load private key from file then return True else False"""
        if self.private_key_file.exists():
            if self.use_private_key_encryption:
                if self.private_key_encryption_password is None:
                    if password is None:
                        password = input(
                            f"Please provide the password to open private key with common name: "
                            f"{self.common_name}: "
                        )
                else:
                    password = self.private_key_encryption_password
                if isinstance(password, str):
                    password_bytes = bytes(password, encoding="utf-8")
                else:
                    password_bytes = password
                with open(self.private_key_file, "rb") as f:
                    self.private_key = load_pem_private_key(
                        f.read(), password=password_bytes
                    )
            else:
                with open(self.private_key_file, "rb") as f:
                    self.private_key = load_pem_private_key(f.read(), password=None)
            log.info(f"Private key loaded from file: {self.private_key_file}")
            if isinstance(self.private_key, EllipticCurvePrivateKey) is False:
                log.critical(
                    f"Private key for: {self.common_name}, was invalid: {type(self.private_key)}"
                )
                sys.exit(-1)
        else:
            return False
        return True

    def save_csr(self):
        """save csr to file"""
        if self.csr is None:
            log.critical(f"No csr found for common name: {self.common_name}")
            sys.exit(-1)

        if self.csr_file.exists():
            log.warning(
                f"Overwriting existing certificate signing request file: {self.csr_file}"
            )

        with open(self.csr_file, "wb") as f:
            f.write(self.csr.public_bytes(encoding=serialization.Encoding.PEM))

        log.info(f"csr saved to file: {self.csr_file}")
        return self.csr_file

    def load_csr(self):
        """load csr from file"""
        if self.csr_file.exists() is False:
            log.error(f"csr file not found: {self.csr_file}")
            return None

        if self.csr is not None:
            log.warning("csr already loaded, overwriting")

        with open(self.csr_file, "rb") as f:
            data = f.read()
            data_pem = x509.load_pem_x509_csr(data)
            if isinstance(data_pem, x509.CertificateSigningRequest):
                self.csr = data_pem
                log.info(
                    f"CSR is loaded, signature is valid: {self.csr.is_signature_valid}"
                )
            else:
                log.error(f"CSR loaded from file is not valid: {self.csr_file}")
                return None
        return self.csr

    def _get_subject_(self):
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.COUNTRY_NAME),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, self.STATE_OR_PROVINCE_NAME
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.LOCALITY_NAME),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ORGANIZATION_NAME),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, self.ORGANIZATIONAL_UNIT_NAME
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ]
        )

    def create_self_signed_cert(self, cert_age: int = 10):
        """
        Create a self signed cert, certificate age in days (default 10 days)
        """

        subject = issuer = self._get_subject_()

        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=cert_age)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName("127.0.0.1"),
                        x509.DNSName(socket.getfqdn()),
                    ]
                ),
                critical=False,
                # Sign our certificate with our private key
            )
            .sign(self.private_key, hashes.SHA256())
        )

        return None

    def create_root_cert(self, cert_age=100):
        """
        Creating a root certificate, just a self signed cert with a longer validity age (in days)
        Must use other instance of the CertTool2 for each layer and Cert in the hierarchy of the PKI infrastructure
        """
        b = x509.CertificateBuilder()
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.COUNTRY_NAME),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, self.STATE_OR_PROVINCE_NAME
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.LOCALITY_NAME),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ORGANIZATION_NAME),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, self.ORGANIZATIONAL_UNIT_NAME
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ]
        )

        self.cert = (
            b.serial_number(x509.random_serial_number())
            .issuer_name(name)
            .subject_name(name)
            .public_key(self.private_key.public_key())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=cert_age)
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(self.private_key, self._hash(), default_backend())
        )
        return None

    def get_cert_in_pem(self) -> bytes:
        return self.cert.public_bytes(encoding=serialization.Encoding.PEM)

    def save_cert(self):
        """Write our certificate out to disk."""

        if self.cert_file.exists():
            log.warning(f"Overwriting existing cert file: {self.cert_file}")

        with open(self.cert_file, "wb") as f:
            f.write(self.get_cert_in_pem())
        log.info(f"Saved cert: {self.common_name} to file: {self.cert_file}")
        return self.cert_file

    def load_cert(self):
        """Load our certificate from disk."""

        if self.cert_file.exists() is False:
            log.error(f"Cert file not found: {self.cert_file}")
            return None

        if self.cert is not None:
            log.warning(f"Overwriting existing cert in memory")

        with open(self.cert_file, "rb") as f:
            data = f.read()
            data_pem = x509.load_pem_x509_certificate(data)
            if isinstance(data_pem, x509.Certificate):
                self.cert = data_pem
            else:
                log.error(f"cert file not valid cert: {type(data)}")
                return None
        log.info(f"Loaded cert from file: {self.cert_file}")

        return self.cert_file

    def create_csr(self) -> None:
        """
        Create a certificate signing request that will to be need to be sent to the CA to be signed
        """
        log.info(f"CSR for: {self.common_name}")
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.COUNTRY_NAME),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, self.STATE_OR_PROVINCE_NAME
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.LOCALITY_NAME),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ORGANIZATION_NAME),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ]
        )
        b = x509.CertificateSigningRequestBuilder()
        req = b.subject_name(name).sign(
            self.private_key, self._hash(), default_backend()
        )
        self.csr = req
        return None

    def make_subject_alternate_name(
        self, csr_common_name: str, name_list: List[str] = None
    ):
        """
        Make a good list of subject alternate names
        when prefix is prod_A or B then do not add the local host name or fqdn name to the san list
        as this signing will be done on the ca host not the leaf host
        add in the common_name too
        """
        out_list = [
            x509.DNSName("localhost"),
            # x509.DNSName("cryptography.io"),
            # x509.DNSName('parrot.cryptography.io'),
            x509.DNSName(str(csr_common_name)),
        ]
        if self.prefix != "prod_A" or self.prefix != "prod_B":
            if socket.getfqdn() is not None:
                out_list.append(x509.DNSName(socket.getfqdn()))
            if socket.gethostname() is not None:
                out_list.append(x509.DNSName(socket.gethostname()))

        if name_list is not None:
            for name in name_list:
                try:
                    out_list.append(x509.DNSName(name))
                except Exception as e:
                    log.error(
                        # TODO: why is this an error when it looks like it worked after?
                        f"Invalid name, not able to add it as a Subject Alternate Name: {e} - {name}"
                    )
        out_list = list(dict.fromkeys(out_list))  # de-duplicate entries
        if x509.DNSName("None") in out_list:
            out_list.remove(x509.DNSName("None"))
        log.info(
            f"{len(out_list)} Subject Alternate Names added to the certificate: {out_list}"
        )
        return out_list

    def sign_certificate(
        self,
        csr: x509.CertificateSigningRequest,
        subject_alternate_name: List[str] | None = None,
    ):
        """
        Authority signs the csr from the leaf with their private key issuing the certificate
        path_len=0 means this cert can only sign itself, not other certs,
        path_len=None, here
        see: https://github.com/python-trio/trustme/blob/master/trustme/__init__.py?#L392
        """
        subject = self._get_subject_()
        # for full list of oid see:
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772812(v=ws.10)?redirectedfrom=MSDN
        log.info(
            f"{subject.rfc4514_string()} is signing the certificate for {csr.subject} csr"
        )

        b = x509.CertificateBuilder()
        b = (
            b.subject_name(csr.subject)
            .issuer_name(subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        )
        b = b.add_extension(
            x509.SubjectAlternativeName(
                self.make_subject_alternate_name(
                    self.get_csr_common_name(csr),
                    subject_alternate_name,
                )
            ),
            critical=False,
        )
        cert = b.sign(self.private_key, self._hash(), default_backend())
        log.info(f"CSR has been signed, cert created with serial: {cert.serial_number}")
        return cert

    def save_cert_as_p12(
        self,
        p12_name: str = "my_client",
        name: str = "my_client",
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
            log.critical(
                f"Unable to create a p12 file for: {self.common_name} - {name}, no private key"
            )
            sys.exit(-1)

        if self.cert is None:
            log.critical(
                f"Unable to create a p12 file for: {self.common_name} - {name}, no cert"
            )
            sys.exit(-1)

        p12_name_bytes = bytes(p12_name, "UTF-8")
        password = b"1234"
        encryption_algorithm = serialization.BestAvailableEncryption(password)
        # encryption_algorithm = serialization.NoEncryption() # did not work

        log.info(f"Client cert in p12 file has password: {password}")

        cas = None  # cas: Union[None, List[x509.Certificate]] = None,

        with open(self.cert_p12_file, "wb") as f:
            f.write(
                pkcs12.serialize_key_and_certificates(
                    p12_name_bytes,
                    self.private_key,
                    self.cert,
                    cas,
                    encryption_algorithm,
                )
            )
            log.info(f"Cert saved in pkcs12 format: {self.cert_p12_file}")

        return self.cert_p12_file

    def cert_info(self) -> dict:
        """Cert info see:
        https://github.com/pyca/cryptography/blob/main/src/cryptography/hazmat/_oid.py#L119-L149
        """
        m = {}

        if hasattr(self.cert, "serial_number"):
            m["serial"] = self.cert.serial_number
        if hasattr(self.cert, "not_valid_after"):
            m["not_after"] = self.cert.not_valid_after
        if hasattr(self.cert, "not_valid_before"):
            m["not_before"] = self.cert.not_valid_before
        if hasattr(self.cert, "fingerprint"):
            m["fingerprint"] = self.cert.fingerprint(self._hash())
        if hasattr(self.cert, "subject"):
            m["subject"] = self.cert.subject
            subject: x509.Name = self.cert.subject
            common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if common_name is not None:
                m["common_name"] = common_name[0].value

            # m["pem_data"] = self.cert.public_bytes(serialization.Encoding.PEM)
            # m["discriminator"] = self.cert.value

            # dig the elements from this object without knowing what might have been stored in it
            # v messy!
            # print(dir(NameOID))
            # leave the private attributes, not digging these attributes our
            for item in dir(NameOID):
                if item.startswith("__"):
                    pass
                if subject.get_attributes_for_oid(getattr(NameOID, item)) is None:
                    pass
                else:
                    thing = subject.get_attributes_for_oid(getattr(NameOID, item))
                    if thing is None or len(thing) < 1:
                        pass
                    else:
                        if isinstance(thing, tuple):
                            m[item.lower()] = thing
                        else:
                            m[item.lower()] = thing[0].value

        try:
            extensions = self.cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            if extensions is not None:
                m_san = []
                for index, item in enumerate(
                    extensions.value.get_values_for_type(x509.DNSName)
                ):
                    m_san.append(item)
                m["subject_alternate_names"] = m_san
            self.cert_tool_info = m
        except Exception as e:
            log.info("No Subject Alternate Name found")
        return m

    def get_csr_common_name(self, csr: x509.CertificateSigningRequest) -> str | None:
        """get the common name from the csr that is being signed"""
        m: str | None = None
        if isinstance(csr, x509.CertificateSigningRequest) is False:
            log.error(f"CSR not found cannot find its common name")
            return None

        if hasattr(csr.subject, "subject"):
            subject: x509.Name = csr.subject
            common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if common_name is not None:
                m = common_name[0].value

        return m

    def save_cert_tool(self) -> None:
        """
        Save the certtool object to a json file
        :return: None
        :rtype: None
        """

        def my_converter(obj):
            def b64(obj) -> str:
                return str(base64.b64encode(obj))

            if isinstance(obj, pathlib.Path):
                return str(obj)
            if isinstance(obj, NoneType):
                return str(NoneType)
            if isinstance(obj, dict):
                return json.dumps(obj, indent=2, default=my_converter)
            if isinstance(obj, EllipticCurvePrivateKey):
                if self.use_private_key_encryption:
                    return b64(
                        obj.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.BestAvailableEncryption(
                                self.private_key_encryption_password
                            ),
                        )
                    )
                else:
                    return b64(
                        obj.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption(),
                        )
                    )
            if isinstance(obj, Certificate):
                return b64(obj.public_bytes(serialization.Encoding.PEM))
            if isinstance(obj, CertificateSigningRequest):
                return b64(obj.public_bytes(serialization.Encoding.PEM))

        log.info(f"Saving certtool instance to a file: {self.cert_tool_info_file}")
        json_obj = json.dumps(self.__dict__, indent=2, default=my_converter)
        log.debug(f"json obj: {json_obj}")
        with open(self.cert_tool_info_file, "w") as f:
            f.write(json_obj)
        return None

    def load_cert_tool(self):
        self.load_private_key()
        self.load_cert()

    def load_common_name_from_csr(self) -> str | None:
        if self.csr is None:
            log.warning("no csr found")
            return None
        if hasattr(self.csr, "subject"):
            subject: x509.Name = self.csr.subject
            common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if common_name is not None:
                self.common_name = common_name[0].value
                log.info(f"common name loaded from csr: {self.common_name}")
                # also need to set the cert_file name correctly with the common name
                self.cert_file = self.location / f"{self.common_name}_cert.pem"
                return self.common_name
        else:
            log.warning("no csr subject found")
        return None


app = FastAPI()


@app.get("/")
async def read_main():
    return {"message": "Hello World - bingo - bang"}


def tls_server(cert_file: pathlib.Path, private_key_file: pathlib.Path):
    host = "localhost"
    port = 5001
    log.info(f"Running TLS server: {host}:{port}")
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="debug",
        ssl_keyfile=private_key_file,
        ssl_certfile=cert_file,
    )


def mtls_server(
    cert_file: pathlib.Path, private_key_file: pathlib.Path, ca_cert_file: pathlib.Path
):
    host = "localhost"
    port = 5002
    log.info(f"Running MTLS server: {host}:{port}")
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="debug",
        ssl_keyfile=private_key_file,
        ssl_certfile=cert_file,
        ssl_ca_certs=ca_cert_file,
        ssl_cert_reqs=2,
    )


def tls_web_server_process(cert_path, private_key_path):
    log.info(f"Starting TLS server process: {cert_path}")
    p = Process(
        target=tls_server,
        args=(
            cert_path,
            private_key_path,
        ),
        daemon=True,
    )
    p.start()
    log.info(f"TLS Server process started with cert: {cert_path}")
    yield p
    p.kill()  # Cleanup after test
    log.info("TLS Server process stopped")
    return


def mtls_web_server_process(cert_path, private_key_path, ca_cert_file):
    log.info(f"Starting MTLS server process: {cert_path}")
    p = Process(
        target=mtls_server,
        args=(
            cert_path,
            private_key_path,
            ca_cert_file,
        ),
        daemon=True,
    )
    p.start()
    log.info(f"MTLS Server process started with cert: {cert_path}")
    yield p
    p.kill()  # Cleanup after test
    log.info("MTLS Server process stopped")
    return


def run_a_server(host="localhost", port=5000):
    log.info(f"Starting server: http://{host}:{port} with no TLS")
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="debug",
    )


def ca_certs_tls_recipe() -> None:
    log.info("Creating ca signed certs for TLS Server and Client...")
    cert_location = pathlib.Path().cwd() / "certs"
    prefix = "dev_tls"
    cert_tool_root = CertTool(
        location=cert_location, common_name="root cert", prefix=prefix
    )
    cert_tool_root.create_private_key()
    cert_tool_root.save_private_key()  # added to test private key life cycle
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()

    common_name = "localhost"
    cert_tool_leaf = CertTool(
        location=cert_location, common_name=common_name, prefix=prefix
    )
    cert_tool_leaf.create_private_key()
    cert_tool_leaf.create_csr()
    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)
    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()

    log.info("running web server with certs")
    web_server_process_handle = tls_web_server_process(
        cert_tool_leaf.cert_file, cert_tool_leaf.private_key_file
    )
    next(web_server_process_handle)  # use next to use the yielded iterator

    url = "https://localhost:5001"
    log.info(f"testing the web server and certs: open url: {url}")
    log.info(f".. import ca cert into your web browser as trusted: {cert_location}")

    r = requests.get(
        url,
        verify=cert_tool_root.cert_file,
        proxies=proxies,
    )
    if r.json() == {"message": "Hello World - bingo - bang"}:
        log.info("local test passed")
    else:
        log.error("local test failed")

    input("\n\nPress Enter to continue...\n\n")

    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


def ca_certs_tls_recipe_private_key_encryption() -> None:
    log.info("Creating ca signed certs for TLS Server and Client (with encryption)...")
    cert_location = pathlib.Path().cwd() / "certs"
    prefix = "dev_tls"
    password = "1234"
    cert_tool_root = CertTool(
        location=cert_location,
        common_name="root cert",
        prefix=prefix,
        use_private_key_encryption=True,
        private_key_encryption_password=password,
    )
    cert_tool_root.create_private_key()
    cert_tool_root.save_private_key(
        password=password
    )  # added to test private key life cycle
    cert_tool_root = None
    cert_tool_root = CertTool(
        location=cert_location,
        common_name="root cert",
        prefix=prefix,
        use_private_key_encryption=True,
    )
    cert_tool_root.load_private_key(password=password)
    cert_tool_root.create_root_cert(10)
    cert_tool_root.save_cert()

    common_name = "localhost"
    cert_tool_leaf = CertTool(
        location=cert_location, common_name=common_name, prefix=prefix
    )
    cert_tool_leaf.create_private_key()

    cert_tool_leaf.create_csr()

    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)

    cert_tool_leaf.save_cert()
    log.info(cert_tool_leaf.cert_info())
    cert_tool_leaf.save_private_key()

    log.info("running web server with certs")
    web_server_process_handle = tls_web_server_process(
        cert_tool_leaf.cert_file, cert_tool_leaf.private_key_file
    )
    next(web_server_process_handle)  # use next to use the yielded iterator

    url = "https://localhost:5001"
    log.info(f"testing the web server and certs: open url: {url}")
    log.info(f".. import ca cert into your web browser as trusted: {cert_location}")

    r = requests.get(
        url,
        verify=cert_tool_root.cert_file,
        proxies=proxies,
    )
    if r.json() == {"message": "Hello World - bingo - bang"}:
        log.info("local test passed")
    else:
        log.error("local test failed")

    input("\n\nPress Enter to continue...\n\n")

    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


def ca_certs_mtls_recipe() -> None:
    log.info("creating ca signed certs with mtls client")
    cert_location = pathlib.Path().cwd() / "certs"
    prefix = "dev_mtls"

    # root ca
    cert_tool_root = CertTool(
        location=cert_location, common_name="root cert", prefix=prefix
    )
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()
    assert cert_tool_root.save_cert().exists()
    # leaf server cert
    common_name = "localhost"
    cert_tool_leaf = CertTool(
        location=cert_location, common_name=common_name, prefix=prefix
    )
    cert_tool_leaf.create_private_key()
    cert_tool_leaf.create_csr()

    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)

    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()

    # create client cert
    common_name = "client_cert"
    cert_tool_client = CertTool(
        location=cert_location, common_name=common_name, prefix=prefix
    )
    cert_tool_client.create_private_key()

    cert_tool_client.create_csr()

    cert_tool_client.cert = cert_tool_root.sign_certificate(cert_tool_client.csr)

    cert_tool_client.save_cert()
    cert_tool_client.save_private_key()
    cert_tool_client.save_cert_as_p12()

    log.info("running web server with certs")
    web_server_process_handle = mtls_web_server_process(
        cert_tool_leaf.cert_file,
        cert_tool_leaf.private_key_file,
        cert_tool_root.cert_file,
    )
    next(web_server_process_handle)  # use next to use the yielded iterator
    url = "https://localhost:5002"
    log.info(
        f"testing the web server and certs, with mutual TLS client cert: open {url}"
    )
    log.info(
        f"load the client cert with password 1234: {cert_tool_client.cert_file} into the browser "
    )
    log.info(
        f"load the ca cert into the browsers list of trusted root certs: {cert_tool_root.cert_file}"
    )
    r = requests.get(
        url,
        verify=cert_tool_root.cert_file,
        # cert - tuple order must match client_cert then client_key
        cert=(cert_tool_client.cert_file, cert_tool_client.private_key_file),
        proxies=proxies,
    )

    if r.json() == {"message": "Hello World - bingo - bang"}:
        log.info("local test passed")
    else:
        log.error("local test failed")

    input("\n\nPress Enter to continue...\n\n")

    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


if __name__ == "__main__":
    # ca_certs_tls_recipe()
    ca_certs_tls_recipe_private_key_encryption()
    # ca_certs_mtls_recipe()
