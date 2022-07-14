import argparse
import logging
import pathlib
import socket
import sys
from typing import List

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from CertTool import CertTool
from pydantic_schemas import CSRPydanticModel

__app__ = "leaf_cert_tool"
__version__ = "0.0.2"

log = logging.getLogger(__name__)

common_name = socket.getfqdn()


def create_csr(
    prefix: str,
    location: pathlib.Path | None = None,
    common_name=common_name,
    san: List[str] | None = None,
) -> CertTool:
    """
    Create a leaf private key under the location prefix and certificate signing request
    common name based on local fqdn
    :param common_name:
    :param location: to store the files in
    :param prefix: prefix
    :type prefix:
    :return: csr
    :rtype: CertTool
    """
    log.info(f"creating leaf csr for: {prefix}")
    common_name = common_name

    # leaf keys and csr
    cert_tool_leaf = CertTool(
        location=location, common_name=f"{common_name}", prefix=prefix
    )
    cert_tool_leaf.create_private_key()
    if san is None:
        cert_tool_leaf.create_csr()
    else:
        cert_tool_leaf.create_csr(san=san)
    cert_tool_leaf.save_csr()
    # log.debug(f'cert_tool_leaf.csr_file.exists: {cert_tool_leaf.csr_file.exists()}')
    cert_tool_leaf.save_private_key()
    # cert_tool_leaf.cert_info()
    # cert_tool_leaf.save_cert_tool()
    return cert_tool_leaf


def send_csr_to_ca_url(
    ca_url: str,
    prefix: str,
    csr: x509.CertificateSigningRequest,
    common_name: str,
    subject_alternate_name: List[str] | None = None,
    location: pathlib.Path | None = None,
):
    if isinstance(ca_url, str) is False:
        log.critical("No ca URL supplied")
        sys.exit(-1)

    log.info(f"Root CA URL set to: {ca_url}")
    log.info(f"Checking is the CA url exists")
    url = f"{ca_url}/root_cert/info"
    try:
        response = requests.get(url)
    except Exception as e:
        log.error(f"Unable to contact the ca: {e} - {ca_url}")
        sys.exit(0)
    if response.status_code == 200:
        log.info(f"URL found: {response.status_code}")
    else:
        log.critical(f"URL invalid response: {response.status_code}")
        sys.exit(-1)

    ca_response: dict | None = None
    if response.json() != {"root_cert_info": "no cert found"}:
        ca_response = response.json()
        log.info(f"CA Response: {ca_response}")
    else:
        log.critical(f"Root CA API has no certificate, response: {response.json()}")
        sys.exit(-1)

    url = f"{ca_url}/config"
    response = requests.get(url)
    if response.status_code == 200:
        log.info(f"URL found (config): {response.status_code}")
    else:
        log.critical(f"URL invalid response to config: {response.status_code}")
        sys.exit(-1)

    if response.json()["prefix"] == prefix:
        log.debug(f"Root CA prefix matches the local leaf prefix: {prefix} ")
    else:
        log.error(
            f'Root CA prefix: {response.json()["prefix"]} does not match the local prefix: {prefix}'
        )
        sys.exit(0)

    # get the pem csr
    # to bytes
    # find the bit between ---- BEGIN CER ...... ------------
    csr_safe = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    # log.debug(f"\n{csr_safe}")
    csr_safe = str("\n".join(csr_safe.split("\n")[1:-2])).replace("\n", "-")
    # log.info(f"csr safe: {csr_safe}")
    csr_model = CSRPydanticModel(
        common_name=common_name,
        prefix=prefix,
        csr=csr_safe,
        san=subject_alternate_name,
    )
    # log.debug(f"{csr_model.dict()}")
    url = f"{ca_url}/sign_csr"
    response = requests.post(url, json=csr_model.dict())
    log.info(f"CA response: {response.status_code}")
    try:
        cert_tool = CertTool(
            location=location,
            prefix=prefix,
            common_name=common_name,
        )

        with open(cert_tool.cert_file, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)

        log.info(f"Cert file written: {cert_tool.cert_file}")
    except Exception as e:
        log.error(f"problem getting and writing out the certificate from the ca: {e}")
    return


def parse_args() -> argparse:
    """Parse the programme arguments
    :return: arguments
    """
    parser = argparse.ArgumentParser(description="leaf cert tools", prog=__app__)

    parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        choices=["dev", "test", "prod_A", "prod_B"],
        type=str,
        help="leaf cert prefix",
    )

    parser.add_argument(
        "-l",
        "--location",
        dest="location",
        type=pathlib.Path,
        help=f"location to store certs and keys",
    )

    # TODO: make this take multiple root ca urls (prod_A and prod_B)
    parser.add_argument(
        "-u",
        "--root-ca-url",
        "--root_ca_url",
        dest="ca_url",
        type=str,
        help="URL of the root CA",
    )

    parser.add_argument(
        "-pwd", "--password", type=str, help="leaf cert private key password"
    )

    parser.add_argument(
        "-n",
        "--san",
        dest="san",
        nargs="*",
        type=str,
        help="list of zero of more subject alternate names, some like localhost are added"
        "automatically, must be used with --sign_csr argument",
    )

    parser.add_argument(
        "-ll",
        "--log-level",
        choices=["debug", "info"],
        type=str,
        help="log detail, debug all, info less (default is debug)",
    )

    parser.add_argument(
        "-v",
        "--version",
        help="get version information then exit",
        action="store_true",  # no extra value after the parameter
    )

    args = parser.parse_args()
    logging.debug(str(args))
    return args


def main():
    args = parse_args()
    location: pathlib.Path | None = None

    if args.version:
        log.info(f"Application: {__app__} - Version: {__version__}")
        sys.exit(0)

    if args.prefix is None:
        log.critical(f"Prefix is none, select a valid prefix")
        sys.exit(0)

    if args.location is None:
        log.critical(f"Location is none, using default")

    if args.san is None:
        cert_tool = create_csr(args.prefix, location=args.location, san=None)
    else:
        cert_tool = create_csr(args.prefix, location=args.location, san=args.san)
    if cert_tool.csr is not None:
        if args.ca_url is None:
            log.info(
                f"Root CA URL is not set and cannot send this CSR to the CA for signing"
            )
            sys.exit(0)
        else:
            # simple(args.ca_url)
            send_csr_to_ca_url(
                args.ca_url,
                args.prefix,
                cert_tool.csr,
                common_name=common_name,
                subject_alternate_name=args.san,
                location=args.location,
            )


if __name__ == "__main__":
    main()
