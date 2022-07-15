import logging
import pathlib
import socket
import sys
from datetime import datetime
from typing import Generator, Any

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from app.CertTool import tls_web_server_process
from app.pydantic_schemas import CSRPydanticModel

# test path fix
sys.path.append(str(pathlib.Path().cwd() / "app"))

proxies = {
    "http": None,
    "https": None,
}

from app.main_api import (
    app,
    depends_prefix,
    depends_root_ca_common_name,
    depends_location,
)
from app.main_leaf import create_csr
from app.main_root import create_root

log = logging.getLogger(__name__)


class Config:
    API_PREFIX: str = "/"


settings = Config


def depends_test_prefix() -> str:
    return "test"


def depends_test_root_ca_common_name() -> str:
    return "test ca"


def depends_test_location() -> pathlib.Path:
    """using pytest tmp_path fixture could not be made to work
    see the clean-up in client fixture
    """
    return pathlib.Path().cwd() / "certs" / depends_test_prefix()


@pytest.fixture()
def client() -> Generator[TestClient, Any, None]:
    app.dependency_overrides[depends_prefix] = depends_test_prefix
    app.dependency_overrides[
        depends_root_ca_common_name
    ] = depends_test_root_ca_common_name
    app.dependency_overrides[depends_location] = depends_test_location
    with TestClient(app) as client:
        yield client

    def recursive_delete(f: pathlib):
        if f.is_file():
            f.unlink()
        else:
            try:
                for child in f.iterdir():
                    recursive_delete(child)
                f.rmdir()
            except Exception as e:
                log.warning(f"problem deleting temporary test file or directory: {f}")
                pass

    # clean up after the test
    recursive_delete(depends_test_location())
    # remove the overrides
    app.dependency_overrides = {}


def test_read_main(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "message": f"Hello World, {depends_test_root_ca_common_name()} api"
    }


def test_read_config(client):
    response = client.get("/config")
    ref = {
        "common_name": depends_test_root_ca_common_name(),
        "location": str(depends_test_location()),
        "prefix": depends_test_prefix(),
    }
    assert response.status_code == 200
    assert response.json() == ref


def test_read_root_cert_info_no_cert_found(client):
    response = client.get("/root_cert/info")
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Root CA not found for location: "
        f"{str(depends_test_location())}, prefix: {depends_test_prefix()}"
    }


def test_read_root_cert_info(client):
    root_ca = create_root(
        prefix=depends_test_prefix(),
        root_ca_common_name=depends_test_root_ca_common_name(),
        location=depends_test_location(),
    )
    response = client.get("/root_cert/info")
    assert response.status_code == 200
    result_cert_info = response.json()
    assert (
        result_cert_info["root_cert_extensions"]
        == "<Extensions([<Extension(oid=<ObjectIdentifier(oid=2.5.29.19, "
        "name=basicConstraints)>, critical=True, "
        "value=<BasicConstraints(ca=True, "
        "path_length=0)>)>])>"
    )
    assert result_cert_info["root_cert_issuer"] == str(root_ca.cert.issuer)
    assert result_cert_info["root_cert_subject"] == str(root_ca.cert.subject)
    # for a root cert that is self-signed by itself then the issuer and the subject as the same
    assert result_cert_info["root_cert_subject"] == result_cert_info["root_cert_issuer"]
    datetime_format = "%Y-%m-%d %H:%M:%S"
    assert datetime.strptime(
        result_cert_info["root_cert_not_valid_before"], datetime_format
    ) < datetime.strptime(
        result_cert_info["root_cert_not_valid_after"], datetime_format
    )
    assert int(result_cert_info["root_cert_serial_number"]) > 1


def download_file(
    client, url: str, local_filename: pathlib.Path | None
) -> pathlib.Path:
    if local_filename is None:
        # use the given filename not the name from the last bit of url
        local_filename = url.split("/")[-1]

    # NOTE the stream=True parameter below
    with client.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024):
                # If you have chunk encoded response uncomment if and set chunk_size parameter to None.
                # if chunk:
                f.write(chunk)
    return pathlib.Path(local_filename)


def test_main_api_post_csr(client):
    # prefix = "test"
    # root_ca_common_name = "test root ca"
    san_list = [
        "abcd.com",
        "*.abbc.com",
        "abcd.com",
        "localhost",
        "efghuhsss",
        socket.getfqdn(),
        socket.gethostname(),
    ]

    root_ca = create_root(
        prefix=depends_test_prefix(),
        root_ca_common_name=depends_test_root_ca_common_name(),
        location=depends_test_location(),
    )
    response = client.get("/root_cert/info")
    assert response.status_code == 200
    result_cert_info = response.json()
    assert (
        result_cert_info["root_cert_extensions"]
        == "<Extensions([<Extension(oid=<ObjectIdentifier(oid=2.5.29.19, "
        "name=basicConstraints)>, critical=True, "
        "value=<BasicConstraints(ca=True, "
        "path_length=0)>)>])>"
    )
    datetime_format = "%Y-%m-%d %H:%M:%S"
    assert datetime.strptime(
        result_cert_info["root_cert_not_valid_before"], datetime_format
    ) < datetime.strptime(
        result_cert_info["root_cert_not_valid_after"], datetime_format
    )
    assert int(result_cert_info["root_cert_serial_number"]) > 1

    leaf_common_name = f"{depends_test_prefix()}-leaf_common_name"
    leaf_cert_tool = create_csr(
        prefix=depends_test_prefix(),
        location=depends_test_location(),
        common_name=leaf_common_name,
    )

    leaf_cert_tool.save_private_key()
    assert leaf_cert_tool.private_key_file.exists()
    csr_safe = leaf_cert_tool.csr.public_bytes(serialization.Encoding.PEM).decode(
        "utf-8"
    )
    csr_safe = str("\n".join(csr_safe.split("\n")[1:-2])).replace("\n", "-")
    csr_model = CSRPydanticModel(
        common_name=leaf_common_name,
        prefix=depends_test_prefix(),
        csr=csr_safe,
        san=san_list,
    )

    url = f"/sign_csr"
    # log.info(csr_model.dict())
    response = client.post(url, json=csr_model.dict())
    log.info(f"CA response: {response.status_code}")
    assert response.status_code == 200
    leaf_cert = response.text
    # log.info(leaf_cert)
    assert len(leaf_cert) > 10
    assert "--END CERTIFICATE----" in leaf_cert

    # write cert to a tmp_file
    leaf_cert_file = depends_test_location() / "tmp_leaf_cert.pem"
    with open(leaf_cert_file, "wb") as f:
        f.write(bytes(leaf_cert, "utf-8"))

    assert leaf_cert_file.exists()
    with open(leaf_cert_file, "rb") as f:
        data = f.read()
        data_pem = x509.load_pem_x509_certificate(data)

    assert isinstance(data_pem, x509.Certificate)

    log.info("running web server with certs")
    root_ca.save_cert()
    assert root_ca.cert_file.exists()
    assert root_ca.cert != leaf_cert_tool.cert
    with open(root_ca.cert_file, "rb") as f:
        root_cert = f.read()
        # log.info(root_cert)
    web_server_process_handle = tls_web_server_process(
        leaf_cert_file, leaf_cert_tool.private_key_file
    )
    next(web_server_process_handle)  # use next to use the yielded iterator
    log.info("testing the web server and certs")
    r = requests.get(
        "https://localhost:5011",
        verify=root_ca.cert_file,
        proxies=proxies,
    )
    assert r.status_code == 200
    assert r.json() == {"message": "Hello World - bingo - bang"}
    try:
        next(web_server_process_handle)
    except StopIteration:
        pass

    # get the root cert from main_api via http request, no re-use the cert in the test directory
    # think this is being overwritten somewhere with the client cert meaning it is not the root cert needed
    # not recognised by the web browser when loaded

    # get the root cert
    downloaded_root_cert_file: pathlib.Path = (
        depends_test_location() / "downloaded_root_cert.pem"
    )
    downloaded_root_cert_bytes: bytes = b""
    download_file(client, "/root_cert", downloaded_root_cert_file)
    with open(downloaded_root_cert_file, "rb") as f:
        downloaded_root_cert_bytes = f.read()
    log.info(f"have test root cert file: {downloaded_root_cert_bytes}")
    assert len(downloaded_root_cert_bytes) > 20

    data_pem = x509.load_pem_x509_certificate(downloaded_root_cert_bytes)
    if isinstance(data_pem, x509.Certificate):
        downloaded_root_cert = data_pem
    else:
        log.error(f"cert file not valid cert: {type(data)}")
        assert False

    # the initial root cert does this match the downloaded root cert
    assert downloaded_root_cert == root_ca.cert

    log.info(downloaded_root_cert.subject)

    # ref_common_name from main_api.py
    ref_common_name = (
        f",CN={depends_test_prefix()}"
        f'-{depends_test_root_ca_common_name().replace(" ", "_").replace(".", "-")}'
    )
    assert ref_common_name in str(
        downloaded_root_cert.subject
    )  # where is the download_root_cert from?
