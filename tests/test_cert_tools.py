import logging
import pathlib
from multiprocessing import Process

import pytest
import requests
import uvicorn
from cryptography.x509 import CertificateSigningRequest, Certificate

from fastapi import FastAPI

from app.CertTool import CertTool
from app.main_leaf import create_csr
from app.main_root import create_root, sign_csr

log = logging.getLogger(__name__)

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
    cert_tool = CertTool(location=tmp_path, common_name=common_name, prefix='pytest')
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

    cert_tool_root = CertTool(location=tmp_path, common_name='root cert', prefix='pytest')
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()
    assert cert_tool_root.save_cert().exists()

    common_name = 'localhost'
    cert_tool_leaf = CertTool(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool_leaf.create_private_key()

    cert_tool_leaf.create_csr()
    assert isinstance(cert_tool_leaf.csr, CertificateSigningRequest)
    assert str(cert_tool_leaf.csr.subject) == f'<Name(C={cert_tool_leaf.COUNTRY_NAME},' \
                                              f'ST={cert_tool_leaf.STATE_OR_PROVINCE_NAME},' \
                                              f'L={cert_tool_leaf.LOCALITY_NAME},' \
                                              f'O={cert_tool_leaf.ORGANIZATION_NAME},' \
                                              f'CN={common_name})>'

    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)
    assert isinstance(cert_tool_leaf.cert, Certificate)
    assert str(cert_tool_leaf.cert.subject) == f'<Name(C={cert_tool_leaf.COUNTRY_NAME},' \
                                               f'ST={cert_tool_leaf.STATE_OR_PROVINCE_NAME},' \
                                               f'L={cert_tool_leaf.LOCALITY_NAME},' \
                                               f'O={cert_tool_leaf.ORGANIZATION_NAME},' \
                                               f'CN={common_name})>'
    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()
    assert cert_tool_leaf.save_cert().exists()
    assert cert_tool_leaf.save_private_key().exists()
    log.info('running web server with certs')
    web_server_process_handle = tls_web_server_process(cert_tool_leaf.cert_file,
                                                       cert_tool_leaf.private_key_file)
    next(web_server_process_handle)  # use next to use the yielded iterator
    log.info('testing the web server and certs')
    r = requests.get('https://localhost:5001', verify=cert_tool_root.cert_file, )
    assert r.status_code == 200
    assert r.json() == {'message': 'Hello World - bingo - bang'}
    try:
        next(web_server_process_handle)
    except StopIteration:
        pass


def test_ca_signed_server_with_private_key_encryption(tmp_path):
    password = '1234'
    cert_tool_root = CertTool(location=tmp_path,
                              common_name='root cert',
                              prefix='pytest',
                              use_private_key_encryption=True
                              )
    cert_tool_root.create_private_key()
    cert_tool_root.save_private_key(password=password)
    cert_tool_root = None  # remove the existing object to check the file version works
    cert_tool_root = CertTool(location=tmp_path,
                              common_name='root cert',
                              prefix='pytest',
                              use_private_key_encryption=True
                              )
    cert_tool_root.load_private_key(password=password)
    cert_tool_root.create_root_cert(2)
    cert_tool_root.save_cert()
    assert cert_tool_root.save_cert().exists()

    common_name = 'localhost'
    cert_tool_leaf = CertTool(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool_leaf.create_private_key()

    cert_tool_leaf.create_csr()
    assert isinstance(cert_tool_leaf.csr, CertificateSigningRequest)
    assert str(cert_tool_leaf.csr.subject) == f'<Name(C={cert_tool_leaf.COUNTRY_NAME},' \
                                              f'ST={cert_tool_leaf.STATE_OR_PROVINCE_NAME},' \
                                              f'L={cert_tool_leaf.LOCALITY_NAME},' \
                                              f'O={cert_tool_leaf.ORGANIZATION_NAME},' \
                                              f'CN={common_name})>'

    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)
    assert isinstance(cert_tool_leaf.cert, Certificate)
    assert str(cert_tool_leaf.cert.subject) == f'<Name(C={cert_tool_leaf.COUNTRY_NAME},' \
                                               f'ST={cert_tool_leaf.STATE_OR_PROVINCE_NAME},' \
                                               f'L={cert_tool_leaf.LOCALITY_NAME},' \
                                               f'O={cert_tool_leaf.ORGANIZATION_NAME},' \
                                               f'CN={common_name})>'
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


def test_ca_signed_server_with_private_key_encryption_bad_password(tmp_path):
    password = '1234'
    cert_tool_root = CertTool(location=tmp_path,
                              common_name='root cert',
                              prefix='pytest',
                              use_private_key_encryption=True
                              )
    cert_tool_root.create_private_key()
    cert_tool_root.save_private_key(password=password)
    cert_tool_root = None  # remove the existing object to check the private in a file works
    cert_tool_root = CertTool(location=tmp_path,
                              common_name='root cert',
                              prefix='pytest',
                              use_private_key_encryption=True
                              )
    with pytest.raises(ValueError):
        cert_tool_root.load_private_key(password='bad wrong password')
    assert cert_tool_root.private_key is None


def test_ca_signed_server_with_mtls(tmp_path):
    log.info('creating ca signed certs with mtls client')
    # root ca
    cert_tool_root = CertTool(location=tmp_path, common_name='root cert', prefix='pytest')
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(100)
    cert_tool_root.save_cert()
    assert cert_tool_root.save_cert().exists()
    # leaf server cert
    common_name = 'localhost'
    cert_tool_leaf = CertTool(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool_leaf.create_private_key()
    cert_tool_leaf.create_csr()
    assert isinstance(cert_tool_leaf.csr, CertificateSigningRequest)
    assert str(cert_tool_leaf.csr.subject) == f'<Name(C={cert_tool_leaf.COUNTRY_NAME},' \
                                              f'ST={cert_tool_leaf.STATE_OR_PROVINCE_NAME},' \
                                              f'L={cert_tool_leaf.LOCALITY_NAME},' \
                                              f'O={cert_tool_leaf.ORGANIZATION_NAME},' \
                                              f'CN={common_name})>'
    cert_tool_leaf.cert = cert_tool_root.sign_certificate(cert_tool_leaf.csr)
    assert isinstance(cert_tool_leaf.cert, Certificate)
    assert str(cert_tool_leaf.cert.subject) == f'<Name(C={cert_tool_leaf.COUNTRY_NAME},' \
                                               f'ST={cert_tool_leaf.STATE_OR_PROVINCE_NAME},' \
                                               f'L={cert_tool_leaf.LOCALITY_NAME},' \
                                               f'O={cert_tool_leaf.ORGANIZATION_NAME},' \
                                               f'CN={common_name})>'
    cert_tool_leaf.save_cert()
    cert_tool_leaf.save_private_key()
    assert cert_tool_leaf.save_cert().exists()
    assert cert_tool_leaf.save_private_key().exists()

    # create client cert
    common_name = 'client_cert'
    cert_tool_client = CertTool(location=tmp_path, common_name=common_name, prefix='pytest')
    cert_tool_client.create_private_key()

    cert_tool_client.create_csr()
    assert isinstance(cert_tool_client.csr, CertificateSigningRequest)
    assert str(cert_tool_client.csr.subject) == f'<Name(C={cert_tool_client.COUNTRY_NAME},' \
                                                f'ST={cert_tool_client.STATE_OR_PROVINCE_NAME},' \
                                                f'L={cert_tool_client.LOCALITY_NAME},' \
                                                f'O={cert_tool_client.ORGANIZATION_NAME},' \
                                                f'CN={common_name})>'

    cert_tool_client.cert = cert_tool_root.sign_certificate(cert_tool_client.csr)
    assert isinstance(cert_tool_client.cert, Certificate)
    assert str(cert_tool_client.cert.subject) == f'<Name(C={cert_tool_client.COUNTRY_NAME},' \
                                                 f'ST={cert_tool_client.STATE_OR_PROVINCE_NAME},' \
                                                 f'L={cert_tool_client.LOCALITY_NAME},' \
                                                 f'O={cert_tool_client.ORGANIZATION_NAME},' \
                                                 f'CN={common_name})>'
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


def test_main_root_and_main_leaf(tmp_path):
    prefix = 'test'
    root_ca_common_name = 'test root ca'
    # main_root_create_root_cmd_line = f'--prefix test --create_root --location {tmp_path}'
    root_ca = create_root(prefix=prefix, root_ca_common_name=root_ca_common_name, location=tmp_path)
    # main_leaf_create_csr_cmd_line = f'--prefix test --location {tmp_path}'
    leaf_cert_tool = create_csr(prefix=prefix, location=tmp_path)
    # main_root_sign_csr_cmd_line = f'--prefix test --sign_csr {tmp_path}/certs/dev/{socket.getfqdn()}_csr.pem'
    leaf_cert_tool.cert = sign_csr(leaf_cert_tool.csr_file, prefix=prefix, location=tmp_path,
                                   root_ca_common_name=root_ca_common_name)
    leaf_cert_tool.save_cert()
    assert leaf_cert_tool.cert_file.exists()
    assert root_ca.cert_file.exists()

    log.info('running web server with certs')
    web_server_process_handle = tls_web_server_process(leaf_cert_tool.cert_file,
                                                       leaf_cert_tool.private_key_file)
    next(web_server_process_handle)  # use next to use the yielded iterator
    log.info('testing the web server and certs')
    r = requests.get('https://localhost:5001', verify=root_ca.cert_file, )
    assert r.status_code == 200
    assert r.json() == {'message': 'Hello World - bingo - bang'}
    try:
        next(web_server_process_handle)
    except StopIteration:
        pass
