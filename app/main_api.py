import argparse
import configparser
import logging
import pathlib
import sys

import uvicorn
from cryptography import x509
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from starlette import status

sys.path.append(str(pathlib.Path().cwd()))
from app import utils
from app.CertTool import CertTool
from app.pydantic_schemas import CSRPydanticModel, CAInfoModel, RootCertInfoModel

__app__ = "root_cert_tool_api"
__version__ = "0.0.3"
default_ini_file: pathlib.Path = pathlib.Path().cwd() / r"settings" / "cert_tool_api.ini"

log = logging.getLogger(__name__)

app = FastAPI()


def depends_root_ca_common_name() -> str:
    return "root cert"


def depends_prefix() -> str:
    return "dev"


_location: pathlib.Path | None = None


def depends_location():
    log.debug(f"location: {_location}")
    return _location


def get_ini(setting: str, ini_file: pathlib.Path = default_ini_file) -> str | None:
    """
    load the ini file setting from the ini file default section
    returns None if the setting request is not found
    """
    if ini_file.exists() is False:
        log.info(f"Ini settings file not found: {ini_file}")
    else:
        # log.info(f"Ini settings file used: {ini_file} - {setting}")
        pass
    try:
        config = configparser.ConfigParser()
        config.read(ini_file)
        if setting in config["default"]:
            value=config["default"][setting]
            log.info(f"Ini settings file used: {ini_file} - {setting} - section: default - value: {value} ")
            return value
        else:
            log.error(f"Setting file does not contain the setting requested: {setting}")
            return None
    except Exception as e:
        log.critical('ini file problem: {e}')
        sys.exit(-1)


@utils.benchmark
@utils.counter
def parse_args() -> argparse:
    """Parse the programme arguments ....
    :return: arguments
    """
    parser = argparse.ArgumentParser(description="root ca cert tools", prog=__app__)

    default_location = pathlib.Path().cwd() / "certs"

    parser.add_argument(
        "-l",
        "--location",
        dest="location",
        type=pathlib.Path,
        help=f"location to store certs and keys, defaults to {default_location}",  # but is set by CertTool
    )

    parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        choices=["dev", "test", "prod_A", "prod_B"],
        type=str,
        help="root cert prefix",
    )

    parser.add_argument(
        "-pp",
        "--port",
        dest="port",
        default=80,
        type=int,
        help="port to run this web app on, defaults to port 80, the default port 80 will not work on ubuntu without "
             "setting additional permissions on python executable",
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
    log.debug(str(args))
    return args


@utils.logging
@app.get("/")
async def root(root_ca_common_name=Depends(depends_root_ca_common_name)):
    return {"message": f"Hello World, {root_ca_common_name} api"}


@app.get("/config", response_model=CAInfoModel)
async def config(
        prefix=Depends(depends_prefix),
        root_ca_common_name=Depends(depends_root_ca_common_name),
        location=Depends(depends_location),
):
    """
    Get the root ca configuration settings: prefix - location of the Root CA certs and keys etc
    :return:
    """
    return {
        "common_name": f"{root_ca_common_name}",
        "prefix": f"{prefix}",
        "location": f"{location}",
    }


@app.get("/root_cert", response_class=FileResponse)
def get_root_cert(
        prefix=Depends(depends_prefix),
        location=Depends(depends_location),
        root_ca_common_name=Depends(depends_root_ca_common_name),
):
    """
    The root cert for this CA, in a pem file, see the '/root_ca/info' for cert details
    '/info' end api point to tell you which CA this web interface in using.
    Load this cert into any browser or other client that needs to trust it.
    :return: cert pem file
    """
    cert_tool = CertTool(
        location=location, prefix=prefix, common_name=root_ca_common_name
    )

    if cert_tool.cert_file.exists():
        return FileResponse(
            cert_tool.cert_file,
            media_type="application/octet-stream",
            filename=cert_tool.cert_file.name,
        )
    else:
        log.error(
            f"root cert not found: {cert_tool.cert_file}, location: {location}, prefix: {prefix}"
        )
        return JSONResponse(
            {"message": f"error cert file for {cert_tool.prefix} not found"}
        )


@app.get("/root_cert/info", response_model=RootCertInfoModel)
def get_root_cert_info(
        prefix=Depends(depends_prefix),
        location=Depends(depends_location),
        root_ca_common_name=Depends(depends_root_ca_common_name),
):
    """
    Get the root ca cert settings, expiry etc.
    :return:
    """
    cert_tool = CertTool(
        location=location,
        prefix=prefix,
        common_name=root_ca_common_name,
    )
    cert_tool.load_cert()
    if cert_tool.cert_file.exists() and cert_tool.cert is not None:
        log.info(cert_tool.cert.subject)
        return RootCertInfoModel(
            root_cert_subject=str(cert_tool.cert.subject),
            root_cert_issuer=str(cert_tool.cert.issuer),
            root_cert_not_valid_before=str(cert_tool.cert.not_valid_before),
            root_cert_not_valid_after=str(cert_tool.cert.not_valid_after),
            root_cert_serial_number=str(cert_tool.cert.serial_number),
            root_cert_extensions=str(cert_tool.cert.extensions),
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Root CA not found for location: {location}, prefix: {prefix}",
        )


@app.post("/sign_csr", response_class=FileResponse)
def post_sign_csr(
        csr: CSRPydanticModel,
        prefix=Depends(depends_prefix),
        location=Depends(depends_location),
        root_ca_common_name=Depends(depends_root_ca_common_name),
):
    """
    Take a csr in a pem string json format (provided by the main_leaf.py client programme)
    and return a certificate file signed by the CA files accessed by this programme.
    Json created as follows:

        # created like this:
        #     csr_safe = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        #     csr_safe = str('\n'.join(csr_safe.split('\n')[1:-2])).replace('\n', '-')


    The common name of the resulting cert is required to name and add to the signed cert
    The cert mau also have additional subject alternate names, some like localhost are added automatically by
    the root CA as the cert is signed
    TODO: investigate adding the san names in the CSR and passing them to the main_api server in the csr not as
      additional list in the json data
    :param csr:
    :param prefix: the prefix of the cert and the csr must be the same,we do not want a dev cert signed by the root ca
    :return: pem format Certificate signed by the root CA
    """
    cert_tool_root = CertTool(
        location=location,
        prefix=prefix,
        common_name=root_ca_common_name,
    )
    cert_tool_root.load_cert()
    cert_tool_root.load_private_key()

    if cert_tool_root.cert_file.exists() and cert_tool_root.cert is not None:

        csr_rec = csr.csr.replace("-", "\n")
        # log.debug(f'2:\n{csr_rec}')
        csr_rec = f"-----BEGIN CERTIFICATE REQUEST-----\n{csr_rec}\n-----END CERTIFICATE REQUEST-----\n"
        # log.debug(f'3:\n{csr_rec}')
        cert = None
        cert_in_pem = None
        try:
            cert = cert_tool_root.sign_certificate(
                x509.load_pem_x509_csr(bytes(csr_rec, encoding="utf-8")),
                cert_tool_root.make_subject_alternate_name(
                    csr.common_name, name_list=csr.san
                ),
            )
            cert_tool_root.cert = cert
            cert_tool_root.save_cert()
            return FileResponse(
                cert_tool_root.cert_file,
                media_type="text/plain",
                filename=f"{csr.common_name}_cert.pem",
            )

        except Exception as e:
            log.info(f"error creating the cert: {e}")
        log.info(cert.subject)

    else:
        return {"root-certs not ready to make a csr": csr.common_name}


@app.get('/health')
def health():
    return "Healthy: OK"


@utils.counter
def server(host: str = "0.0.0.0", port: int = 80):
    log.info(f"Running server: {host}:{port}")
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="debug",
    )


@utils.counter
def main():
    args = parse_args()
    global _location
    global prefix

    if args.version:
        log.info(f"Application: {__app__} - Version: {__version__}")
        sys.exit(0)

    port = get_ini("port")
    if port is None:
        if args.port is None:
            log.info("No port found, using the default")
            sys.exit(-1)
        else:
            port = args.port

    if isinstance(port, str) and port is not None:
        log.debug(f'convert {port} to int its is {type(port)}')
        port = int(port)

    prefix = get_ini("prefix")
    if prefix is None:
        if args.prefix is None:
            log.critical("No prefix found")
            sys.exit(-1)
        else:
            prefix = args.prefix

    _location = pathlib.Path(get_ini("location"))
    if _location is None:
        if args.location is None:
            log.critical(f"No location found")
            sys.exit(-1)
        else:
            _location = args.location

    log.info(f"Prefix: {prefix}")
    log.info(
        f"Location: {_location.absolute()} - exists {_location.absolute().exists()}"
    )

    server(port=port, host='0.0.0.0')


if __name__ == "__main__":
    main()
