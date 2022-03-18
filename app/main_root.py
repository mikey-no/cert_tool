import argparse
import logging
import pathlib
import socket
import sys
from typing import List

from cryptography.x509 import Certificate

sys.path.append(str(pathlib.Path().cwd()))
from app.CertTool import CertTool

__app__ = 'root_cert_tool'
__version__ = '0.0.1'
root_ca_common_name: str = 'root cert'

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


def parse_args() -> argparse:
    """Parse the programme arguments
    :return: arguments
    """
    parser = argparse.ArgumentParser(description='root ca cert tools', prog=__app__)

    default_location = pathlib.Path().cwd() / 'certs'
    parser.add_argument('-l', '--location',
                        dest='location',
                        default=default_location,
                        type=pathlib.Path,
                        help=f'location to store certs and keys, defaults to: {default_location}'
                        )

    parser.add_argument('-p', '--prefix',
                        dest='prefix',
                        choices=['dev', 'test', 'prod_A', 'prod_B'],
                        type=str,
                        help='root cert prefix'
                        )

    parser.add_argument('-pwd', '--password',
                        type=str,
                        help='root cert private key password'
                        )

    parser.add_argument('-c', '--create_root',
                        dest='create_root',
                        help='Create a root ca with a given prefix, warning, this will over write existing keys',
                        action='store_true',
                        )

    parser.add_argument('-s', '--sign_csr',
                        dest='sign_csr',
                        type=pathlib.Path,
                        help='Sign the csr (pem file) with the root ca key of the given prefix, outputting new cert',
                        )

    parser.add_argument('-n', '--san',
                        dest='san',
                        nargs='*',
                        type=str,
                        help='list of zero of more subject alternate names, some like localhost are added '
                             'automatically, must be used with --sign_csr'
                        )

    parser.add_argument('-ll', '--log-level',
                        choices=['debug', 'info'],
                        type=str,
                        help='log detail, debug all, info less (default is debug)'
                        )

    parser.add_argument('-v', '--version',
                        help='get version information then exit',
                        action='store_true'  # no extra value after the parameter
                        )

    args = parser.parse_args()
    logging.debug(str(args))
    return args


def create_root(prefix: str = 'dev',
                root_ca_common_name: str = root_ca_common_name,
                location: pathlib.Path | None = None,
                duration: int = 100) -> CertTool:
    """
    Create a root certificate and private key under the location prefix
    :param location:
    :param root_ca_common_name:
    :type root_ca_common_name:
    :param prefix: prefix
    :type prefix:
    :param duration: days for the root ca to last
    :type duration:
    :return: None
    :rtype:
    """
    log.info(f'creating ca signed root for: {prefix}')
    if location is None:
        cert_location = pathlib.Path().cwd() / 'certs'
    else:
        cert_location = location

    # root ca
    cert_tool_root = CertTool(location=cert_location, common_name=root_ca_common_name, prefix=prefix)
    cert_tool_root.create_private_key()
    cert_tool_root.create_root_cert(duration)
    cert_tool_root.save_cert()
    cert_tool_root.save_private_key()
    # cert_tool_root.save_cert_tool()
    return cert_tool_root


def re_use_existing_ca(prefix: str,
                       location: pathlib.Path,
                       root_ca_common_name: str = root_ca_common_name):
    """
    Have not sorted out if the root ca created before has a private key password
    given the root ca common name, location and prefix are the same then this should pick up the existing root ca
    :param location:
    :type location:
    :param prefix:
    :type prefix:
    :param root_ca_common_name:
    :type root_ca_common_name:
    :param args:
    :type args:
    :return:
    :rtype:
    """
    dummy_root_ca = CertTool(location=location,
                             prefix=prefix,
                             use_private_key_encryption=False,
                             common_name=root_ca_common_name, )
    if dummy_root_ca.private_key_file.exists():
        log.info('Re-using existing root ca... found a private key')
        if dummy_root_ca.load_private_key():
            log.info('Loading existing root ca private key')
        else:
            log.error('Not able to load a private key from an old root ca')
    else:
        log.critical(f'unable to find the root ca private key file: {dummy_root_ca.private_key_file}')
        sys.exit(1)
    return dummy_root_ca


def sign_csr(sign_csr_file: pathlib.Path,
             prefix: str,
             location: pathlib.Path,
             subject_alternate_name: List[str] | None = None,
             root_ca_common_name: str = root_ca_common_name,
             ) -> Certificate | None:
    if sign_csr_file.exists():
        log.info(f'signing csr: {sign_csr_file}')
        pseudo_leaf = CertTool(prefix=prefix, common_name='leaf_temp_common_name', location=location)
        pseudo_leaf.csr_file = sign_csr_file
        pseudo_leaf_load_csr_result = pseudo_leaf.load_csr()  # use this to turn the csr in file to a csr
        pseudo_leaf.load_common_name_from_csr()
        # need to load up the private key from the root ca to enable this cert to e signed
        re_used_root_ca = re_use_existing_ca(prefix=prefix,
                                             location=location,
                                             root_ca_common_name=root_ca_common_name)
        if re_used_root_ca.private_key_file.exists() is False:
            log.critical(f'root ca not configured unable to sign: {sign_csr_file}')
            sys.exit(-1)
        else:
            re_used_root_ca.load_cert()
            re_used_root_ca.load_private_key()
            if pseudo_leaf_load_csr_result is not None:
                pseudo_leaf.cert = re_used_root_ca.sign_certificate(pseudo_leaf.csr, subject_alternate_name)
                log.info(f'Leaf cert: {pseudo_leaf.cert}')
                pseudo_leaf.save_cert()
                return pseudo_leaf.cert
            else:
                log.error(f'Unable to sign the csr the cert was not loaded: {pseudo_leaf_load_csr_result}')
                return None
    else:
        log.critical(f'csr file not found: {sign_csr_file}')
        sys.exit(-1)


def main():
    args = parse_args()

    if args.version:
        log.info(f'Application: {__app__} - Version: {__version__}')
        sys.exit(0)

    if args.prefix is None:
        log.critical(f'Prefix is none, select a valid prefix')
        sys.exit(0)

    if args.create_root and args.sign_csr:
        log.critical('Cannot create a root ca and sign a csr at the same time (optionally use with --san)')
        sys.exit(-1)

    if args.create_root is False and args.sign_csr is None:
        log.critical('Create a root ca (--create_root) or sign a csr (--sign_csr), pick one')
        sys.exit(-1)

    if args.san and args.create_root:
        log.critical('Cannot set a list of subject alternate names until the cert is being signed, only use with '
                     'sign_csr')

    if args.create_root:
        create_root(args.prefix)
        sys.exit(0)

    if args.sign_csr:
        sign_csr(sign_csr_file=args.sign_csr,
                 prefix=args.prefix,
                 location=args.location,
                 subject_alternate_name=args.san)
        info_cert_tool = CertTool(prefix=args.prefix, common_name=socket.getfqdn(), location=args.location)
        info_cert_tool.load_cert()
        print(info_cert_tool.cert_info())
        sys.exit(0)


if __name__ == "__main__":
    main()
