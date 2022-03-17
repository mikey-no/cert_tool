import argparse
import logging
import pathlib
import socket
import sys

from CertTool import CertTool

__app__ = 'leaf_cert_tool'
__version__ = '0.0.1'

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


def create_csr(prefix: str = 'dev',
               location: pathlib.Path | None = None) -> CertTool:
    """
    Create a leaf private key under the location prefix and certificate signing request
    common name based on local fqdn
    :param location:
    :param prefix: prefix
    :type prefix:
    :return: csr_file
    :rtype: pathlib.Path
    """
    log.info(f'creating leaf csr for: {prefix}')
    if location is None:
        cert_location = pathlib.Path().cwd() / 'certs'
    else:
        cert_location = location
    common_name = socket.getfqdn()

    # leaf keys and csr
    cert_tool_leaf = CertTool(location=cert_location, common_name=f'{common_name}', prefix=prefix)
    cert_tool_leaf.create_private_key()
    cert_tool_leaf.create_csr()
    cert_tool_leaf.save_csr()
    # log.debug(f'cert_tool_leaf.csr_file.exists: {cert_tool_leaf.csr_file.exists()}')
    cert_tool_leaf.save_private_key()
    # cert_tool_leaf.cert_info()
    # cert_tool_leaf.save_cert_tool()
    return cert_tool_leaf


def parse_args() -> argparse:
    """Parse the programme arguments
    :return: arguments
    """
    parser = argparse.ArgumentParser(description='leaf cert tools', prog=__app__)

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
                        help='leaf cert prefix'
                        )

    parser.add_argument('-pwd', '--password',
                        type=str,
                        help='leaf cert private key password'
                        )

    # will need to add in the url of the root ca server that will sign the csr

    parser.add_argument('-ll', '--log-level',
                        choices=['debug', 'info'],
                        type=str,
                        help='log detail, debug all, info less (default id debug)'
                        )

    parser.add_argument('-v', '--version',
                        help='get version information then exit',
                        action='store_true'  # no extra value after the parameter
                        )

    args = parser.parse_args()
    logging.debug(str(args))
    return args


def main():
    args = parse_args()

    if args.version:
        log.info(f'Application: {__app__} - Version: {__version__}')
        sys.exit(0)

    if args.prefix is None:
        log.critical(f'Prefix is none, select a valid prefix')
        sys.exit(0)

    create_csr(args.prefix)


if __name__ == "__main__":
    main()
