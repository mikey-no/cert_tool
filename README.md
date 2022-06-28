# CertTools
Using python [cryptography module](https://pypi.org/project/cryptography/) to create x509 certificates for:
- self signed TLS Server
- CA signed TLS Server
- CA signed TLS Server and client Mutual TLS Certificate

Server is created with [FastAPI](https://fastapi.tiangolo.com/) and [Uvicorn](https://www.uvicorn.org/).
Client with [requests](https://docs.python-requests.org/en/latest/) making use of the certificates.

The servers and client are run with [pytest](https://docs.pytest.org/), testing the above certificates are all working. 

The FastAPI Uvicorn server is run in another process than the clients using [multiprocessing](https://docs.python.org/3/library/multiprocessing.html).

> You could then use these certificates and keys within a TLS terminating proxy in front of your application without 
> wondering if the certificates are even working or not. :relieved:

> I would only use this in a lab context. You would have to trust the certificate authority!! 

## Runs on

- Python 3.10 (Windows 10, Ubuntu 20.04)
- in a docker container (note this work is partially complete, for example the root certificate is not held in a docker secret)

# Setup

from the project root folder ```cert_tool```
```commandline
python -m venv venv
.\venv\scripts\activate.bat
pip install -r requirements.txt
```
# Build docker image

1) Initialise the Certificate Authority as below
2) To build the docker api root cert server first run
   1) ```run_docker_registry.bash``` build and start the registry server
   2) ```build_image.bash``` build the docker image of the main_api.py based application

# Test

```commandline
cd cert_tool
python -m pytest --capture=no
```

- **pytest --capture=no**  - option shows the standard output as the tests run
- **python -m**            - calling via python will also add the current directory to sys.path (see: [pytest usage](https://www.pytest.org/en/7.1.x/how-to/usage.html#usage))

On Ubuntu:
The pytest do not run on Ubuntu due to: "ERROR:    [Errno 98] error while attempting to bind on address ('127.0.0.1', 5001): address already in use"
the steps taken to allow python a non-privileged user do not work and when you run with sudo your path does not have 
the venv set up as required. This may be caused by running docker registry locally on my test host.


# Run

## Run from the CA

Initialise the Certificate Authority

```commandline
python .\app\main_root.py --prefix dev --create_root --location certs\dev\root
```

## Run the api web interface to the root CA

Assuming your CA is running from a host with this url: 'localhost'

## OR via Docker

Run:
```commandline
./run.bash
```

```commandline
python .\app\main_api.py --prefix dev --location certs\dev\root
```
In another window open...
```commandline
firefox http://localhost
```

See the API docs: http://localhost/docs

The ca works on http not https to enable a client to start the communication with no prior root ca installed.

### settings.ini
main_api will take a cert_tool_api.ini file in subdirectory of the current working directory with the prefix and location values.

## On the leaf server

Run the command to request a certificate from the CA
```commandline
python .\app\main_leaf.py --prefix dev --ca_url http://localhost --san leaf.example.internal redleaf.example.internal --location cert\dev\leaf
```

The root ca signed cert is downloaded to ```cert\dev\leaf\<leaf fdqn>_cert.pem```, see the console output.

where:
1) --ca_url is the url of the CA
2) --san is an optional list of subject alternate names
   1) The CA assumes you want localhost and the socket.fqdn() name from the leaf server adding to the san list by default
3) prefix of the ca and leaf server must match

The leaf cert name is the response back from the CA and is saved to a file prefixed with the socket.fqdn() name pem file.

## Run from the Leaf Server (from command line only)

Initialise the Leaf private, public and create a certificate signing request

```commandline
python .\app\main_leaf.py --prefix dev --san abc.example.internal bcd.example.internal
```

## Run from the CA (again)

Sign the certificate signing request creating a leaf certificate, using the command line tool rather than the root_api
web api.

```commandline
python .\app\main_root.py --prefix dev --sign_csr certs/dev/$(hostname)_csr.pem
```

This
```$(hostname)``` in ubuntu bash must give the same text and ```socket.socket.getfqdn()``` in python
# Other

1) The private key may be encrypted (but has not been fully tested)
2) Not sure why I didn't use the [TestClient functionality in Starlettle](https://www.starlette.io/testclient/) more
3) Log settings not fully tested or implemented

## Running on Linux you may get this error

ERROR:    [Errno 98] error while attempting to bind on address ('127.0.0.1', 5001): address already in use
There is a security setting that needs to be changed to enable python to run as a none privileged user and be allowed to
bind to a port less than 1024. Use ```allow_low_port.bash```. The local docker registry started and stopped with ```run_docker_registry.bash```
and ```stop_docker_registry.bash```. Need to swap the ports used around to not cause this conflict.

I tried iptables but found this simpler to explain.
I did not try authbind.

use the ```allow_low_port.bash``` script to create copy of the python executable that is called python_enabled that has
the permission to connect to port 80 etc with a non privileged user.