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
- pytests do not run on the Ubuntu OS for a reason(s) I do not understand (error: "... port in use ..." - but not so 
far as I can tell)... 

# Setup

from the project root folder ```cert_tool```
```commandline
python -m venv venv
.\venv\scripts\activate.bat
pip install -r requirements.txt
```

# Test

```commandline
cd cert_tool
python -m pytest --capture=no
```

- **pytest --capture=no**  - option shows the standard output as the tests run
- **python -m**            - calling via python will also add the current directory to sys.path (see: [pytest usage](https://www.pytest.org/en/7.1.x/how-to/usage.html#usage)) 

# Run

## Run from the CA

Initialise the Certificate Authority

```commandline
python .\app\main_root.py --prefix dev --create_root --location certs\dev\root
```

## Run the api web interface to the root CA

Assuming your CA is running from a host with this url: 'localhost'

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
main_api will take a settings.ini file in subdirectory of the current working directory with the prefix and location values.

## On the leaf server

Run the command to request a certificate from the CA
```commandline
python .\app\main_leaf.py --prefix dev --ca_url http://localhost --san leaf.example.internal redleaf.example.internal --location cert\dev\leaf
```

The root ca signed cert is downloaded to ```cert\dev\leaf\<leaf fdqn>_cert.pem```, see the console output.

where:
1) --ca_url is the url of the CA
2) --san is a optional list of subject alternate names
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
python .\app\main_root.py --prefix dev --sign_csr certs/dev/{socket.getfqdn()}_csr.pem
```

## Run just CertTool

This command is show for completeness, it is not used anymore, it was one of the development stages the application 
passed through.

Just CertTool, without the functionality broken out into separate programmes (as above)

```commandline
python .\app\CertTool.py
```

Then open in a web browser: 

- http:      ```https://localhost:5000```
- tls:       ```https://localhost:5001```
- mtls:      ```https://localhost:5002```

CertTool would need to be commented differently to run each of the above configurations. The 'recipes' are included 
in the script (CertTool.py). 

- NB 1: the hostname of the leaf server will be automatically used in the certificate file name
- NB 2: to prefix must be the same for each of these three commands

The command to run mTLS not implemented in a stand-alone application like has been done with the leaf and root scripts.
The functionality is within CertTool.py, just not exposed.

## Overview of how it works

1. import
```python
from multiprocessing import Process
```
- for example TLS Server running with uvicorn, note the certificate and private key are passed in as parameters to the function. 
  - the private key relates to the certificate and as 'only you' have the private key then the cert must be yours
```python

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
```
2. run the TLS Server process 
  - yield the new process, pass in the parameters as an enum to the tls_server above
```python

def tls_web_server_process(cert_path, private_key_path):
    log.info(f'Starting TLS server process: {cert_path}')
    p = Process(target=tls_server, args=(cert_path, private_key_path,), daemon=True)
    p.start()
    log.info(f'TLS Server process started with cert: {cert_path}')
    yield p
    p.kill()  # Cleanup after test
    log.info('TLS Server process stopped')
    return
```
3. in the test function after the certs are created run the tls web server
  - then call the returned iterator (from the above yield generator to close the server down when the tests are complete)
```python
    web_server_process_handle = tls_web_server_process(cert_tool_leaf.cert_file, cert_tool_leaf.private_key_file)
    next(web_server_process_handle)  # use next to use the yielded iterator
    log.info('testing the web server and certs')
    r = requests.get('https://localhost:5001', verify=cert_tool_root.cert_file, )
    # assert some tests on r
    try:
        next(web_server_process_handle)
    except StopIteration:
        pass
```

# Other

1) The private key may be encrypted (but has not been fully tested)
2) Not sure why I didn't use the [TestClient functionality in Starlettle](https://www.starlette.io/testclient/) more
3) Log settings not fully tested or implemented
