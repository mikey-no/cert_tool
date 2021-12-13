# CertTools

Using python [cryptography module](https://pypi.org/project/cryptography/) to create x509 certificates in turn for:
- self signed TLS Server
- CA signed TLS Server
- CA signed TLS Server and client Mutual TLS Certificate

Then using [pytest](https://docs.pytest.org/) test the above certificates are all working with a server and client. 
- Server with [FastAPI](https://fastapi.tiangolo.com/) and [Uvicorn](https://www.uvicorn.org/).
- Client with [requests](https://docs.python-requests.org/en/latest/) making use of the certificates.

The FastAPI Uvicorn server is run in another process 
[multiprocessing](https://docs.python.org/3/library/multiprocessing.html) than the client.

> You could then use these certificates and keys within a TLS terminating proxy in front of your application without 
> wondering if the certificates are even working or not. :relieved:

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

## Runs on

- Python 3.10

# Setup

```commandline
python -m venv venv
.\venv\scripts\activate.bat
pip install -r requirements.txt
```

# Test

```commandline
pytest .\app\CertTools.py --capture=no
```

**pytest --capture=no**  - option shows the standard output as the tests run

# Run

```commandline
python .\app\CertTool.py
```

Then open in a web browser: ```https://localhost:<port>```



