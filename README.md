## Introduction
Welcome to the python ishare package. This package implements helpers for the 
authentication flow between iSHARE services. Specifically, the part of the process 
where a json web token (per iSHARE specification) is transformed into an access token. 
This access token can then be used to communicate with the rest of a Role's service 
endpoints.

This package could be relevant for connecting to/from the following 
[roles](https://ishare.eu/about-ishare/roles/):
- Satellite or Data Space Authorities
- Authentication Registries
- Identity Providers
- Service or Data Provider
- Service or Data Consumers

For more information on ISHARE;
* [The ISHARE website](https://ishare.eu/nl/)
* [The developer documentation](https://dev.ishare.eu/)
* [The ISHARE Framework](https://ishareworks.atlassian.net/wiki/spaces/IS/overview)
* [The ISHARE Satellite repository](https://github.com/iSHAREScheme/iSHARESatellite)

## Usage

### Prerequisites
For a working connection with, for example, an iSHARE satellite you need a participant 
registration. 

- From the registration with an iSHARE Satellite. 
  - (encryption) The registered Certificate's *private* RSA key. This must be kept SECRET!
  - (`x509 header`) The registered Certificate's *public* x509 certificate chain. 
  - (`client_id`) The registered participant's EORI number
  - The registered participant adherence status is "Active".
- For every participant Service you want to connect to:
  - (`audience`) The target service's EORI number
  - (decryption) Their public x509 (can be retrieved from an iSHARE Satellite)
  - The domain of the service you're connecting to

All of these are required to encrypt and decrypt communication between different the 
iSHARE services. For more detailed information refer to the `private key jwt` json web 
token flow [here](https://oauth.net/private-key-jwt/).

### The three-step methodology

1. Create a json web token per iSHARE [specification](https://dev.ishare.eu/introduction/jwt.html)).
2. Use a client interface to communicate with a role
3. Use the `ISHARESatelliteClient` interface to verify a participant

#### I. Creating the json web token

There is a convenience method (`python_ishare.create_jwt`) in the package to help create 
the token. 

```python
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificates, Certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from python_ishare import create_jwt

YOUR_PARTICIPANT_EORI = "XXX"
THEIR_PARTICIPANT_EORI = "YYY"

# Load your RSA key to an RSAPrivateKey
with Path("path/to/my/key.pem") as file:
    private_key: RSAPrivateKey = load_pem_private_key(
        file.read_bytes(),
        password=b"your_password_or_None"
    )

with Path("path/to/my/certs.pem") as file:
    chain: list[Certificate] = load_pem_x509_certificates(
        file.read_bytes()
    )    
    
# Create the actual token
my_token = create_jwt(
    payload={
        "iss": YOUR_PARTICIPANT_EORI,
        "sub": YOUR_PARTICIPANT_EORI,
        "aud": THEIR_PARTICIPANT_EORI,
        "jti": "your-unique-id" # optional
    },
    private_key=private_key,
    x5c_certificate_chain=chain
)
```

This method is strictly seperated out from the client interfacing (next step). This is 
for two reasons; 

- It makes you responsible for loading the `Certificate`'s from the chain and 
`RSAPrivateKey` as such that these important files can be stored anywhere.
- It makes it possible to sign the json web token externally using an AWS asymmetric key 
for example. A great security solution.

#### II. Connecting to an iSHARE Satellite

To connect to an iSHARE satellite this package provides an `ISHARESatelliteClient` 
interface class.

```python
from python_ishare import ISHARESatelliteClient

# From step 1
YOUR_PARTICIPANT_EORI = "XXX"
my_token = create_jwt(...)
public_key = ...

client = ISHARESatelliteClient(
    target_domain="satellite.ishare.com",
    target_public_key=public_key,
    client_eori=YOUR_PARTICIPANT_EORI,
    json_web_token=my_token
)

# To retrieve the satellite's capabilities
capabilities = client.get_capabilities()
print(capabilities)

# To retrieve the satellite's public capabilities
public_capabilities = client.get_capabilities(use_token=False)
print(public_capabilities)
```

The value of this interface class is that you never needed to worry about access tokens.
This is handled for you underwater. Tokens are re-used whenever a new request is made. 

#### III. Verifying an iSHARE participant

Verifying a participant is a key responsibility for a number of roles. The 
`ISHARESatelliteClient` has a method to do this for you. 

```python
# From step 2
YOUR_PARTICIPANT_EORI = "XXX"
client = IShareSatelliteClient(...)

# Assuming you have some python web framework there will be a request
request = ...

# If you're a service provider, you can use this to verify other parties iSHARE tokens
client.verify_json_web_token(
    audience=YOUR_PARTICIPANT_EORI,
    client_id=request.param["client_id"],
    client_assertion=request.param["client_assertion"],
    client_assertion_type=request.param["client_assertion_type"],
    grant_type=request.param["grant_type"],
    scope=request.param["scope"],
)
```

> [!IMPORTANT]  
> The `verify_json_web_token` currently does not implement full Certificate validation!

## Developer Setup
Everything needed to start developing on this package. 

## Quick start `||` tl;dr

1. Install the python package management tool; [`poetry`](https://python-poetry.org/docs/#installation).
    ```shell
    curl -sSL https://install.python-poetry.org | python3 -
    ```

2. Install the local python project.
    ```shell
    poetry install
    ```

3. Run the test suite and linters using [`tox`](https://tox.wiki/en/4.11.4/).
    ```shell
    poetry run tox
    ```

4. Run development commands inside the virtualenv.

    ```shell
    poetry run <my_command>
    ```

## Setup
This project runs on a central `pyproject.toml` configuration. Here you can find the 
information for what python version to use and dependencies. Configuration for the 
various linters, testing frameworks is also defined there. 

### Poetry - Project installer
Poetry is a smooth dependency manager for Python that is seemingly taking over the 
market. The [Documentation](https://python-poetry.org/docs/_) is 
of excellent quality.  

[Poetry installation](https://python-poetry.org/docs/#installation):

```shell
curl -sSL https://install.python-poetry.org | python3 -
```

[For a specific version of poetry](https://python-poetry.org/docs/1.5/#installing-with-the-official-installer):

```shell
curl -sSL https://install.python-poetry.org | python3 - --version <POETRY_VERSION>
```

[For users of pipx](https://python-poetry.org/docs/1.5/#installing-with-pipx):
```shell
pipx install poetry
```

### Project Installation

Running `poetry install` will install the source code and all it's dependencies 
including development packages. 

### Pythonic Dependencies
Behind the scenes Poetry creates and manages the virtualenv with all the python 
package dependencies necessary for the project. This means that to access packages and 
scripts installed by Poetry you need to run commands in that environment.

There are two different ways, pick your favorite;

- Wrap your command in a `poetry run` format. For example;

    ```shell
    # poetry run <my_sub_command>
    poetry run black
    ```

- Activate the virtualenv in your shell, and all commands will run accordingly. 

    ```shell
    # <my_sub_command>
    poetry shell
    # Spawns a shell with the venv activated
    black
    # (And all other commands after that)
    ```

💡 *There are IDE's that understand Poetry and handle it for you so you don't have to
do anything else. For instance in PyCharm, you can configure your interpreter to use 
Poetry.*

### Linting libraries used
The following packages are used to ensure code cody cleanliness and monitor some 
known/preventable security issues.

- [`black`](https://github.com/psf/black) is used to auto-format code. 
- [`isort`](https://pycqa.github.io/isort/) is used to automatically sort imports. 
- [`flake8`](https://flake8.pycqa.org/en/latest/) is used enforce standard style guide 
conventions not automatically handled by black.  
- [`bandit`](https://bandit.readthedocs.io/en/latest/) is used to detect some common 
security issues.
- [`mypy`](https://mypy-lang.org/) is used to validate python typehints for correctness.
- [`safety`](https://pypi.org/project/safety/) is used to check 
dependencies for known security issues against a database.
- [`tox`](https://tox.wiki/) is used to run all of the above commands inside an isolated python 
environment.