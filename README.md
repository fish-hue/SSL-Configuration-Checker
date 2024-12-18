# SSL Configuration Checker

## Overview

The **SSL Configuration Checker** is a command-line tool designed to assess the SSL/TLS configurations of web servers. It helps identify security flaws and ensures compliance with best practices by checking various parameters like certificate validity, cipher strength, supported protocols, and vulnerability to known weaknesses.

## Features

- **Certificate Validation**: Verifies the validity and expiration of SSL certificates.
- **Cipher Suite Configuration**: Check against user-defined lists of weak and strong ciphers via a JSON configuration file.
- **Protocol Checking**: Ensures the server supports recommended protocols (TLSv1.2 and TLSv1.3).
- **Logging**: Configurable logging levels (DEBUG, INFO, WARNING, ERROR) with an option to log to a file.
- **Direct IP Support**: Bypass DNS resolution and check directly against an IP address.
- **Enhanced Error Handling**: Detailed error messages for issues such as timeouts, certificate errors, and unsupported protocols.

## Installation

To use this tool, you need Python 3.x and the `cryptography` library. Install the required library using pip:

```bash
pip install cryptography
```

## Usage

You can run the SSL Configuration Checker from the command line. The basic syntax is:

```bash
python sslcc.py [hostname] [-p port] [options]
```

### Arguments

- `hostname` (required): The hostname or IP address of the server to check (e.g., `example.com`).
- `-p`, `--port`: Specify the port number (default is 443).
- `--timeout`: Specify the connection timeout duration in seconds (default is 10).
- `--log-to-file`: Log output to a file (`ssl_checker.log` by default).
- `--log-level`: Set the logging level (DEBUG, INFO, WARNING, ERROR, default is INFO).
- `--quiet`: Disable informational logs (only errors and warnings will be shown).
- `--config`: Specify the path to the JSON configuration file (default is `config.json`).
- `--ip`: Directly use this IP address instead of resolving the hostname.

### Example

To check the SSL configuration for `example.com`:

```bash
python sslcc.py example.com
```

To check using a specific port and logging to a file:

```bash
python sslcc.py example.com -p 8443 --log-to-file --log-level DEBUG
```

### Configuration File

You can customize the cipher suites used for validation by creating a `config.json` file. Here's an example structure:

```json
{
    "weak_ciphers": [
        "RC4-SHA",
        "RC4-MD5"
    ],
    "strong_ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384"
    ]
}
```

## Contributing

Contributions are welcome! If you'd like to contribute, please fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

