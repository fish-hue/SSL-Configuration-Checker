import ssl
import socket
import datetime
import logging
import argparse
import sys
import json

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
except ImportError:
    print("The 'cryptography' library is required. Install it using:\n"
          "pip install cryptography")
    sys.exit(1)

# Logger configuration
logger = logging.getLogger(__name__)
DEFAULT_LOG_FILE = "ssl_checker.log"
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10

# Default lists for weak and strong ciphers
WEAK_CIPHERS = [
    'RC4-SHA',
    'RC4-MD5',
    'DES-CBC3-SHA',
    'EXP-EDH-RSA-DES-CBC-SHA',
    'EXP-RC4-MD5'
]
STRONG_CIPHERS = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384'
]
DEPRECATED_PROTOCOLS = ['SSLv3']

# Exit codes
EXIT_SUCCESS = 0
EXIT_TIMEOUT = 1
EXIT_DNS_ERROR = 2
EXIT_CERT_ERROR = 3
EXIT_UNEXPECTED_ERROR = 99

# Function to validate SSL configuration
def validate_ssl_config(cert, cert_binary, cipher, protocol, weak_ciphers, strong_ciphers):
    check_ciphers(cipher, weak_ciphers, strong_ciphers)
    check_protocols(protocol)
    
    if check_certificate_expiration(cert):
        logger.info("Certificate is valid.")
        check_certificate(cert, cert_binary)

# Load settings from a JSON configuration file
def load_config(file_path):
    """Load configuration from a JSON file and return weak and strong ciphers."""
    try:
        with open(file_path, 'r') as f:
            config = json.load(f)

        weak_ciphers = config.get('weak_ciphers', WEAK_CIPHERS)
        strong_ciphers = config.get('strong_ciphers', STRONG_CIPHERS)

        if 'weak_ciphers' not in config:
            logger.warning(f"'weak_ciphers' not found in config, using default: {WEAK_CIPHERS}")
        if 'strong_ciphers' not in config:
            logger.warning(f"'strong_ciphers' not found in config, using default: {STRONG_CIPHERS}")

        return weak_ciphers, strong_ciphers
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Could not load config file: {file_path}. Error: {e}")
        return WEAK_CIPHERS, STRONG_CIPHERS

# Setup logging configuration
def setup_logging(log_to_file, log_file=DEFAULT_LOG_FILE, log_level=logging.INFO):
    """Configure logging with optional file output."""
    handlers = [logging.StreamHandler()]
    if log_to_file:
        handlers.append(logging.FileHandler(log_file, mode='w'))
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s: %(message)s',
        handlers=handlers
    )

# Check certificate expiration
def check_certificate_expiration(cert):
    """Check the expiration date of the certificate."""
    if 'notAfter' in cert:
        expiry = cert['notAfter']
        expiration_date = datetime.datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiration_date - datetime.datetime.utcnow()).days
        logger.info(f"Current date: {datetime.datetime.utcnow()}")
        
        if days_left < 0:
            logger.error(f"Certificate expired on {expiration_date}.")
            return False
        elif days_left <= 30:
            logger.warning(f"Certificate expires soon ({days_left} days left).")
        else:
            logger.info(f"Certificate valid until {expiration_date} ({days_left} days left).")
        return True
    else:
        logger.error("'notAfter' key not found in the certificate.")
        return False

# Main SSL check function
def check_ssl_configuration(host, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Check the SSL configuration for the specified host and port."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        logger.info(f"Checking SSL configuration for {host}:{port}")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_binary = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                logger.info(f'Connected to {host} using cipher: {cipher[0]}')
                logger.info(f'Protocol version: {protocol}')

                # Load the configuration for weak and strong ciphers
                weak_ciphers, strong_ciphers = load_config('config.json')

                # Validate ciphers and protocol
                validate_ssl_config(cert, cert_binary, cipher[0], protocol, weak_ciphers, strong_ciphers)

                # Additional checks can be performed if needed
                check_vulnerabilities(host, port)
                check_supported_protocols(host, port, timeout)

    except socket.timeout:
        logger.error(f"Connection to {host}:{port} timed out.")
        return EXIT_TIMEOUT
    except socket.gaierror:
        logger.error(f"Unable to resolve host: {host}. Check DNS or network.")
        return EXIT_DNS_ERROR
    except (ssl.SSLCertVerificationError, ssl.CertificateError) as e:
        logger.error(f"Certificate error: {e}")
        return EXIT_CERT_ERROR
    except Exception as e:
        logger.error(f"Unexpected error of type {type(e).__name__}: {e}")
        return EXIT_UNEXPECTED_ERROR  # Return a specific exit code

    return EXIT_SUCCESS  # Success

# Checking the strength of the cipher
def check_ciphers(cipher, weak_ciphers, strong_ciphers):
    """Check the cipher strength used for the connection."""
    if cipher in weak_ciphers:
        logger.warning(f"Weak cipher in use: {cipher}")
    elif cipher in strong_ciphers:
        logger.info(f"Strong cipher in use: {cipher}")
    else:
        logger.warning(f"Cipher '{cipher}' is not strong. Consider using AEAD-based ciphers.")

# Checking for deprecated protocols
def check_protocols(protocol):
    """Check if a deprecated protocol is in use."""
    if protocol in DEPRECATED_PROTOCOLS:
        logger.warning(f"Deprecated protocol in use: {protocol}")

    SUPPORTED_PROTOCOLS = [
        'TLSv1', 
        'TLSv1.1', 
        'TLSv1.2', 
        'TLSv1.3'
    ]

    if protocol not in SUPPORTED_PROTOCOLS:
        logger.warning(f"Unsupported protocol in use: {protocol}.")
    elif protocol != 'TLSv1.3':
        logger.warning("Consider upgrading to TLSv1.3 for enhanced security.")

# Validate the SSL certificate
def check_certificate(cert, cert_binary):
    """Validate the SSL certificate."""
    if not cert:
        logger.error("No certificate presented.")
        return

    if logger.level != logging.WARNING:  # Check if quiet mode is active
        logger.debug(f"Certificate details: {cert}")

    issuer = dict(cert.get('issuer', []))
    subject = dict(cert.get('subject', []))
    logger.info(f"Issuer: {issuer}")
    logger.info(f"Subject: {subject}")

    if issuer == subject:
        logger.warning("Self-signed certificate detected.")
    if "CN" in subject and subject["CN"].startswith("*."):
        logger.warning(f"Wildcard certificate detected ({subject['CN']}).")

    check_key_strength(cert_binary)

def check_key_strength(cert_binary):
    """Validate the strength of the public key."""
    try:
        cert_x509 = x509.load_der_x509_certificate(cert_binary, default_backend())
        public_key = cert_x509.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            if key_size < 2048:
                logger.warning(f"RSA key size insufficient: {key_size} bits.")
            else:
                logger.info(f"RSA key size: {key_size} bits.")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.info(f"Elliptic curve: {public_key.curve.name}")
        else:
            logger.warning(f"Unsupported public key type. Key type: {type(public_key)}")
    except Exception as e:
        logger.error(f"Key strength validation error: {e}")

def check_vulnerabilities(hostname, port):
    """Check for common vulnerabilities."""
    context = ssl.create_default_context()
    try:
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as connection:
            connection.settimeout(5.0)
            connection.connect((hostname, port))
            ssl_info = connection.getpeercert()
            cipher = connection.cipher()[0]
            protocol = connection.version()

            # Check certificate expiry
            if ssl_info:
                if not check_certificate_expiration(ssl_info):
                    logger.error("Certificate is invalid or expired.")
            
            # Check for vulnerabilities in the cipher
            if cipher in WEAK_CIPHERS:
                logger.warning(f"Vulnerable cipher in use: {cipher}")
            if protocol in DEPRECATED_PROTOCOLS:
                logger.warning(f"Deprecated protocol in use: {protocol}")

    except ssl.SSLError as e:
        logger.warning(f"SSL error occurred: {e}")
    except Exception as e:
        logger.error(f"Error connecting to {hostname}:{port} - {e}")

# Checking supported protocols
def check_supported_protocols(host, port, timeout):
    """ Check supported SSL/TLS protocols by attempting connections with various versions. """
    supported_versions = []
    for protocol_version in [
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3
    ]:
        if is_protocol_supported(host, port, timeout, protocol_version):
            supported_versions.append(protocol_version.name)

    if supported_versions:
        logger.info(f"Supported protocols: {', '.join(supported_versions)}")
    else:
        logger.warning("No supported protocols detected.")

# Check if a specific protocol version is supported
def is_protocol_supported(host, port, timeout, protocol_version):
    """Utility to check if a specific protocol is supported."""
    context = ssl.create_default_context()
    context.minimum_version = protocol_version
    context.maximum_version = protocol_version
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except socket.timeout:
        logger.error(f"Connection to {host}:{port} timed out while checking protocol {protocol_version.name}.")
        return False
    except Exception as e:
        logger.warning(f"Error checking protocol {protocol_version.name}: {e}")
        return False

def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="SSL Configuration Checker",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("hostname", help="Hostname to check (e.g., example.com)")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help="Port number (default: %(default)s)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Timeout duration in seconds (default: %(default)s)")
    parser.add_argument("--log-to-file", action="store_true", help="Log output to file")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Set the logging level (default: %(default)s)")
    parser.add_argument("--quiet", action="store_true", help="Disable informational logs")
    parser.add_argument("--config", type=str, default='config.json',
                        help="Path to the JSON configuration file (default: %(default)s)")
    parser.add_argument("--ip", type=str, help="Directly use this IP address instead of resolving the hostname")

    # Parse the arguments
    args = parser.parse_args()

    # Determine logging level
    log_level = logging.getLevelName(args.log_level.upper())
    setup_logging(args.log_to_file, log_level=log_level)

    # Set logging level based on quiet mode
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # Load configuration
    weak_ciphers, strong_ciphers = load_config(args.config)

    # Log the loaded ciphers (optional)
    logging.info(f"Weak ciphers loaded from config: {weak_ciphers}")
    logging.info(f"Strong ciphers loaded from config: {strong_ciphers}")

    # Use IP if provided, otherwise use hostname
    host = args.ip if args.ip else args.hostname

    # Run SSL check
    exit_code = check_ssl_configuration(host, args.port, args.timeout)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
