import boto3
import logging
import os
import json
import subprocess
import glob
import threading
from awslambdaric.bootstrap import run
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json
import re


_logger = logging.getLogger()


def get_cert_info(cert_data):
    cert = x509.load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    cert_info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": cert.not_valid_before.isoformat(),
        "not_valid_after": cert.not_valid_after.isoformat(),
        "serial_number": cert.serial_number,
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }

    subject_alt_names = []
    for extension in cert.extensions:
        if isinstance(extension.value, x509.SubjectAlternativeName):
            for name in extension.value:
                subject_alt_names.append(name.value)
    if len(subject_alt_names) > 0:
        cert_info["subject_alt_names"] = ",".join(subject_alt_names)

    return cert_info


def streamline_tags(tags):
    """
    Streamlines tag keys and values to conform with AWS restrictions:
    - Removes non-legal characters.
    - Shortens keys to a maximum of 128 characters and values to 256 characters.
    """
    streamlined_tags = {}
    # Allowed characters: letters, numbers, space, . - _ : / + =
    pattern = re.compile(r"[^A-Za-z0-9 \.\-\_\:\+\/=]")

    for key, value in tags.items():
        # Remove non-legal characters and shorten keys
        cleaned_key = re.sub(pattern, "", key)[:128]
        # Remove non-legal characters and shorten values
        cleaned_value = re.sub(pattern, "", str(value))[:256]

        streamlined_tags[cleaned_key] = cleaned_value

    return streamlined_tags


def stream_output(pipe, logger_method):
    """
    Stream output from a subprocess pipe to the logger.
    """
    for line in iter(pipe.readline, b""):
        logger_method(line.decode("utf-8").strip())


def run_command_with_streaming(commandline):
    _logger.info(f"Commandline: {commandline}")

    # Start the subprocess with pipes for stdout and stderr
    process = subprocess.Popen(
        commandline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Create threads to stream stdout and stderr
    stdout_thread = threading.Thread(
        target=stream_output, args=(process.stdout, _logger.info)
    )
    stderr_thread = threading.Thread(
        target=stream_output, args=(process.stderr, _logger.info)
    )

    # Start the threads
    stdout_thread.start()
    stderr_thread.start()

    # Wait for the command to complete and threads to finish
    process.wait()
    stdout_thread.join()
    stderr_thread.join()

    return process.returncode


def find_certificates(base_path):
    certs = {}
    # Iterate over each subdirectory in the base path
    for subdir in next(os.walk(base_path))[1]:
        domain = subdir
        domain_path = os.path.join(base_path, subdir)
        # Iterate over each file in the subdirectory
        for file_path in glob.glob(f"{domain_path}/*"):
            file_name = os.path.basename(file_path)
            if file_name.endswith(".cer"):
                if domain not in certs:
                    certs[domain] = {}
                break

        if domain not in certs:
            # directory does not contain a certificate
            continue

        # Iterate over each file in the subdirectory
        for file_path in glob.glob(f"{domain_path}/*"):
            try:
                file_name = os.path.basename(file_path)
                with open(file_path, "r") as file:
                    certs[domain][file_name] = file.read()
                _logger.info(f"Read file {file_path}, stored in {domain}/{file_name}")
            except Exception as e:
                _logger.error(f"Error reading file {file_path}: {e}")

    return certs


def create_or_update_secret(client, secret_name, cert_data, tags=None):
    try:
        try:
            # Try to get the secret to determine if it exists
            client.get_secret_value(SecretId=secret_name)
            update = True
        except client.exceptions.ResourceNotFoundException:
            update = False

        secret_string = json.dumps(cert_data)

        if update:
            # Update the existing secret
            client.update_secret(SecretId=secret_name, SecretString=secret_string)
            _logger.info(f"Updated secret: {secret_name}")
        else:
            # Create a new secret
            client.create_secret(Name=secret_name, SecretString=secret_string)
            _logger.info(f"Created secret: {secret_name}")

        # Add or update tags if provided
        if tags:
            formatted_tags = [{"Key": k, "Value": v} for k, v in tags.items()]
            client.tag_resource(SecretId=secret_name, Tags=formatted_tags)
            _logger.info(f"Tags updated for secret: {secret_name}")

    except Exception as e:
        _logger.error(f"Error creating/updating secret {secret_name}: {e}")


def run_acme():
    _logger.info("Starting acme-sh-aws-lambda-secret")

    # Get the domain name from the environment
    domains_string = os.environ.get("DOMAINS")
    if not domains_string:
        _logger.error("DOMAINS environment variable not set")
        return

    domains = domains_string.split(",")
    if len(domains) == 0:
        _logger.error("DOMAINS environment variable is empty")
        return

    _logger.info(f"Domains: {domains}")

    # get the aws secret name from the environment
    secret_name = os.environ.get("SECRET_NAME")
    if not secret_name:
        _logger.error("SECRET_NAME environment variable not set")
        return

    email = os.environ.get("EMAIL")
    if not email:
        _logger.error("EMAIL environment variable not set")
        return

    session = boto3.Session()

    # Access the credentials
    credentials = session.get_credentials()

    sts_client = boto3.client("sts")

    # Call the get_caller_identity method
    caller_identity = sts_client.get_caller_identity()

    _logger.info(
        f"AWS caller identity:\n{json.dumps(caller_identity, indent=4, sort_keys=True, default=str)}"
    )

    current_credentials = credentials.get_frozen_credentials()

    aws_access_key_id = current_credentials.access_key
    aws_secret_access_key = current_credentials.secret_key
    aws_session_token = current_credentials.token

    os.environ["AWS_ACCESS_KEY_ID"] = aws_access_key_id
    os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret_access_key
    os.environ["AWS_SESSION_TOKEN"] = aws_session_token
    _logger.info(f"Using temporary AWS_ACCESS_KEY_ID {aws_access_key_id}")

    # install the acme script
    _logger.info("Installing acme.sh")

    # create a temporary directories on /tmp
    os.system("mkdir -p /tmp/acme_sh")
    os.system("mkdir -p /tmp/certs")
    os.system("mkdir -p /tmp/data")
    os.chdir("/tmp/")

    os.system(
        f"/app/acme.sh --install-online --accountemail {email}  --no-profile  --force --home /tmp/acme_sh --cert-home /tmp/certs --config-home /tmp/data"
    )

    # start the acme.sh process as subprocess
    _logger.info("Starting acme.sh")

    domains_options = " ".join([f'-d "{domain}"' for domain in domains])
    commandline = f"/tmp/acme_sh/acme.sh --issue --server zerossl  {domains_options} --home /tmp/acme_sh --cert-home /tmp/certs --config-home /tmp/data --dns dns_aws --debug 1"

    return_code = run_command_with_streaming(commandline)
    _logger.info(f"Command finished with return code: {return_code}")

    # Define the base path to the acme.sh certificates
    base_path = "/tmp/certs"

    # Find all certificates and keys
    certs = find_certificates(base_path)
    if not certs:
        _logger.error("No certificates found")
        return {"message": "no certificates found"}

    # Create a Secrets Manager client
    secrets_manager_client = boto3.client("secretsmanager")

    cert_infos = []
    for domain in certs:
        for cert_file_name, cert_text in certs[domain].items():
            if cert_file_name.endswith(".cer"):
                if any([domain in cert_file_name for domain in domains]):
                    # Found a certificate for one of the domains

                    cert_info = get_cert_info(cert_text)
                    _logger.info(
                        f"Certificate info for {domain}/{cert_file_name}:\n{json.dumps(cert_info, indent=4, sort_keys=True, default=str)}"
                    )
                    cert_infos.append(cert_info)

    now_iso_date = datetime.now(timezone.utc).isoformat()
    tags = {"issued_at": now_iso_date}

    if len(cert_infos) > 0:
        first_cert_info = cert_infos[0]
        tags = {
            "Subject": first_cert_info["subject"],
            "Issuer": first_cert_info["issuer"],
            "NotBefore": first_cert_info["not_valid_before"],
            "NotAfter": first_cert_info["not_valid_after"],
            "SerialNumber": first_cert_info["serial_number"],
            "SignatureAlgorithm": first_cert_info["signature_algorithm"],
        }
        if "subject_alt_names" in first_cert_info:
            tags["SubjectAltNames"] = first_cert_info["subject_alt_names"]

    tags = streamline_tags(tags)

    # Create or update the secret
    create_or_update_secret(secrets_manager_client, secret_name, certs, tags=tags)

    cert_files = []
    for domain in certs:
        for cert_file in certs[domain]:
            cert_files.append(f"{domain}/{cert_file}")

    return {"message": "success", "cert_files": cert_files, "secret_name": secret_name}


class StdoutLogger:
    def __init__(self):
        pass

    def info(self, message):
        print(message)

    def error(self, message):
        print(message)

    def warning(self, message):
        print(message)

    def debug(self, message):
        print(message)


def handler(event, context):
    global _logger

    _logger = StdoutLogger()

    _logger.info(f"Running lambda handler, event: {event}, context: {context}")
    return run_acme()


def run_lambda():
    lambda_runtime_api_addr = os.environ["AWS_LAMBDA_RUNTIME_API"]
    app_root = os.environ.get("APP_ROOT", "/root")

    handler_name = "run.handler"
    _logger.info(
        f"Starting awslambdaric, app_root: {app_root}, lambda_runtime_api_addr: {lambda_runtime_api_addr} handler: {handler_name}"
    )
    run(app_root, handler_name, lambda_runtime_api_addr)


def main():
    if os.environ.get("AWS_LAMBDA_RUNTIME_API"):
        _logger.info("We are running in AWS Lambda")
        run_lambda()
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        run_acme()


if __name__ == "__main__":
    main()
