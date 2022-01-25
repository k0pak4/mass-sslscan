"""A module to run SSLScan against a list of targets and output it into a reportable format"""
import argparse
import csv
from datetime import datetime
import re
import sys

import pexpect

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
WEAK_CIPHERS = ["RC4-SHA", "RC4-MD5", "DES-CBC3-SHA", "DHE-RSA-DES-CBC3-SHA"]
WEAK_SIGNATURE_ALGORITHMS = ["rsa_pkcs1_sha1", "rsa_pkcs1_sha224", "dsa_sha1", "ecdsa_sha1",
                             "dsa_sha224", "dsa_sha256", "dsa_sha384", "dsa_sha512", "all signature algorithms"]

def escape_ansi(line):
    """Remove ansi codes from the terminal output"""
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

def parse_sslscan_output(output):
    """Parse the results of running SSLScan, gathering weak configurations"""
    # Store all weak configurations
    weak_configs = []

    try:
        # Parse Weak Protocols
        protocols = re.search(r"SSL/TLS Protocols:[\s\S.]*TLS Fallback SCSV:", output)[0]
        for proto in WEAK_PROTOCOLS:
            if re.search(rf"{proto}([^disabled]*)enabled", protocols):
                weak_configs.append(proto)
    except:
        pass
    try:
        # Parse Weak Ciphers
        ciphers = re.search(r"Supported Server Cipher[\s\S.]*Server Signature Algorithm", output)[0]
        for ciph in WEAK_CIPHERS:
            if re.search(f"{ciph}", ciphers):
                weak_configs.append(ciph)
    except:
        pass
    try:
        # Parse Weak Signature Algorithms
        algorithms = re.search(r"Server Signature Algorithm[\s\S.]*SSL Certificate", output)[0]
        for algo in WEAK_SIGNATURE_ALGORITHMS:
            # Match against no trailing digits so alg_1 doesn't match alg_128
            if re.search(rf"{algo}[^0-9]", algorithms):
                weak_configs.append(algo)
    except:
        pass
    try:
        # Parse Expired Certificate
        expire_date_string = escape_ansi(re.search(r"after:[\s\S.]*", output)[0]).split('after:')[1].strip()
        expire_date = datetime.strptime(expire_date_string, '%b %d %H:%M:%S %Y GMT')
        if datetime.now() > expire_date:
            weak_configs.append("Expired Certificate")
    except:
        pass
    try:
        # Parse Self-Signed Certificate
        issuer_string = re.search(r"Issuer:[\s\S.]*Not", output)[0]
        if '\x1b[31m' in issuer_string:
            weak_configs.append("Self Signed Certificate")
    except Exception as exc:
        print(f"exceptioin: {exc}")
        pass
    return weak_configs


def single_scan(target):
    """ Run SSLScan against a single target, returning its results"""

    # Run SSLScan in a sub process
    sys.stdout.write(f"[+] Running SSLScan against {target}...")
    sys.stdout.flush()
    if target.endswith(":21"):
        cmdline = f"sslscan --starttls-ftp --show-sigs {target}"
    elif target.endswith(":25"):
        cmdline = f"sslscan --starttls-smtp --show-sigs {target}"
    else:
        cmdline = f"sslscan --show-sigs {target}"
    process_result = pexpect.spawnu(cmdline, timeout=300)
    output = process_result.read()

    # Parse the results of running SSLScan
    result = parse_sslscan_output(output)

    sys.stdout.write("Done!\n")
    return result


def create_output(results, findings, output_filename, output_format='csv'):
    """Create output and save it in the specified format"""
    if output_format != 'csv':
        print(f"[-] Error: Only supported output format is CSV: {output_format}")
        sys.exit(1)

    # Sort the Findings so we can ensure the same results
    findings = list(sorted(findings))

    with open(output_filename, 'w') as csv_file:
        csv_writer = csv.writer(csv_file)

        # Write the Header
        columns = findings.copy()
        columns.insert(0, 'Host')
        csv_writer.writerow(columns)

        # Write each target's row, sorted by IP Address
        for target in sorted(results):
            # Write this target's row
            row = [target]
            for finding in findings:
                row.append('x') if finding in results[target] else row.append('')
            csv_writer.writerow(row)
    print(f"[+] Successfully wrote SSLScan findings to {output_filename}!")

def main():
    """Parse the arguments and run SSLScan against the targets"""

    # Parse required arguments to generate the list of targets and output configurations
    parser = argparse.ArgumentParser(
        description='Run SSLScan against multiple targets, reporting their weak configurations')
    parser.add_argument('filename', help="The output filename")
    parser.add_argument('targets',
                    help='comma separated list of targets in host:port form with default port 443')
    parser.add_argument('--format', default='csv',
                        help='The output format to display and save results in, defaults to csv')
    args = parser.parse_args()
    output_filename = args.filename
    output_format = args.format
    targets = args.targets.split(',')

    # Run SSLScan against every provided target, storing the results
    results_map = {}
    findings = set()
    for target in targets:
        result = single_scan(target.strip())
        findings.update(result)
        results_map[target] = result

    # Output the results to the desired format
    create_output(results_map, findings, output_filename, output_format)

if __name__ == "__main__":
    main()
