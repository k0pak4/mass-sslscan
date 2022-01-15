# mass-sslscan

Mass SSL Scan is used to run SSLScan against a large number of targets, outputting it into a format that can be used in reporting.

## Installation

1. Clone this repository.
2. Install sslscan on your system.
    
## Usage

### Positional Arguments

#### filename
The output filename for the resulting data.
    
#### targets
A comma separated list of hosts and ports. If no port is given, port 443 is defaulted

### Optional Arguments

#### format
Supported formats are `csv`. Defaults to `csv`.

## Example Usage
python3 mass_sslscan.py internal_scan.csv 192.168.0.231,192.168.10.100:25 --format csv