# Python Ethical Hacking

## Brute Force, Packet Analyzer, Port Scanner, Sniffer Network, Web Scraper


## Brute Force:
This script performs a brute-force attack on a login form by iterating through a list of usernames and passwords.

### Usage:
Run the script in the terminal with the following format:
```bash
python brute_force.py <URL_FORM_LOGIN> <username1> <username2> <password_list.txt> --username_field <username_field> --password_field <password_field> -d <delay_in_seconds>
```
### Arguments:
- <URL_FORM_LOGIN>: The URL of the login form to target.
- <username1>, <username2>, ...: List of usernames to test.
- <password_list.txt>: Path to a text file containing passwords to test.
- --username_field <username_field>: The field name for the username in the login form (default: "username").
- --password_field <password_field>: The field name for the password in the login form (default: "password").
- -d <delay_in_seconds>: Optional delay between login attempts to avoid detection (default: 0).

- Example:
1. Brute force a login form at http://example.com/login using admin as a username:
```bash
python brute_force.py http://example.com/login admin user.txt --username_field email --password_field pass -d 0.5
```
### Notes:
- Replace <URL_FORM_LOGIN> with the target login form URL.
- Ensure the --username_field and --password_field match the field names in the HTML form.
- Use a delay (-d) to avoid triggering security measures such as rate limiting or IP blocking.


## Packet Analyzer:
1. Basic usage with a PCAP file:

```bash
python3 packet_analyzer.py /path/to/capture.pcap
```
(Replace "/path/to/capture.pcap" with the actual path to your PCAP file.)

2. Running with a PCAP file in the current directory:

```bash
python3 packet_analyzer.py capture.pcap
```
(This assumes the capture.pcap file is in the same directory as the script.)

3. Running with a log level (DEBUG) and saving output to a file (output.log):

```bash
python3 packet_analyzer.py capture.pcap -l DEBUG -o output.log
```
(This sets the log level to DEBUG and saves logs to output.log.)


## Port Scanner

1. Scan specific ports:

```bash
python3 scan_port.py 192.168.1.1 -p 22,80,443
```
Description: Scans ports 22, 80, and 443 on the target IP address.

2. Scan a range of ports:

```bash
python3 scan_port.py 192.168.1.1 -p 1-1000
```
Description: Scans all ports in the range from 1 to 1000 on the target IP address.

3. Scan all ports (default behavior):

```bash
python3 scan_port.py 192.168.1.1
```
Description: Scans all possible ports (0–65535) on the target IP address.

4. Use threads for faster scanning:

```bash
python3 scan_port.py 192.168.1.1 -t 200
```
Description: Uses 200 threads to perform the scan, speeding up the process.

### Notes:
- Replace 192.168.1.1 with the IP address of the target machine.
- The -p option specifies which ports to scan. Use commas for specific ports or a dash for ranges.
- The -t option defines the number of threads to use for scanning.


## Sniffer Network
### Basic usage:
```bash
python3 sniffer_network.py -i <interface>
```
Example 1: Sniff packets on interface 'eth0':

```bash
python3 sniffer_network.py -i eth0
```
Example 2: Sniff packets on interface 'enp0s3':

```bash
python3 sniffer_network.py -i enp0s3
```
### Optional arguments:
- -c, --count <number>: Number of packets to sniff (default: unlimited)
- -f, --filter <BPF>: Apply a BPF filter to sniff specific packets (e.g., "tcp", "port 80")

- Examples with optional arguments:
1. Sniff packets on interface 'wlan0', limited to 100 packets:

```bash
python3 sniffer_network.py -i wlan0 -c 100
```
Sniff TCP packets on interface 'eth0':

```bash
python3 sniffer_network.py -i eth0 -f "tcp"
```
Sniff packets on port 80 using interface 'wlan0':

```bash
python3 sniffer_network.py -i wlan0 -f "port 80"
```
### Notes:
1. Replace <interface> with the name of the network interface (e.g., eth0, wlan0, lo, etc.).
2. Use ifconfig or ip link show to check available network interfaces.
3. Run the script with sudo for permission to sniff network traffic:

```bash
sudo python3 sniffer_network.py -i eth0
```


## Web Scraper
### Basic usage:
```bash
python3 web_scraper.py <url>
```
Example 1: Scrape a webpage:

```bash
python3 web_scraper.py https://example.com
```
Example 2: Access a login page on a server:

```bash
python3 web_scraper.py <ip_address>/<login_page>
```

```bash
python3 web_scraper.py http://example.com/login
```
### Notes:
1. Replace <url> with the full URL of the webpage you want to scrape.
2. Replace <ip_address>/<login_page> with the appropriate IP address or domain and login page path.
3. Ensure you have a stable internet connection and permissions to access the target URL.

