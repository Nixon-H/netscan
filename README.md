# NetScan v1.0: Comprehensive Bash Network Scanner

NetScan is a powerful, menu-driven bash script designed for active network enumeration and penetration testing. It acts as an interactive wrapper for common scanning tools like `nmap`, `tcpdump`, and `openssl`, consolidating multiple enumeration techniques into a single, robust, and user-friendly interface.

This tool is built with a focus on **robustness**, **session logging**, and **graceful cleanup**, ensuring that all processes are properly terminated and all session activity is recorded.

## ⚠️ Legal Disclaimer

> **Use this script only on networks you have authorization to scan.**
> Unauthorized scanning may violate local or organizational policies. The author is not responsible for any misuse or damage caused by this script. Always act ethically and within your legal and organizational boundaries.

-----

## 🚀 Core Features

  * **Menu-Driven Interface:** A simple, numbered menu for selecting different scan types.
  * **Host Discovery:** Enumerate live hosts using ICMP Ping Sweeps and ARP Scans.
  * **Port Scanning:** Scan for common and user-defined ports on discovered hosts.
  * **Service & OS Detection:** Perform in-depth OS fingerprinting and service version detection using `nmap -O -sV`.
  * **Banner Grabbing:** Connect to open ports to capture service banners using `netcat` and `openssl`.
  * **Packet Capture:** Automatically runs `tcpdump` during the full scan to capture all scan-related traffic to a `.pcap` file.
  * **Bandwidth Analysis:** Analyzes the generated `.pcap` file to report on data and bit rates using `capinfos`.
  * **Reverse DNS Lookup:** Performs a full CIDR-range reverse DNS (PTR) lookup.
  * **Data Export:** Save full scan results to clean, portable **CSV** and **JSON** formats.
  * **Robust Session Management:**
      * **Automatic Logging:** All console output (stdout and stderr) is automatically saved to a time-stamped log file in `/tmp/`.
      * **Graceful Cleanup:** A `trap` ensures that all background processes (like `tcpdump`) and temporary files are deleted on script exit (Ctrl+C, `exit`, or error).
      * **Strict Mode:** Runs under `set -euo pipefail` to exit immediately on errors or unset variables.

-----

## 🔧 Requirements & Dependencies

This script is designed for Debian-based systems (like Ubuntu, Kali, or ParrotOS) but can be adapted. It requires **root privileges** to run `nmap`'s privileged scans and `tcpdump`.

### Dependency List

The script will check for these dependencies and offer to install them via `apt` if they are missing:

  * **`nmap`**: The core engine for all host discovery and port scanning.
  * **`tcpdump`**: Used for packet capture during the full scan.
  * **`wireshark-utils` (for `capinfos`)**: Used to analyze the `.pcap` file.
  * **`dnsutils` (for `host`)**: Used for the reverse DNS lookup.
  * **`python3`**: Used for reliable CIDR validation (via the `ipaddress` module).
  * **`netcat-openbsd` (for `nc`)**: Used for banner grabbing.
  * **`openssl`**: Used for banner grabbing on SSL/TLS ports (e.fs., 443).
  * **`iproute2` (for `ip`)**: Used to auto-detect the default network interface and CIDR.
  * **`coreutils` (for `timeout`)**: Used to prevent banner grabs from hanging.

-----

## 🛠️ Installation & Usage

1.  **Download the script:**
    Save the code as `netscan.sh` (or any name you prefer).

2.  **Make it executable:**

    ```bash
    chmod +x netscan.sh
    ```

3.  **Run as root:**
    The script must be run with `sudo` or as the root user.

    ```bash
    sudo ./netscan.sh
    ```

The script will first check for root privileges, then check for all dependencies. If dependencies are missing, it will prompt you to install them. After a legal disclaimer, you will be presented with the main menu.

## 📜 Menu Options Explained

Here is a detailed breakdown of each menu option.

### 1\. Enumerate network hosts (ICMP Ping Sweep)

  * **What it does:** Performs a "ping sweep" of the target network.
  * **How it works:** Runs `nmap -sn -PE -n --ttl <TTL>` to send ICMP echo requests to every host in the CIDR range.
  * **Output:** A table of all **Active** IP addresses that responded.

### 2\. Enumerate network hosts (ARP Scan)

  * **What it does:** Discovers hosts on the **local subnet** by sending ARP requests. This is often more reliable than ICMP for local networks.
  * **How it works:** Runs `nmap -sn -PR -n -e <interface>` on the target CIDR.
  * **Output:** A table of **Active** IP addresses and their corresponding MAC addresses.

### 3\. Map hosts (ICMP & ARP)

  * **What it does:** Combines the results of Option 1 and Option 2 into a single, unified list.
  * **How it works:** Runs both `probe_icmp` and `probe_arp` functions and merges the results, noting which method (or both) found the host.
  * **Output:** A sorted table showing IP, MAC Address, and Discovery Method (ICMP, ARP, or ICMP/ARP).

### 4\. Full Scan: Map hosts & scan ports (nmap, CSV/JSON export)

This is the most comprehensive scanning option and is required to populate data for options 5 and 7.

  * **What it does:**
    1.  Starts a `tcpdump` process to capture all traffic for the target network.
    2.  Performs host discovery (both ICMP and ARP) to find live hosts.
    3.  Runs an `nmap` port scan (`nmap -p <ports> -T4`) against all live hosts.
    4.  Stops the `tcpdump` process, saving the capture to `/tmp/netscan_capture.pcap`.
    5.  Prompts you to save the results.
  * **Output:**
      * A console table of all hosts, their MACs, discovery methods, and open ports.
      * A `.pcap` file in `/tmp/`.
      * (Optional) A **CSV** file.
      * (Optional) A **JSON** file.

### 5\. Banner Grabbing (Run after Option 4)

  * **What it does:** Attempts to connect to open ports (found in Option 4) to identify the running service.
  * **How it works:**
      * It reads the `service_port_map` array populated by Option 4.
      * For HTTP ports (80, 8080), it sends a `GET / HTTP/1.1` request using `nc`.
      * For HTTPS ports (443, 8443), it sends the same request using `openssl s_client`.
      * For other ports (FTP, SSH, etc.), it sends a blank probe with `nc`.
  * **Output:** A table showing the IP, Port, and the first line of the service's banner/response.

### 6\. Reverse DNS Lookup (CIDR-accurate)

  * **What it does:** Iterates through **every single IP address** in a given CIDR range and performs a reverse DNS lookup.
  * **How it works:**
      * Uses an embedded Python script to generate the full list of IPs in the CIDR.
      * Pipes this list to a `while read` loop that runs `host <ip>`.
      * Parses the output for "pointer" (PTR) records.
  * **Output:** A table of IP addresses and their corresponding PTR domain names.

### 7\. Analyze Bandwidth of last scan (from Option 4)

  * **What it does:** Reads the `.pcap` file generated by Option 4 and provides high-level stats.
  * **How it works:** Runs `capinfos -i /tmp/netscan_capture.pcap` and greps for the "Data bit rate" line.
  * **Output:** The data/bit rate of the capture, showing the bandwidth used during the scan.

### 8\. OS & Service Detection (nmap -O -sV)

  * **What it does:** Performs an aggressive scan to determine the operating system and service versions of a target.
  * **How it works:** Runs `nmap -O -sV -T4 <target>`. This scan is **loud** and **slow** but provides highly detailed information.
  * **Output:** The raw, colorized output from `nmap`'s OS and service detection engine.

-----

## 📈 Output Formats

The script generates several types of output, stored in `/tmp/` or in the current directory.

### 1\. Session Log

  * **Location:** `/tmp/netscan_session_YYYYMMDD_HHMMSS.log`
  * **Format:** Plain text.
  * **Content:** A complete, un-colorized log of everything printed to the terminal (both commands and results) during the script's execution.

### 2\. Packet Capture (PCAP)

  * **Location:** `/tmp/netscan_capture.pcap`
  * **Format:** PCAP (Packet Capture)
  * **Content:** A full packet capture of the network traffic generated during the **Full Scan (Option 4)**. This file can be opened in tools like **Wireshark** or **tcpdump** for deep analysis.

### 3\. CSV Export (from Option 4)

  * **Location:** User-specified filename (e.g., `results.csv`)
  * **Format:** Comma-Separated Values
  * **Example:**
    ```csv
    IP,MAC,Method,Ports
    192.168.1.1,00:AA:BB:CC:DD:EE,ICMP/ARP,80,443
    192.168.1.10,00:11:22:33:44:55,ARP,22
    192.168.1.54,N/A,ICMP,
    ```

### 4\. JSON Export (from Option 4)

  * **Location:** User-specified filename (e.g., `results.json`)
  * **Format:** JSON
  * **Example:**
    ```json
    {
      "hosts": [
        {
          "ip": "192.168.1.1",
          "mac": "00:AA:BB:CC:DD:EE",
          "method": "ICMP/ARP",
          "open_ports": [
            "80",
            "443"
          ]
        },
        {
          "ip": "192.168.1.10",
          "mac": "00:11:22:33:44:55",
          "method": "ARP",
          "open_ports": [
            "22"
          ]
        },
        {
          "ip": "192.168.1.54",
          "mac": "N/A",
          "method": "ICMP",
          "open_ports": []
        }
      ]
    }
    ```

-----

## 🧠 Technical Deep Dive

This script includes several non-trivial components to ensure stability and accuracy.

  * **State Management:** The script uses Bash [associative arrays](https://www.gnu.org/software/bash/manual/html_node/Arrays.html) (`declare -A`) to maintain state. For example, `service_port_map` is populated by Option 4 and then read by Option 5. This state is cleared at the beginning of each "Full Scan."
  * **CIDR & IP Validation:** To avoid errors with `nmap` and ensure accurate logic, the script uses a Python 3 "here-document" to leverage the `ipaddress` module. This is far more reliable than any regex-based validation in pure Bash.
  * **Nmap Grepable Output (`-oG`):** The script parses `nmap`'s machine-readable `-oG` format. This format is piped to `awk` and `sed` to extract live IPs, MAC addresses, and open ports, which are then stored in the associative arrays.
  * **Robust Cleanup:** The `trap cleanup EXIT INT TERM` command is critical. It ensures that if the user presses `Ctrl+C` (INT) or the script exits for any reason (EXIT, TERM), the `cleanup()` function is *always* called. This function's primary job is to find the PID of the backgrounded `tcpdump` process and kill it, preventing a zombie `tcpdump` process from consuming resources.
  * **Spinner & Concurrency:** The `spinner()` function provides a visual indication of progress. It takes the Process ID (PID) of the backgrounded `nmap` scan (`$!`) and loops while `kill -0 "$pid"` (which checks if the process exists) is true, creating a non-blocking UI.
