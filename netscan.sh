#!/bin/bash

# --- 1. Set script to be robust ---
# -e: exit on error
# -u: exit on unset variables
# -o pipefail: exit on pipeline failures
set -euo pipefail

# --- 7. Clean-up Trap ---
# (Must be defined early)
cleanup() {
  echo -e "\n\n🧹 Cleaning up any running processes and temp files..."
  # Use safe check for unset var (due to set -u) and safer kill
  if [ -n "${CAPTURE_PROCESS_ID:-}" ] && ps -p "$CAPTURE_PROCESS_ID" >/dev/null 2>&1; then
      echo "Stopping tcpdump (PID $CAPTURE_PROCESS_ID)..."
      kill "$CAPTURE_PROCESS_ID" || true # Add || true to prevent exit on error if PID just died
  fi
  
  # Remove all temp files (fixed pattern)
  rm -f /tmp/netscan_* 2>/dev/null || true
  echo "Done. Exiting."
}
trap cleanup EXIT INT TERM

# --- 5. Session Logging ---
LOG_FILE="/tmp/netscan_session_$(date +%Y%m%d_%H%M%S).log"
# Redirect stdout and stderr to a log file AND the console
exec &> >(tee -a "$LOG_FILE")
echo "--- Network Scanner v1.0 Session Start ---"
echo "Session log being saved to $LOG_FILE"


# --- 3. Colorized Output Definitions ---
C_GREEN='\033[1;32m'
C_RED='\033[1;31m'
C_NC='\033[0m' # No Color

# --- Root Privilege Check (Moved Earlier) ---
if [[ $EUID -ne 0 ]]; then
   # --- FIX: Switched to printf for reliable color output ---
   printf "%b\n" "${C_RED}This script must be run as root. Please run with sudo or as root.${C_NC}"
   exit 1
fi

# --- 4. Install Helper / Dependency Check (Non-Recursive) ---
MISSING_DEPS=()
check_dependencies() {
  echo "Checking dependencies..."
  MISSING_DEPS=()
  # 'timeout' is in 'coreutils', which should always be present.
  local deps=(nmap tcpdump capinfos host awk sed grep ip python3 nc openssl timeout)
  for d in "${deps[@]}"; do
    if ! command -v "$d" &>/dev/null; then
      MISSING_DEPS+=("$d")
    fi
  done
  [ ${#MISSING_DEPS[@]} -gt 0 ] && return 1 || return 0
}

install_dependencies() {
    # --- FIX: Switched to printf for reliable color output ---
    printf "%b\n" "${C_RED}Error: Missing required dependencies: ${MISSING_DEPS[*]}${C_NC}"
    read -p "Attempt to install them now? (y/n): " install_confirm
    if [[ "$install_confirm" =~ ^[Yy]$ ]]; then
        if command -v apt &>/dev/null; then
            echo "Attempting install with apt (Debian/Ubuntu)..."
            local packages=()
            for d in "${MISSING_DEPS[@]}"; do
                case "$d" in
                    nmap) packages+=("nmap");;
                    tcpdump) packages+=("tcpdump");;
                    capinfos) packages+=("wireshark-utils");;
                    host) packages+=("dnsutils");;
                    python3) packages+=("python3");;
                    ip) packages+=("iproute2");;
                    nc) packages+=("netcat-openbsd");;
                    openssl) packages+=("openssl");;
                    timeout) packages+=("coreutils");;
                    *) echo "Don't know how to install '$d'. Skipping.";;
                esac
            done
            if [ ${#packages[@]} -gt 0 ]; then
                # No 'sudo' needed, script is already root
                apt update
                apt install -y "${packages[@]}"
            fi
        else
            # --- FIX: Switched to printf for reliable color output ---
            printf "%b\n" "${C_RED}Could not find 'apt'. Please install dependencies manually (e.g., nmap, wireshark-utils, dnsutils, netcat-openbsd, openssl).${C_NC}"
            return 1
        fi
    else
        echo "Please install dependencies and re-run."
        return 1
    fi
    return 0
}

# --- Run Dependency Checks ---
if ! check_dependencies; then
    if ! install_dependencies; then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}Installation failed or was skipped. Exiting.${C_NC}"
        exit 1
    fi
    # Re-check after install attempt
    if ! check_dependencies; then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}Dependencies still missing: ${MISSING_DEPS[*]}. Exiting.${C_NC}"
        exit 1
    fi
fi
echo "All dependencies satisfied."


# --- Legal Disclaimer ---
# --- FIX: Switched to printf for reliable color output ---
printf "%b\n" "\n\033[1;33m⚠️  WARNING: Use this script only on networks you have authorization to scan.\033[0m"
echo "Unauthorized scanning may violate local or organizational policies."
read -p "Do you wish to continue? (y/n): " consent
[[ "$consent" =~ ^[Yy]$ ]] || { echo "Exiting."; exit 0; }

# --- QoL: Auto-detect local CIDR ---
get_local_cidr() {
  ip -o -f inet addr show | awk '/scope global/ {print $4; exit}'
}

# --- Progress Indicators: Spinner ---
# --- FIX 1: All output redirected to stderr (>&2) ---
spinner() {
  local pid=$1
  local spin='-\|/'
  local i=0
  echo -n " " >&2 # Initial space
  sleep 0.05 # Prevent spinner flash on fast commands
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) %4 ))
    printf "\r[%s] Scanning..." "${spin:$i:1}" >&2
    sleep .2
  done
  echo -e "\r[+] Scan complete.     " >&2
}

# --- Input Validation ---

# --- (CRITICAL SYNTAX FIX) Python-backed CIDR validation ---
validate_cidr() {
  # The here-document (<<PY ... PY) must come *immediately* after the command.
  if python3 - "$1" <<PY
import sys, ipaddress
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
  then
    # Python exited with 0 (success)
    return 0
  else
    # Python exited with 1 (failure)
    # --- FIX: Switched to printf for reliable color output ---
    printf "%b\n" "${C_RED}Invalid CIDR: $1${C_NC}"
    return 1
  fi
}

validate_ports() {
  local ports="$1"
  if [[ -n "$ports" && ! "$ports" =~ ^[0-9,-]+$ ]]; then
    # --- FIX: Switched to printf for reliable color output ---
    printf "%b\n" "${C_RED}Invalid port list. Use numbers separated by commas (e.g., 80,443,1000-2000).${C_NC}"
    return 1
  fi
  return 0
}

# --- Filename validation ---
validate_filename() {
    local fname="$1"
    if [[ -z "$fname" ]]; then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}Filename cannot be empty.${C_NC}"
        return 1
    fi
    if [[ "$fname" =~ [/\\] ]]; then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}Filename cannot contain path separators.${C_NC}"
        return 1
    fi
    if [[ "$fname" =~ ^\. ]]; then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}Filename cannot start with a dot.${C_NC}"
        return 1
    fi
    return 0
}

is_ip_or_cidr() {
  local t="$1"
  # Regex for CIDR or a single IP
  if [[ "$t" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]{1,2}))?$ ]]; then return 0; fi
  return 1
}

# --- Utility Function: Check if IP is in CIDR ---
check_ip_in_cidr() {
  # Pass arguments to python script
  python3 - "$1" "$2" <<PY
import sys, ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    addr = ipaddress.ip_address(sys.argv[2])
    sys.exit(0 if addr in net else 1)
except Exception:
    sys.exit(1) # Fail closed if invalid input
PY
  # The function's return code will be Python's exit code
}

# --- Utility Functions ---

# --- Robust error handling ---
detect_iface() {
  # Handle unset variable with set -u
  if [ -n "${NET_IFACE:-}" ]; then
    echo "$NET_IFACE"
    return 0
  fi
  local default_iface
  default_iface=$(ip -o -4 route show to default | awk '{print $5; exit}')
  
  if [ -z "$default_iface" ]; then
    echo "ERROR: Could not detect default network interface." >&2
    return 1 # Fail with exit code
  else
    echo "$default_iface" # Print to stdout on success
    return 0
  fi
}


# --- Global Configuration ---
DEFAULT_CIDR=$(get_local_cidr)
[ -z "$DEFAULT_CIDR" ] && DEFAULT_CIDR="192.168.1.0/24" # Fallback
CAPTURE_PROCESS_ID="" # PID tracking for cleanup
declare -a COMMON_PORTS=(22 80 443 139 445)

# --- Global State Arrays ---
declare -A host_registry
declare -A service_port_map
declare -A mac_addresses

# --- Core Scan Functions ---

# --- Signature fixed, packet_size removed ---
probe_icmp() {
    local cidr_block="$1"
    local time_to_live="$2"
    local icmp_results_file
    icmp_results_file=$(mktemp /tmp/netscan_icmp.XXXXXX)
    chmod 600 "$icmp_results_file" # Set secure permissions

    echo "Running nmap ICMP scan... (nmap -PE -sn --ttl $time_to_live $cidr_block)" >&2

    (nmap -sn -PE -n --ttl "$time_to_live" "$cidr_block" -oG - | awk '/Status: Up$/{print $2}' > "$icmp_results_file") &
    local nmap_pid=$!
    spinner $nmap_pid
    wait $nmap_pid

    echo "$icmp_results_file"
}

# --- FINAL FIX: Replaced function with correct parser ---
probe_arp() {
    local cidr_block="$1"
    local arp_results_file
    arp_results_file=$(mktemp /tmp/netscan_arp.XXXXXX)
    chmod 600 "$arp_results_file" # Set secure permissions
    local iface
    # --- Use new exit-code check ---
    if ! iface=$(detect_iface); then
        return 1 # Error already printed by detect_iface
    fi

    echo "Running nmap ARP scan... (nmap -PR -sn -e $iface $cidr_block)" >&2

    # --- NEW FIX: Use a single, correct awk command to parse IP and MAC field ---
    # This finds "Status: Up", prints $2 (IP), and then searches for "MAC: <addr>"
    # If it finds a MAC, it prints it. If not, it prints an empty string.
    (nmap -sn -PR -n -e "$iface" "$cidr_block" -oG - | \
      awk '/Status: Up$/ { 
          ip=$2; 
          mac=""; 
          if(match($0, /MAC: ([0-9A-Fa-f:]+)/, a)) { 
              mac=a[1] 
          }; 
          print ip, mac 
      }' > "$arp_results_file") &
    
    local nmap_pid=$!
    spinner $nmap_pid
    wait $nmap_pid
    
    echo "$arp_results_file"
}


# --- Main Menu Task Functions ---

# Task 1: Enumerate all machines on the network using ICMP protocol
task_run_icmp_sweep() {
    local start_time=$(date +%s)
    local network ttl results_file ip
    read -p "Enter target network (CIDR format) [default: $DEFAULT_CIDR]: " network
    network=${network:-$DEFAULT_CIDR}
    if ! validate_cidr "$network"; then return 1; fi

    read -p "Enter ICMP TTL (Time to Live) [default: 64]: " ttl
    ttl=${ttl:-64}

    results_file=$(probe_icmp "$network" "$ttl") # Updated call

    echo "+-----------------+--------+"
    echo "| IP Address      | Status |"
    echo "+-----------------+--------+"
    while read -r ip; do
        printf "| %-15s | ${C_GREEN}Active${C_NC} |\n" "$ip"
    done <"$results_file"
    echo "+-----------------+--------+"

    rm "$results_file"
    local end_time=$(date +%s)
    echo "ICMP enumeration complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}

# Task 2: Enumerate all machines on the network using ARP protocol
task_run_arp_sweep() {
    local start_time=$(date +%s)
    local network results_file ip mac
    read -p "Enter target network (CIDR format) [default: $DEFAULT_CIDR]: " network
    network=${network:-$DEFAULT_CIDR}
    if ! validate_cidr "$network"; then return 1; fi

    if ! results_file=$(probe_arp "$network"); then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}ARP scan failed, likely could not detect interface.${C_NC}"
        return 1
    fi

    echo "+-----------------+-------------------+--------+"
    echo "| IP Address      | MAC Address       | Status |"
    echo "+-----------------+-------------------+--------+"
    while IFS=' ' read -r ip mac; do
        # --- NEW FIX: Also skip if MAC is an empty string ---
        if [ -z "$ip" ] || [ -z "$mac" ] || [ "$mac" == "Nmap" ]; then 
            continue
        fi
        printf "| %-15s | %-17s | ${C_GREEN}Active${C_NC} |\n" "$ip" "$mac"
    done <"$results_file"
    echo "+-----------------+-------------------+--------+"

    rm "$results_file"
    local end_time=$(date +%s)
    echo "ARP enumeration complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}

# Task 3: Enumerate and map machines on the network based on ICMP and ARP
task_run_combined_map() {
    local start_time=$(date +%s)
    declare -A discovered_hosts
    local k network ttl icmp_data_file arp_data_file ip mac
    
    # Clear global associative array properly
    for k in "${!mac_addresses[@]}"; do unset 'mac_addresses[$k]'; done

    read -p "Enter target network (CIDR format) [default: $DEFAULT_CIDR]: " network
    network=${network:-$DEFAULT_CIDR}
    if ! validate_cidr "$network"; then return 1; fi

    read -p "Enter ICMP TTL [default: 64]: " ttl
    ttl=${ttl:-64}

    icmp_data_file=$(probe_icmp "$network" "$ttl") # Updated call
    
    if ! arp_data_file=$(probe_arp "$network"); then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}ARP scan failed, likely could not detect interface.${C_NC}"
        rm "$icmp_data_file" # Clean up the file we already made
        return 1
    fi

    while read -r ip; do
        discovered_hosts["$ip"]="ICMP"
    done <"$icmp_data_file"

    while IFS=' ' read -r ip mac; do
        # --- NEW FIX: Also skip if MAC is an empty string ---
        if [ -z "$ip" ] || [ -z "$mac" ] || [ "$mac" == "Nmap" ]; then continue; fi
        mac_addresses["$ip"]="$mac" # Store in global map
        if [ -n "${discovered_hosts["$ip"]:-}" ]; then
            discovered_hosts["$ip"]="ICMP/ARP"
        else
            discovered_hosts["$ip"]="ARP"
        fi
    done <"$arp_data_file"

    rm "$icmp_data_file" "$arp_data_file"

    echo "Network Mapping Results:"
    echo "+-----------------+-------------------+----------+--------+"
    echo "| IP Address      | MAC Address       | Method   | Status |"
    echo "+-----------------+-------------------+----------+--------+"
    
    local -a _sorted_ips
    mapfile -t _sorted_ips < <(printf '%s\n' "${!discovered_hosts[@]}" | sort -V)
    for ip in "${_sorted_ips[@]}"; do
        printf "| %-15s | %-17s | %-8s | ${C_GREEN}Active${C_NC} |\n" "$ip" "${mac_addresses["$ip"]:-N/A}" "${discovered_hosts["$ip"]}"
    done
    echo "+-----------------+-------------------+----------+--------+"
    
    local end_time=$(date +%s)
    echo "Combined map complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}

# Task 4: Enumerate well-known ports on each machine and map them
task_run_port_scan() {
    local start_time=$(date +%s)
    local pcap_path="/tmp/netscan_capture.pcap"
    rm -f "$pcap_path"

    local iface_to_capture
    if ! iface_to_capture=$(detect_iface); then
        return 1
    fi
    
    local k network ttl common_ports_str extra_ports
    local full_port_list icmp_data_file arp_data_file nmap_results_file
    local nmap_pid line ip open_ports save outfile save_json outfile_json
    local first ports ports_json p_arr i
    declare -A discovered_hosts
    declare -A host_open_ports
    
    # Clear global associative arrays properly
    for k in "${!host_registry[@]}"; do unset 'host_registry[$k]'; done
    for k in "${!service_port_map[@]}"; do unset 'service_port_map[$k]'; done
    for k in "${!mac_addresses[@]}"; do unset 'mac_addresses[$k]'; done

    read -p "Enter target network (CIDR format) [default: $DEFAULT_CIDR]: " network
    network=${network:-$DEFAULT_CIDR}
    if ! validate_cidr "$network"; then return 1; fi

    # --- (FIX 1) Start tcpdump AFTER getting network and WITH the filter ---
    echo "Starting packet capture for network: $network"
    tcpdump -i "$iface_to_capture" -w "$pcap_path" "net $network" >/dev/null 2>&1 &
    CAPTURE_PROCESS_ID=$! # Assign PID right after launch

    read -p "Enter ICMP TTL [default: 64]: " ttl
    ttl=${ttl:-64}

    common_ports_str=$(IFS=,; echo "${COMMON_PORTS[*]}")
    echo "Default ports to scan: $common_ports_str"
    read -p "Enter additional ports (e.g., 8080,1000-2000) [press Enter for none]: " extra_ports
    if ! validate_ports "$extra_ports"; then return 1; fi
    
    full_port_list="$common_ports_str"
    if [ -n "$extra_ports" ]; then
        full_port_list="$full_port_list,$extra_ports"
    fi

    echo "Running host discovery..."
    icmp_data_file=$(probe_icmp "$network" "$ttl") # Updated call
    
    if ! arp_data_file=$(probe_arp "$network"); then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}ARP scan failed, likely could not detect interface.${C_NC}"
        rm "$icmp_data_file"
        return 1
    fi

    while read -r ip; do
        discovered_hosts["$ip"]="ICMP"
        host_registry["$ip"]="ICMP"
    done <"$icmp_data_file"

    while IFS=' ' read -r ip mac; do
        # --- NEW FIX: Also skip if MAC is an empty string ---
        if [ -z "$ip" ] || [ -z "$mac" ] || [ "$mac" == "Nmap" ]; then continue; fi
        mac_addresses["$ip"]="$mac"
        if [ -n "${discovered_hosts["$ip"]:-}" ]; then
            discovered_hosts["$ip"]="ICMP/ARP"
            host_registry["$ip"]="ICMP/ARP"
        else
            discovered_hosts["$ip"]="ARP"
            host_registry["$ip"]="ARP"
        fi
    done <"$arp_data_file"

    rm "$icmp_data_file" "$arp_data_file"

    echo "Scanning ports on discovered hosts (using nmap)..."
    nmap_results_file=$(mktemp /tmp/netscan_nmap_ports.XXXXXX)
    chmod 600 "$nmap_results_file" # Set secure permissions
    declare -a target_ips=("${!discovered_hosts[@]}")

    if [ ${#target_ips[@]} -gt 0 ]; then
        (nmap -p "$full_port_list" -T4 -n -oG - "${target_ips[@]}" > "$nmap_results_file") &
        nmap_pid=$!
        spinner $nmap_pid
        wait $nmap_pid
    else
        echo "No hosts discovered, skipping port scan."
        touch "$nmap_results_file"
    fi

    for ip in "${target_ips[@]}"; do
        host_open_ports["$ip"]=""
        service_port_map["$ip"]=""
    done

    while read -r line; do
        if [[ "$line" == *"Ports:"* && "$line" == *"/open/"* ]]; then
            ip=$(echo "$line" | awk '{print $2}')
            open_ports=$(echo "$line" | sed 's/.*Ports: //' | \
                         grep -oE '[0-9]+/open/' | \
                         awk -F'/' '{print $1}' | \
                         paste -sd ',' -)
            
            if [ -n "$open_ports" ]; then
                host_open_ports["$ip"]=$open_ports
                service_port_map["$ip"]=$open_ports
            fi
        fi
    done < "$nmap_results_file"
    rm "$nmap_results_file"

    # Stop tcpdump
    if [ -n "${CAPTURE_PROCESS_ID:-}" ] && ps -p "$CAPTURE_PROCESS_ID" >/dev/null 2>&1; then
        kill "$CAPTURE_PROCESS_ID" || true
    fi
    # --- (CRASH FIX) Add '|| true' to prevent 'set -e' from exiting ---
    wait "$CAPTURE_PROCESS_ID" 2>/dev/null || true
    CAPTURE_PROCESS_ID="" # Clear PID

    echo "Mapping Results with Port Scan:"
    echo "+-----------------+-------------------+----------+----------------------+--------+"
    echo "| IP Address      | MAC Address       | Method   | Open Ports           | Status |"
    echo "+-----------------+-------------------+----------+----------------------+--------+"
    
    local -a _sorted_ips
    mapfile -t _sorted_ips < <(printf '%s\n' "${!discovered_hosts[@]}" | sort -V)
    for ip in "${_sorted_ips[@]}"; do
        printf "| %-15s | %-17s | %-8s | %-20s | ${C_GREEN}Active${C_NC} |\n" "$ip" "${mac_addresses["$ip"]:-N/A}" "${discovered_hosts["$ip"]:-N/A}" "${host_open_ports["$ip"]:-}"
    done
    echo "+-----------------+-------------------+----------+----------------------+--------+"
    echo "Packet capture saved to $pcap_path"

    # --- CSV Export ---
    read -p "Save results to CSV file? (y/n): " save
    if [[ "$save" =~ ^[Yy]$ ]]; then
      read -p "Enter filename (e.g., results.csv): " outfile
      if validate_filename "$outfile"; then
        echo "IP,MAC,Method,Ports" > "$outfile"
        for ip in "${_sorted_ips[@]}"; do
          echo "$ip,${mac_addresses["$ip"]:-N/A},${discovered_hosts["$ip"]:-N/A},${host_open_ports["$ip"]:-}" >> "$outfile"
        done
        echo "CSV Results saved to $outfile"
      else
        echo "Invalid filename. Skipping CSV save."
      fi
    fi

    # --- Corrected JSON Export ---
    read -p "Save results to JSON file? (y/n): " save_json
    if [[ "$save_json" =~ ^[Yy]$ ]]; then
      read -p "Enter filename (e.g., results.json): " outfile_json
      if validate_filename "$outfile_json"; then
        {
          echo "{"
          echo '  "hosts": ['
          first=true
          for ip in "${_sorted_ips[@]}"; do
            # build JSON array for ports
            ports="${host_open_ports["$ip"]:-}"
            if [ -z "$ports" ]; then
              ports_json="[]"
            else
              # convert "80,443" -> ["80","443"]
              IFS=',' read -ra p_arr <<<"$ports"
              ports_json='['
              for i in "${!p_arr[@]}"; do
                [[ $i -gt 0 ]] && ports_json+=','
                ports_json+="\"${p_arr[$i]}\""
              done
              ports_json+=']'
            fi

            # ensure comma separation between objects
            if $first; then
              first=false
            else
              echo ","
            fi

            printf '    {"ip":"%s","mac":"%s","method":"%s","open_ports":%s}' \
              "$ip" "${mac_addresses["$ip"]:-N/A}" "${host_registry["$ip"]:-N/A}" "$ports_json"
          done
          echo
          echo "  ]"
          echo "}"
        } > "$outfile_json"
        echo "JSON results saved to $outfile_json"
      else
        echo "Invalid filename. Skipping JSON save."
      fi
    fi

    local end_time=$(date +%s)
    echo "Full scan complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}

# Task 5: Banner Grabbing
task_grab_banners() {
    local start_time=$(date +%s)
    # New, expanded list of ports for banner grabbing
    local PORTS_FOR_BANNER_GRAB=(21 22 25 80 110 143 443 465 587 993 995 3306 5432 8080 8443)
    local scan_target ip ip_address service_banner port
    declare -a ports_to_check
    
    if [ ${#service_port_map[@]} -eq 0 ]; then
        echo "Please run Option 4 (Port Scan) first to populate the list of open ports."
        read -p "Press [Enter] to return to the main menu..."
        return
    fi
    
    read -p "Enter IP or network to scan [default: $DEFAULT_CIDR]: " scan_target
    scan_target=${scan_target:-$DEFAULT_CIDR}
    if [ -z "$scan_target" ]; then echo "Invalid target."; return 1; fi

    echo "Grabbing banners... (This may take a moment)"
    echo "+---------------------+------+----------------------------------------------+"
    echo "| IP Address          | Port | Banner (first 5 lines)                       |"
    echo "+---------------------+------+----------------------------------------------+"

    if [[ "$scan_target" =~ "/" ]]; then
        for ip in "${!service_port_map[@]}";
        do
            # Use new, correct CIDR check
            if ! check_ip_in_cidr "$scan_target" "$ip"; then
                continue
            fi
            
            IFS=',' read -ra ports_to_check <<<"${service_port_map["$ip"]:-}"
            for port in "${ports_to_check[@]}"; do
                if [[ ! " ${PORTS_FOR_BANNER_GRAB[@]} " =~ " $port " ]]; then continue; fi
                
                if [[ "$port" =~ ^(80|443|8080|8443)$ ]]; then
                    if [[ "$port" =~ ^(443|8443)$ ]]; then
                        service_banner=$(echo "GET / HTTP/1.1\r\nHost: $ip\r\n\r\n" | \
                                         timeout 2 openssl s_client -connect "$ip:$port" -quiet 2>&1 | \
                                         head -n 5)
                    else
                        service_banner=$(printf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "$ip" | \
                                         nc -w 2 "$ip" "$port" 2>&1 | head -n 5)
                    fi
                else
                    service_banner=$(echo "" | nc -w 2 "$ip" "$port" 2>&1 | head -n 5)
                fi
                
                if [[ ! $service_banner =~ "Connection refused" && ! $service_banner =~ "Connection timed out" && ! $service_banner =~ "No route to host" && -n "$service_banner" ]]; then
                    service_banner=$(echo "$service_banner" | tr -d '\n\r' | cut -c 1-44)
                    printf "| %-19s | %-4s | %-44s |\n" "$ip" "$port" "$service_banner"
                fi
            done
        done
    else
        ip_address=$scan_target
        if [ -z "${service_port_map["$ip_address"]:-}" ]; then
            echo "No open port data for $ip_address. Run Option 4."
        else
            # --- FIX: Added ':-' to prevent 'unbound variable' error on empty ports ---
            IFS=',' read -ra ports_to_check <<<"${service_port_map["$ip_address"]:-}"
            for port in "${ports_to_check[@]}"; do
                if [[ ! " ${PORTS_FOR_BANNER_GRAB[@]} " =~ " $port " ]]; then continue; fi
                
                if [[ "$port" =~ ^(80|443|8080|8443)$ ]]; then
                    if [[ "$port" =~ ^(443|8443)$ ]]; then
                        service_banner=$(echo "GET / HTTP/1.1\r\nHost: $ip_address\r\n\r\n" | \
                                         timeout 2 openssl s_client -connect "$ip_address:$port" -quiet 2>&1 | \
                                         head -n 5)
                    else
                        service_banner=$(printf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "$ip_address" | \
                                         nc -w 2 "$ip_address" "$port" 2>&1 | head -n 5)
                    fi
                else
                    service_banner=$(echo "" | nc -w 2 "$ip_address" "$port" 2>&1 | head -n 5)
                fi

                if [[ ! $service_banner =~ "Connection refused" && ! $service_banner =~ "Connection timed out" && ! $service_banner =~ "No route to host" && -n "$service_banner" ]]; then
                    service_banner=$(echo "$service_banner" | tr -d '\n\r' | cut -c 1-44)
                    printf "| %-19s | %-4s | %-44s |\n" "$ip_address" "$port" "$service_banner"
                fi
            done
        fi
    fi
    
    echo "+---------------------+------+----------------------------------------------+"
    local end_time=$(date +%s)
    echo "Banner grabbing complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}

# Task 6: Reverse DNS (CIDR-accurate)
task_run_reverse_dns() {
    local start_time=$(date +%s)
    local cidr_input ip host_output ptr
    read -p "Enter target network (CIDR format) [default: $DEFAULT_CIDR]: " cidr_input
    cidr_input=${cidr_input:-$DEFAULT_CIDR}
    if ! validate_cidr "$cidr_input"; then return 1; fi

    echo "Enumerating reverse DNS records (this may take time)..."
    echo "+---------------------+----------------------------------------------+"
    echo "| IP Address          | PTR Record(s)                                |"
    echo "+---------------------+----------------------------------------------+"

    # --- (BUG FIX) Corrected here-doc syntax ---
    while read -r ip; do
        if [ -z "$ip" ]; then continue; fi
        # --- FIX: Added '|| true' to prevent 'set -e' from exiting on a failed lookup ---
        host_output=$(host "$ip" 2>/dev/null || true)
        if [[ "$host_output" == *"pointer"* ]]; then
            ptr=$(echo "$host_output" | awk '/pointer/{print $NF}' | tr '\n' ',' | sed 's/,$//')
            printf "| %-19s | %-44s |\n" "$ip" "$ptr"
        fi
    done < <(python3 - "$cidr_input" <<PY
import sys, ipaddress
try:
    # --- (FIX 2) Iterate over ALL IPs in the network, not just .hosts() ---
    for ip in ipaddress.ip_network(sys.argv[1], strict=False):
        print(ip)
except Exception as e:
    print(f"Python error: {e}", file=sys.stderr, flush=True)
PY
)
    echo "+---------------------+----------------------------------------------+"
    local end_time=$(date +%s)
    echo "Reverse DNS lookup complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}


# Task 7: Analyze bandwidth of Option 4's capture
task_analyze_capture() {
    local start_time=$(date +%s)
    local pcap_path="/tmp/netscan_capture.pcap"
    echo "Analyzing pcap file: $pcap_path"

    if [ ! -r "$pcap_path" ]; then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}The pcap file ($pcap_path) does not exist or is not readable.${C_NC}"
        echo "Please run Option 4 (Port Scan) first to generate the file."
        read -p "Press [Enter] to return to the main menu..."
        return
    fi

    local capinfos_output
    capinfos_output=$(capinfos -i "$pcap_path" | grep "Data bit rate")

    if [ -z "$capinfos_output" ]; then
        echo "Unable to determine data rate from pcap file."
    else
        echo "File name:        $pcap_path"
        echo "$capinfos_output"
    fi

    local end_time=$(date +%s)
    echo "Analysis complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}

# Task 8: OS & Service Detection
task_os_service_detection() {
    local start_time=$(date +%s)
    local target
    read -p "Enter target network or IP [default: $DEFAULT_CIDR]: " target
    target=${target:-$DEFAULT_CIDR}
    if ! is_ip_or_cidr "$target"; then
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}Invalid target. Must be a single IP or CIDR.${C_NC}"
        return 1
    fi

    echo "Running OS and service detection (nmap -O -sV)..."
    echo "This will take several minutes."
    
    nmap -O -sV -T4 "$target"
    
    local end_time=$(date +%s)
    echo "OS & Service detection complete in $((end_time - start_time)) seconds."
    read -p "Press [Enter] to return to the main menu..."
}

# --- Main Program ---

# Function to display the welcome message and instructions.
display_header() {
    clear
    
    # --- FIX: Set color, no newline ---
    printf "%b" "\033[1;35m"
    
    # --- NEW: Get terminal width ---
    local width
    width=$(tput cols)

    # --- NEW: Check width and display appropriate banner ---
    if [ "$width" -lt 40 ]; then
        # --- Small banner for small terminals (Fixed newlines) ---
        printf "▗▖  ▗▖▗▞▀▚▖   ■   ▗▄▄▖▗▞▀▘▗▞▀▜▌▄▄▄▄   "
        printf "▐▛▚▖▐▌▐▛▀▀▘▗▄▟▙▄▖▐▌   ▝▚▄▖▝▚▄▟▌█   █  "
        printf "▐▌ ▝▜▌▝▚▄▄▖  ▐▌   ▝▀▚▖         █   █  "
        printf "▐▌  ▐▌       ▐▌  ▗▄▄▞▘                "
        printf "             ▐▌                       "                              
        printf "%b\n" "          github.com/Nixon-H "
    else
        # --- Big banner for large terminals (Fixed syntax) ---
        printf "░███    ░██               ░██      ░██████                                   \n"
        printf "░████   ░██               ░██     ░██   ░██                                  \n"
        printf "░██░██  ░██  ░███████  ░████████ ░██          ░███████   ░██████   ░████████  \n"
        printf "░██ ░██ ░██ ░██    ░██    ░██     ░████████  ░██    ░██       ░██  ░██    ░██  \n"
        printf "░██  ░██░██ ░█████████    ░██            ░██ ░██         ░███████  ░██    ░██  \n"
        printf "░██   ░████ ░██           ░██     ░██   ░██  ░██    ░██ ░██   ░██  ░██    ░██  \n"
        printf "░██    ░███  ░███████      ░████   ░██████    ░███████   ░█████░██ ░██    ░██  \n"
        printf "                                    _                                         \n"
        printf "                                              https://github.com/Nixon-H\n"
    fi

    # --- FIX: Reset color *after* the banner ---
    printf "%b\n" "\033[0m" 
    
    # --- Rest of the menu ---
    printf "%b\n" "\033[1;34mCOMP1671-Penetration Testing and Ethical Vulnerability Scanning\033[0m"
    printf "%b\n" "\033[1;32mActive Enumeration Week2 - v1.0\033[0m\n"
    printf "%b\n" "\033[1mDefault Network: $DEFAULT_CIDR\033[0m"
    printf "%b\n" "\033[1mSession Log: $LOG_FILE\033[0m"
    printf "%b\n" "\033[1mMenu Options:\033[0m"
    printf "%b\n" "1. Enumerate network hosts (ICMP Ping Sweep)"
    printf "%b\n" "2. Enumerate network hosts (ARP Scan)"
    printf "%b\n" "3. Map hosts (ICMP & ARP)"
    printf "%b\n" "4. Full Scan: Map hosts & scan ports (nmap, CSV/JSON export)"
    printf "%b\n" "5. Banner Grabbing (Run after Option 4)"
    printf "%b\n" "6. Reverse DNS Lookup (CIDR-accurate)"
    printf "%b\n" "7. Analyze Bandwidth of last scan (from Option 4)"
    printf "%b\n" "8. OS & Service Detection (nmap -O -sV)"
    printf "%b\n" "9. Quit\n"
    printf "%b\n" "\033[1mSelect an option by number:\033[0m"
}


# Main menu loop
while true; do
    user_selection="" # Initialize to empty
    display_header
    read -r user_selection

    case $user_selection in
    1)
        task_run_icmp_sweep
        ;;
    2)
        task_run_arp_sweep
        ;;
    3)
        task_run_combined_map
        ;;
    4) 
        task_run_port_scan
        ;;
    5)
        task_grab_banners
        ;;
    6)
        task_run_reverse_dns
        ;;
    7) 
        task_analyze_capture
        ;;
    8) 
        task_os_service_detection
        ;;
    9)
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "\033[31mExiting scanner. Goodbye!\033[0m"
        # The 'trap' will handle cleanup
        exit 0
        ;;
    *)
        # --- FIX: Switched to printf for reliable color output ---
        printf "%b\n" "${C_RED}Invalid selection '$user_selection'. Please choose a number from 1-9.${C_NC}"
        sleep 2
        ;;
    esac
done
