#!/usr/bin/env python3
#
# system_report.py

import os
import subprocess
import json
import platform

# Helper function to execute system commands
def run_command(command):
    try:
        # For Windows, switch to PowerShell for some commands
        if platform.system() == "Windows" and ("Get-" in command or "|" in command):
            result = subprocess.check_output(["powershell", "-Command", command], text=True, stderr=subprocess.STDOUT)
        else:
            result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
        print(result)
        return result.strip()
    except subprocess.CalledProcessError as e:
        return e.output

def get_system_analysis():
    os_type = platform.system()
    if os_type == "Darwin":  # macOS
        system_analysis = system_analysis_mac
    elif os_type == "Windows":
        system_analysis = system_analysis_windows
    elif os_type == "Linux":
        system_analysis = system_analysis_linux
    else:
        return f"Unsupported OS: {os_type}"

    analysis_results = {key: run_command(value) for key, value in system_analysis.items()}
    return analysis_results

# macOS Specific System Analysis
system_analysis_mac = {
    "hostname": run_command("hostname"),
    "printenv": run_command("printenv"),
    "whoami": run_command("whoami"),
    "w": run_command("w"),
    "last": run_command("last"),
    "traceroute": run_command("traceroute 1.1.1.1"),
    "df": run_command("df -h"),
    "diskutil": run_command("diskutil list"),
    "system_profiler (Model Info)": run_command("system_profiler SPHardwareDataType | grep 'Model Identifier'"),
    "system_profiler (Serial Number)": run_command("system_profiler SPHardwareDataType | grep 'Serial Number'"),
    "/etc/passwd": run_command("cat /etc/passwd"),
    "/etc/group": run_command("cat /etc/group"),
    "launchctl": run_command("launchctl list"),
    "/var/log/system.log": run_command("cat /var/log/system.log"),
    "dmesg": run_command("dmesg"),
    "system_profiler (Hardware Overview)": run_command("system_profiler SPHardwareDataType"),
    "top": run_command("top -l 1"),
    "vm_stat": run_command("vm_stat"),
    "networksetup": run_command("networksetup -listallhardwareports"),
    "ifconfig": run_command("ifconfig"),
    "pfctl": run_command("pfctl -s info"),  # Firewall status, might need sudo
    "system_profiler (Software Updates)": run_command("softwareupdate --list"),
    "iostat": run_command("iostat"),
    "diskutil info": run_command("diskutil info /"),  # For the root volume
    "ps": run_command("ps auxwww"),
}

# Windows System Analysis
system_analysis_windows = {
    "hostname": run_command("hostname"),
    "environment_variables": run_command("Get-ChildItem Env: | Format-List"),
    "current_user": run_command("echo %USERNAME%"),
    "logged_on_users": run_command("query user"),
    "systeminfo": run_command("systeminfo"),
    "Get Serial Number": run_command("wmic bios get serialnumber"),
    "Get Model Number": run_command("wmic csproduct get name"),
    "disk_usage": run_command("wmic logicaldisk get size,freespace,caption"),
    "ip_config": run_command("ipconfig /all"),
    "netstat": run_command("netstat -ano"),
    "firewall_status": run_command("netsh advfirewall show allprofiles"),
    "running_processes": run_command("Get-Process | Format-Table Name, ID, Path -AutoSize"),
    "system_services": run_command("Get-Service | Format-Table Name, Status -AutoSize"),
    "scheduled_tasks": run_command("schtasks /query /fo LIST"),
    "update_history": run_command("Get-WindowsUpdateLog"),  # This command may need to be adjusted for different Windows versions or configurations.
    "drivers": run_command("driverquery"),
}

# Linux
system_analysis_linux = {
    "hostname": run_command("hostname"),
    "printenv": run_command("printenv"),
    "whoami": run_command("whoami"),
    "w": run_command("w"),
    "last": run_command("last -a"),
    "traceroute": run_command("traceroute 1.1.1.1"),
    "df": run_command("df -a"),
    "swapon": run_command("swapon --show"),
    "smartctl": run_command(f"smartctl -a"),
    "/etc/passwd": run_command("cat /etc/passwd"),
    "/etc/group": run_command("cat /etc/group"),
    "systemctl": run_command("systemctl list-units --type=service --state=running"),
    "/var/log/auth.log": run_command("cat /var/log/auth.log"),
    "/var/log/syslog": run_command("cat /var/log/syslog"),
    "dmesg": run_command("dmesg"),
    "lshw": run_command("lshw -short"),
    "top": run_command("top -bn1"),
    "free": run_command("free -m"),
    "/proc/meminfo": run_command("cat /proc/meminfo"),
    "/proc/net/dev": run_command("cat /proc/net/dev"),
    "ss": run_command("ss -tuln"),
    "ufw": run_command("ufw status"),
    "sensors": run_command("sensors"),
    "apt": run_command("apt list --upgradable"),
    "iostat": run_command("iostat"),
    "vmstat": run_command("vmstat"),
    "lsblk": run_command("lsblk -np"),
    "ps": run_command("ps auxwww"),
}

# Execute analysis based on OS and output the results
analysis_results = get_system_analysis()
print(json.dumps(analysis_results, indent=4))

