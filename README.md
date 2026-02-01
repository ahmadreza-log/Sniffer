# 📦 Sniffer — Network Packet Monitor

A lightweight **network traffic sniffer** written in Go. It captures packets on a selected network interface, aggregates traffic by direction (Upload/Download), IP, and port, and writes CSV logs with optional summary reports.

## About
**Sniffer** is a small **network packet monitor** that:
- 🔌 Lists available network interfaces and lets you choose one
- 📥📤 Captures packets and classifies them as **Upload** or **Download**
- Aggregates traffic by IP and port (with an in-memory cache, flushed every 5 seconds)
- 📄 Writes CSV logs under `logs/` (one file per minute: `results-YYYY-MM-DD-HH.csv`)
- 📊 Prints a **summary report** every hour and on exit (Ctrl+C): total bytes uploaded/downloaded and top 5 contacted IPs

### ✨ Features
- Device selection via interactive prompt
- Packet capture using [gopacket](https://github.com/google/gopacket) and **pcap**
- CSV columns: `Timestamp`, `Direction`, `Size(Bytes)`, `IP`, `Port`
- Graceful shutdown: Ctrl+C flushes cache, closes log file, and shows final summary

### 📋 Requirements
- **Go 1.24+**
- **pcap**: Npcap on Windows, libpcap on Linux/macOS
- **Admin/root** may be required to open the network device (especially on Windows and Linux)

### 🚀 Build & Run
```bash
# Install dependencies
go mod download

# Run
go run .

# Or build binary
go build -o sniffer     # Linux/macOS → ./sniffer
go build -o sniffer.exe # Windows
```
Then enter the index of the network device and press **Ctrl+C** to stop and see the summary.

### What Gets Created (and what doesn’t)
| Created at runtime        | Not created                    |
|---------------------------|--------------------------------|
| `logs/` directory         | No database                    |
| `logs/results-*.csv`      | No background service/daemon  |
| (Binary if you run `go build`) | No config file by default |

### 📁 Project structure
```
Sniffer/
├── main.go      # Entry point, capture loop, CSV logging, summary
├── go.mod
├── go.sum
└── README.md
```

### 📜 License
See [LICENSE](LICENSE).
