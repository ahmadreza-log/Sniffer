package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PacketLog represents a single entry in the CSV log
// This struct stores metadata about a captured network packet
// such as timestamp, direction, size, IP and port.
type PacketLog struct {
	Timestamp string
	Direction string
	Size      int
	IP        string
	Port      string
}

// CacheKey uniquely identifies a packet group for aggregation
type CacheKey struct {
	Direction string
	IP        string
	Port      string
}

// CacheEntry stores aggregated data for packets with the same CacheKey
type CacheEntry struct {
	SizeSum  int
	LastSeen time.Time
}

// SavePacket writes a PacketLog entry to the CSV file
func SavePacket(log PacketLog, writer *csv.Writer) {
	record := []string{
		log.Timestamp,
		log.Direction,
		strconv.Itoa(log.Size),
		log.IP,
		log.Port,
	}
	writer.Write(record)
	writer.Flush()
}

// GenerateSummary creates and displays a summary report from CSV logs
func GenerateSummary(logPath string) {
	file, err := os.Open(logPath)
	if err != nil {
		log.Printf("[WARN] Cannot open log file for summary: %v\n", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		log.Printf("[INFO] No sufficient data for summary\n")
		return
	}

	var uploadTotal, downloadTotal int
	ipCounter := make(map[string]int)

	for _, row := range records[1:] {
		size, _ := strconv.Atoi(row[2])
		direction := row[1]
		ip := row[3]
		if direction == "Upload" {
			uploadTotal += size
		} else if direction == "Download" {
			downloadTotal += size
		}
		ipCounter[ip]++
	}

	fmt.Println("\n======= Summary Report =======")
	fmt.Printf("Total Uploaded:   %d bytes\n", uploadTotal)
	fmt.Printf("Total Downloaded: %d bytes\n", downloadTotal)
	fmt.Println("\nTop Contacted IPs:")
	count := 0
	for ip, hits := range ipCounter {
		fmt.Printf("- %s: %d connections\n", ip, hits)
		count++
		if count >= 5 {
			break
		}
	}
	fmt.Printf("==============================\n\n")
}

func main() {
	// Capture summary interval (modifiable)
	const SummaryInterval = 1 * time.Hour
	const CacheFlushInterval = 5 * time.Second

	Devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to list network devices: %v", err)
	}

	fmt.Println("Available Network Devices:")
	for i, device := range Devices {
		fmt.Printf("[%d] %s - %s\n", i, device.Name, device.Description)
	}

	fmt.Print("\nSelect a network device by index: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	index, err := strconv.Atoi(input)
	if err != nil || index < 0 || index >= len(Devices) {
		log.Fatalf("Invalid device selection: %v", err)
	}

	selectedDevice := Devices[index].Name
	handle, err := pcap.OpenLive(selectedDevice, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	logDir := "logs"
	os.MkdirAll(logDir, 0755)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("\nMonitoring network traffic on %s... Press Ctrl+C to stop.\n\n", selectedDevice)

	var currentMinute string
	var logFile *os.File
	var writer *csv.Writer
	var logPath string
	var lastSummaryTime = time.Now()

	cache := make(map[CacheKey]*CacheEntry)
	var cacheMutex sync.Mutex

	// Graceful shutdown handler
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cacheMutex.Lock()
		flushCache(cache, writer)
		cacheMutex.Unlock()
		if logFile != nil {
			writer.Flush()
			logFile.Close()
		}
		GenerateSummary(logPath)
		os.Exit(0)
	}()

	// Periodic cache flusher goroutine
	go func() {
		for {
			time.Sleep(CacheFlushInterval)
			cacheMutex.Lock()
			flushCache(cache, writer)
			cacheMutex.Unlock()
		}
	}()

	for packet := range packetSource.Packets() {
		metadata := packet.Metadata()
		timestamp := metadata.Timestamp.Format("2006/01/02 15:04:05")
		minute := metadata.Timestamp.Format("2006-01-02-15")
		size := metadata.Length

		ip := "unknown"
		port := "unknown"
		direction := "unknown"

		if netLayer := packet.NetworkLayer(); netLayer != nil {
			ipFlow := netLayer.NetworkFlow()
			srcIP, dstIP := ipFlow.Endpoints()

			if transLayer := packet.TransportLayer(); transLayer != nil {
				portFlow := transLayer.TransportFlow()
				srcPort, dstPort := portFlow.Endpoints()

				local := Devices[index].Addresses[0].IP.String()
				if srcIP.String() == local {
					direction = "Upload"
					ip = dstIP.String()
					port = dstPort.String()
				} else {
					direction = "Download"
					ip = srcIP.String()
					port = srcPort.String()
				}
			}
		}

		if minute != currentMinute {
			if logFile != nil {
				writer.Flush()
				logFile.Close()
			}
			logPath = filepath.Join(logDir, fmt.Sprintf("results-%s.csv", minute))
			isNew := false
			if _, err := os.Stat(logPath); os.IsNotExist(err) {
				isNew = true
			}
			logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("Failed to open log file: %v", err)
			}
			writer = csv.NewWriter(logFile)
			if isNew {
				writer.Write([]string{"Timestamp", "Direction", "Size(Bytes)", "IP", "Port"})
				writer.Flush()
			}
			currentMinute = minute
		}

		key := CacheKey{Direction: direction, IP: ip, Port: port}
		cacheMutex.Lock()
		if entry, exists := cache[key]; exists {
			entry.SizeSum += size
			entry.LastSeen = time.Now()
		} else {
			cache[key] = &CacheEntry{SizeSum: size, LastSeen: time.Now()}
		}
		cacheMutex.Unlock()

		fmt.Printf("[%s] %s %d bytes %s:%s\n", timestamp, direction, size, ip, port)

		if time.Since(lastSummaryTime) >= SummaryInterval {
			fmt.Printf("\n[Summary Triggered at %s]\n", time.Now().Format("15:04:05"))
			GenerateSummary(logPath)
			lastSummaryTime = time.Now()
		}
	}
}

// flushCache writes aggregated cache entries to CSV and clears the cache
func flushCache(cache map[CacheKey]*CacheEntry, writer *csv.Writer) {
	if writer == nil {
		return
	}
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	for key, entry := range cache {
		SavePacket(PacketLog{
			Timestamp: timestamp,
			Direction: key.Direction,
			Size:      entry.SizeSum,
			IP:        key.IP,
			Port:      key.Port,
		}, writer)
	}
	for k := range cache {
		delete(cache, k)
	}
}
