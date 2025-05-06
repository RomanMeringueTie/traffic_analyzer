package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func handlePacket(packet gopacket.Packet, file_name string) {

	f, err := os.OpenFile(file_name, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString("\n" + packet.Dump() + "\n"); err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) < 2 {
		panic(error.Error(fmt.Errorf("Укажите BPF выражение")))
	}
	bpf_string := os.Args[1]
	save_file := "save.txt"
	if len(os.Args) > 2 {
		save_file = os.Args[2]
	}
	var handle *pcap.Handle
	var err error
	var bpf *pcap.BPF
	matched_packets := 0
	if handle, err = pcap.OpenLive("wlp0s20f3", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		bpf, err = handle.NewBPF(bpf_string)
		if err != nil {
			panic(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				if bpf.Matches(packet.Metadata().CaptureInfo, packet.Data()) {
					matched_packets++
					fmt.Printf("Найден подходящий пакет № %d\n", matched_packets)
					handlePacket(packet, save_file)
				}
			}
		}
	}

}
