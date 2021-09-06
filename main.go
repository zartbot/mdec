package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/zartbot/mdec/exats"
	"github.com/zartbot/mdec/shfe"
	"github.com/zartbot/mdec/sink"
)

func main() {

	dataChan := make(chan *sink.DataStream, 100)
	exporter, err := sink.NewElasticSearchSink(&sink.CfgElasticSearchSink{
		ID:             1,
		Name:           "export record to elasticsearch",
		Input:          dataChan,
		Uri:            "http://elastic:cisco123@127.0.0.1:9200",
		IndexPrefix:    "marketdata",
		Mapping:        "{\"settings\": {\"index.refresh_interval\": \"30s\",\"index.mapping.total_fields.limit\": 6000,\"number_of_shards\": 3,\"number_of_replicas\": 0}}",
		PrefixTypeList: []string{"mirp", "mdqp"},
		Parallelism:    4,
	})
	if err != nil {
		logrus.Fatal("create elasticsearch exporter error:", err)
	}

	go exporter.Run()

	// For pcap source testing purposes
	pcapFile := "/home/zartbot/pcap/hangqing-mode-fcs.pcap"
	handle, err := pcap.OpenOffline(pcapFile)

	//you may also use "sudo tcpreplay -v -i lo pcap/mirp.pcap" to inject packet to real interface.
	//handle, err := pcap.OpenLive("lo", 65535, true, pcap.BlockForever)
	if err != nil {
		logrus.Fatal("open port error:", err)
	}

	defer handle.Close()

	/*
		var filter string = ""
		err = handle.SetBPFFilter(filter)
		if err != nil {
			logrus.Fatal(err)
		}
	*/

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	defer handle.Close()
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	mdqpDecoder := shfe.NewMDQPDecoder(dataChan)

	SysTimestamp := time.Now()
	//Arista and Exablaze FPGA ref-clock 350Mhz for Hardware timestamp
	TSFrequency := uint64(350000000)
	ExaLastTick := uint64(0)

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}

			if packet.LinkLayer().LayerType() == layers.LayerTypeEthernet {
				eth := packet.LinkLayer().(*layers.Ethernet)
				if eth.EthernetType == 0x88b5 {
					//CheckExablaze KeyFrame
					refClock, err := exats.DecodeKeyFrame(eth.Payload)
					if err == nil {
						SysTimestamp = time.Unix(0, refClock.Timestamp)
						TSFrequency = refClock.Frequency
						ExaLastTick = refClock.TickCnt
					}
				}
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				continue
			}

			if packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
				continue
			}

			//Deode Exablaze Timestamp
			ts, hpt, err := exats.DecodeExaTS(packet, TSFrequency, SysTimestamp, ExaLastTick)
			if err != nil {
				continue
			}

			if hpt != nil {
				logrus.Info(hpt)
			}
			if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
				//TODO: Add Port and address validation before decode MDQP
				tcp := packet.TransportLayer().(*layers.TCP)
				mdqpDecoder.StreamFactory.CurrentTimestamp = ts
				if hpt != nil {
					mdqpDecoder.StreamFactory.PicoSecond = hpt.TimeStamp.PicoSeconds
				}
				mdqpDecoder.Assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}

			if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
				ip := packet.NetworkLayer().(*layers.IPv4)
				//TODO: Add Port and address validation before decode MIRP
				udp := packet.TransportLayer().(*layers.UDP)
				if len(udp.Payload) <= 24 {
					continue
				}

				src := fmt.Sprintf("%s:%s", ip.SrcIP, udp.SrcPort)
				dst := fmt.Sprintf("%s:%s", ip.DstIP, udp.DstPort)
				shfe.MIRPDecodeAndSink(udp.Payload, dataChan, ts, hpt, src, dst)
			}

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 1 minutes.
			mdqpDecoder.Assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
		}
	}

}
