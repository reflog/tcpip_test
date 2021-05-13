package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"os"
)

func main() {
	c, err := net.ListenPacket("ip4:tcp", "127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	reader := bufio.NewReader(os.Stdin)

	dstIP := net.ParseIP("127.0.0.1") // vm1
	dstPort := layers.TCPPort(12345)

	srcIP := net.ParseIP("127.0.0.1") // vm0
	srcPort := layers.TCPPort(54321)

	for {
		text, _ := reader.ReadString('\n')
		sendSyn(c, srcIP, srcPort, dstIP, dstPort)
		req := getAck(c)
		if req != nil {
			sendData(c, srcIP, srcPort, dstIP, dstPort, text, req)
			getResponse(c)
		}
	}
}

func sendData(c net.PacketConn, srcIP net.IP, srcPort layers.TCPPort, dstIP net.IP, dstPort layers.TCPPort, text string, req *layers.TCP) {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	transportLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     req.Ack,
		Ack:     req.Seq + uint32(len(text)-20),
		Window:  1500,
		ACK:     true,
		PSH:     true,
	}

	if err := transportLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		fmt.Errorf("failed to set network layer:%v\n", err)
		os.Exit(1)
	}

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts,
		transportLayer,
		gopacket.Payload(text),
	); err != nil {
		fmt.Printf("failed to serialize:%v\n", err)
		os.Exit(1)
	}
	if count, err := c.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
		log.Printf("failed to send:%v", err)
	} else {
		log.Printf("wrote %v bytes\n", count)
	}
}
func getAck(c net.PacketConn) *layers.TCP {
	tmp := make([]byte, 10000)
	for {
		n, addr, err := c.ReadFrom(tmp)
		if err != nil {
			log.Printf("err reading %v from %v", err, addr)
			return nil
		}
		reqPacket := gopacket.NewPacket(tmp[:n], layers.LayerTypeTCP, gopacket.Default)
		tcpLayer := reqPacket.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			log.Printf("tcpLayer nil")
			return nil
		}
		req := tcpLayer.(*layers.TCP)
		if req.DstPort != 54321 {
			continue
		}
		log.Printf("recv tcp port: %v -> %v, seq %v ack %v  SYN %v ACK %v", req.SrcPort, req.DstPort, req.Seq, req.Ack, req.SYN, req.ACK)
		return req
	}
	return nil
}
func sendSyn(c net.PacketConn, srcIP net.IP, srcPort layers.TCPPort, dstIP net.IP, dstPort layers.TCPPort) {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	transportLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     true,
	}

	if err := transportLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		log.Fatalf("failed to set network layer:%v\n", err)
	}

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts,
		transportLayer,
	); err != nil {
		log.Fatalf("failed to serialize:%v\n", err)
	}

	if _, err := c.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
		log.Printf("couldn't send")
	} else {
		log.Printf("sent syn")
	}
}

func getResponse(c net.PacketConn) *layers.TCP {
	tmp := make([]byte, 10000)
	for {
		n, addr, err := c.ReadFrom(tmp)
		if err != nil {
			log.Printf("err reading %v from %v", err, addr)
			return nil
		}
		reqPacket := gopacket.NewPacket(tmp[:n], layers.LayerTypeTCP, gopacket.Default)
		tcpLayer := reqPacket.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			log.Printf("tcpLayer nil")
			return nil
		}
		req := tcpLayer.(*layers.TCP)
		if req.DstPort != 54321 {
			continue
		}
		log.Printf("reply %v", string(tmp[20:]))
		return req
	}
	return nil
}
