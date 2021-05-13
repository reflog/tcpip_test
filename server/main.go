package main

/*
echo server by tcp for rawsocket
*/

import (
	"log"
	"net"
	//"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var RESPONSE = []byte("response\n")

func main() {
	conn, err := net.ListenPacket("ip4:tcp", "127.0.0.1")
	if err != nil {
		log.Fatalf("ListenPacket error: %v\n", err)
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("ReadFrom error: %v\n", err)
		}
		log.Printf("recv from ip: %v", addr.String())

		if addr.String() != "127.0.0.1" {
			log.Printf("addr incorrect %v", addr.String())
			continue
		}

		ipaddr, _ := net.ResolveIPAddr(addr.Network(), addr.String())

		reqPacket := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, gopacket.Default)
		tcpLayer := reqPacket.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			log.Printf("tcpLayer nil")
			continue
		}
		req := tcpLayer.(*layers.TCP)

		if req.DstPort != 12345 {
			continue
		}
		log.Printf("recv tcp port: %v -> %v, seq %v ack %v", req.SrcPort, req.DstPort, req.Seq, req.Ack)

		var res *layers.TCP

		// syn
		if req.SYN && !req.ACK {
			res = &layers.TCP{
				Seq:    0xdeadcafe,
				Ack:    req.Seq + 1,
				SYN:    true,
				ACK:    true,
				Window: 1500,
			}
			log.Printf("Sending ack")
		} else if req.PSH && req.ACK {
			log.Printf("recv PSH,ACK: %v", string(buf[20:]))
			res = &layers.TCP{
				Seq:    req.Ack,
				Ack:    req.Seq + uint32(n-20),
				Window: 1500,
				ACK:    true,
			}
			log.Printf("response sent")
		}

		if res == nil {
			continue
		}

		// Our IP header... not used, but necessary for TCP checksumming.
		ip := &layers.IPv4{
			SrcIP:    ipaddr.IP, // TODO
			DstIP:    ipaddr.IP,
			Protocol: layers.IPProtocolTCP,
		}

		res.SrcPort = req.DstPort
		res.DstPort = req.SrcPort

		res.SetNetworkLayerForChecksum(ip)

		// response
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		if err := gopacket.SerializeLayers(buf, opts, res, gopacket.Payload(RESPONSE)); err != nil {
			log.Fatal(err)
		}

		if _, err := conn.WriteTo(buf.Bytes(), ipaddr); err != nil {
			log.Fatal(err)
		}
	}
}

/*
# drop TCP(rst) output
sudo iptables -A OUTPUT  -p tcp --sport 12345 --tcp-flags rst rst -j DROP

$ sudo ./rawsock_tcp_send
# todo

$ nc 127.0.0.1 12345
123
response

*/
