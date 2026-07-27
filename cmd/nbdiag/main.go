// Command nbdiag is a throwaway diagnostic: decrypt one captured mbaps session
// and print every plaintext record with its inner content type, so an alert
// that TLS 1.3 encrypts can actually be read.
//
// It exists because the northbound :802 failure ("mbap: read header:
// wolfSSL_read returned -1") survived two wrong hypotheses, and guessing again
// is worse than reading the wire. Delete once the answer is known.
package main

import (
	"fmt"
	"os"

	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: nbdiag <capture.pcapng> <keylog>")
		os.Exit(2)
	}
	pkts, err := pcapng.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap:", err)
		os.Exit(1)
	}
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			continue // non-IP/TCP frames are expected
		}
	}
	kl, err := keylog.Open(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "keylog:", err)
		os.Exit(1)
	}

	for _, st := range asm.Streams() {
		if len(st.Dirs) < 2 || st.Dirs[0] == nil || st.Dirs[1] == nil {
			continue
		}
		var cli, srv *netdis.Direction
		for _, d := range st.Dirs {
			if d == nil {
				continue
			}
			if d.Flow.Dst.Port == 802 {
				cli = d
			} else {
				srv = d
			}
		}
		if cli == nil || srv == nil {
			continue
		}
		fmt.Printf("=== %s ===\n", st.Key)
		fmt.Printf("  client complete=%v gap=%d  server complete=%v gap=%d\n",
			cli.Complete(), cli.PendingGap(), srv.Complete(), srv.PendingGap())

		cd, err := tlsdis.ParseDirection(cli.Bytes.Bytes(), cli.Bytes)
		if err != nil {
			fmt.Println("  client records:", err)
			continue
		}
		sd, err := tlsdis.ParseDirection(srv.Bytes.Bytes(), srv.Bytes)
		if err != nil {
			fmt.Println("  server records:", err)
			continue
		}
		params, err := tlsdecrypt.ParamsFromHandshake(cd, sd)
		if err != nil {
			fmt.Println("  ParamsFromHandshake:", err)
			continue
		}
		fmt.Printf("  %s / %s\n", tlsdis.VersionName(params.Version), tlsdis.CipherSuiteName(params.CipherSuite))

		sess, err := tlsdecrypt.New(params, kl)
		if err != nil {
			fmt.Println("  tlsdecrypt.New:", err)
			continue
		}
		for _, side := range []struct {
			name string
			s    tlsdecrypt.Side
			d    *tlsdis.Direction
		}{{"CLIENT", tlsdecrypt.Client, cd}, {"SERVER", tlsdecrypt.Server, sd}} {
			pts, derr := sess.DecryptAll(side.s, side.d.Stream.Records)
			fmt.Printf("  --- %s (%d plaintext) ---\n", side.name, len(pts))
			if derr != nil {
				fmt.Println("     decrypt error:", derr)
			}
			for _, pt := range pts {
				kind := fmt.Sprintf("%v", pt.Type)
				switch pt.Type {
				case 21:
					b := pt.Data
					if len(b) >= 2 {
						kind = fmt.Sprintf("ALERT level=%d desc=%d", b[0], b[1])
					} else {
						kind = "ALERT (short)"
					}
				case 22:
					kind = "handshake"
					if len(pt.Data) >= 4 {
						names := map[byte]string{1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
							8: "EncryptedExtensions", 11: "Certificate", 13: "CertificateRequest",
							15: "CertificateVerify", 20: "Finished", 24: "KeyUpdate"}
						n, ok := names[pt.Data[0]]
						if !ok {
							n = fmt.Sprintf("hs_type_%d", pt.Data[0])
						}
						kind = "handshake " + n
					}
				case 23:
					kind = "appdata"
				}
				fmt.Printf("     %-34s %4dB frames=%v\n", kind, len(pt.Data), pt.Frames())
				if os.Getenv("NBDIAG_HEX") != "" && pt.Type == 22 && len(pt.Data) > 0 && pt.Data[0] == 4 {
					fmt.Printf("        raw: %x\n", pt.Data)
				}
			}
		}
	}
}
