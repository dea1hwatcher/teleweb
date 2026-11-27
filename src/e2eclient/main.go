package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// buildObfuscatedInit creates a valid MTProto obfuscated-transport init packet
// (key=init[8:40], iv=init[40:56], encrypted tail with tag EFEFEFEF and
// signed DC index) plus the CTR stream advanced past the init for framing.
func buildObfuscatedInit(dc int16) ([]byte, cipher.Stream) {
	init := make([]byte, 64)
	_, _ = rand.Read(init)
	init[0] = 0x42 // avoid the abridged 0xEF marker
	key := init[8:40]
	iv := init[40:56]
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	var zero56 [56]byte
	stream.XORKeyStream(zero56[:], zero56[:])
	plain := [8]byte{0xEF, 0xEF, 0xEF, 0xEF, 0, 0, 0x55, 0xAA}
	binary.LittleEndian.PutUint16(plain[4:6], uint16(dc))
	stream.XORKeyStream(init[56:64], plain[:])
	return init, stream
}

func runDirectClient(target string) {
	init, stream := buildObfuscatedInit(2) // DC2

	c, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	fmt.Printf("connected to %s (local %s)\n", c.RemoteAddr(), c.LocalAddr())
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	_, _ = c.Write(init)

	// Keep the tunnel busy: send a small padded-transport style frame (4-byte
	// LE length + payload) so Telegram has something to parse and possibly
	// reply to. Payload is a deliberately invalid unencrypted MTProto message.
	msg := make([]byte, 40)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)-4))
	enc := make([]byte, len(msg))
	stream.XORKeyStream(enc, msg)
	_, _ = c.Write(enc)

	buf := make([]byte, 512)
	n, rerr := c.Read(buf)
	fmt.Printf("read: n=%d err=%v data=% x\n", n, rerr, buf[:n])
	_ = c.Close()
}

// generateTestCerts creates an ephemeral ECDSA CA + leaf cert signed for host
// so Docker dual-validation tests keep full x509 chain verification enabled.
func generateTestCerts(host string) (caPEM []byte, leafCert tls.Certificate, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TeleWEB E2E DPI Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	leafCert, err = tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	return caPEM, leafCert, nil
}

// inspectFirstRecordBlocked simulates an OpenGFW/TSPU SNI DPI rule: it blocks
// when the very first TLS ClientHello record carries a complete handshake header
// and exposes the unfragmented blockedSNI before byte 2048 inside record 1.
func inspectFirstRecordBlocked(rec []byte, blockedSNI string) (blocked bool, reason string) {
	if len(rec) < 9 || rec[0] != 0x16 {
		return false, ""
	}
	recLen := int(binary.BigEndian.Uint16(rec[3:5]))
	if recLen < 42 || 5+recLen > len(rec) {
		return false, ""
	}
	payload := rec[5 : 5+recLen]
	if payload[0] != 0x01 {
		return false, ""
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if hsLen < 38 || 4+hsLen > len(payload) {
		return false, ""
	}
	off := 4 + 2 + 32
	if off >= len(payload) {
		return false, ""
	}
	off += 1 + int(payload[off])
	if off+2 > len(payload) {
		return false, ""
	}
	off += 2 + int(binary.BigEndian.Uint16(payload[off:off+2]))
	if off >= len(payload) {
		return false, ""
	}
	off += 1 + int(payload[off])
	if off+2 > len(payload) {
		return false, ""
	}
	extTotal := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	extEnd := off + extTotal
	if extEnd > len(payload) {
		return false, ""
	}
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[off : off+2])
		extLen := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		if off+4+extLen > extEnd {
			return false, ""
		}
		if extType == 0x0000 && off < 2048 && extLen >= 5 {
			nameLen := int(binary.BigEndian.Uint16(payload[off+4+3 : off+4+5]))
			if 5+nameLen <= extLen {
				sni := string(payload[off+4+5 : off+4+5+nameLen])
				if strings.EqualFold(sni, blockedSNI) {
					return true, fmt.Sprintf("unfragmented SNI=%s at offset=%d", sni, off)
				}
			}
		}
		off += 4 + extLen
	}
	return false, ""
}

func runDPIProxy(listenAddr, blockedSNI, caOutPath string) {
	caPEM, leafCert, err := generateTestCerts(blockedSNI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi-proxy cert gen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(caOutPath, caPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "dpi-proxy write ca: %v\n", err)
		os.Exit(1)
	}

	// Backend TLS + WebSocket /apiws server implementing Cloudflare/Telegram upgrade response.
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leafCert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi-proxy tls listen: %v\n", err)
		os.Exit(1)
	}
	defer tlsLn.Close()

	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				key := req.Header.Get("Sec-WebSocket-Key")
				sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				accept := base64.StdEncoding.EncodeToString(sum[:])
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: binary\r\nCF-Ray: 8e00000000000000-FRA\r\n\r\n", accept)
			}(c)
		}
	}()

	frontLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi-proxy listen %s: %v\n", listenAddr, err)
		os.Exit(1)
	}
	defer frontLn.Close()

	fmt.Printf("DPI_PROXY_READY listen=%s backend=%s blocked=%s ca=%s\n", frontLn.Addr(), tlsLn.Addr(), blockedSNI, caOutPath)

	go func() {
		for {
			cli, err := frontLn.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				buf := make([]byte, 20480)
				_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := client.Read(buf)
				_ = client.SetReadDeadline(time.Time{})
				if err != nil || n == 0 {
					_ = client.Close()
					return
				}
				pkt := buf[:n]
				if blocked, reason := inspectFirstRecordBlocked(pkt, blockedSNI); blocked {
					fmt.Printf("DPI_DROP %s\n", reason)
					if tc, ok := client.(*net.TCPConn); ok {
						_ = tc.SetLinger(0)
					}
					_ = client.Close()
					return
				}
				fmt.Printf("DPI_PASS first_chunk=%dB\n", n)
				backend, err := net.DialTimeout("tcp", tlsLn.Addr().String(), 3*time.Second)
				if err != nil {
					_ = client.Close()
					return
				}
				if _, err := backend.Write(pkt); err != nil {
					_ = client.Close()
					_ = backend.Close()
					return
				}
				go func() { _, _ = io.Copy(backend, client); _ = backend.Close() }()
				_, _ = io.Copy(client, backend)
				_ = client.Close()
			}(cli)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: e2eclient <host:port> | dpi-proxy <listenAddr> <blockedSNI> <caOut>")
		os.Exit(2)
	}
	if os.Args[1] == "dpi-proxy" {
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "usage: e2eclient dpi-proxy <listenAddr> <blockedSNI> <caOut>")
			os.Exit(2)
		}
		runDPIProxy(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	target := os.Args[1]
	if len(os.Args) >= 3 && os.Args[1] == "direct" {
		target = os.Args[2]
	}
	runDirectClient(target)
}
