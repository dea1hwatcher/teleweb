package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// buildObfuscatedInitAndStream crafts a valid MTProto obfuscated-transport
// init: key=init[8:40], iv=init[40:56], encrypted tail with tag EFEFEFEF and
// signed DC index, plus the CTR stream advanced past the init for framing.
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

func main() {
	mode := os.Args[1]
	target := os.Args[2]
	init, stream := buildObfuscatedInit(2) // DC2

	var c net.Conn
	var err error
	if mode == "socks" {
		c, err = net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			fmt.Println("dial socks:", err)
			os.Exit(1)
		}
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		_, _ = c.Write([]byte{5, 1, 0})
		rep := make([]byte, 2)
		if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 5 || rep[1] != 0 {
			fmt.Printf("socks auth failed: %v %v\n", rep, err)
			os.Exit(1)
		}
		_, _ = c.Write([]byte{5, 1, 0, 1, 149, 154, 167, 220, 0x01, 0xBB})
		rep = make([]byte, 10)
		if _, err := io.ReadFull(c, rep); err != nil {
			fmt.Println("socks connect read:", err)
			os.Exit(1)
		}
		fmt.Printf("socks reply: %v\n", rep)
		if rep[1] != 0 {
			fmt.Println("socks connect rejected")
			os.Exit(1)
		}
	} else {
		c, err = net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			fmt.Println("dial:", err)
			os.Exit(1)
		}
		fmt.Printf("connected to %s (local %s)\n", c.RemoteAddr(), c.LocalAddr())
		_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	}
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
