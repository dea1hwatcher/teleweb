//go:build linux && 386

package main

import (
	"syscall"
	"unsafe"
)

func getOriginalDst(fd uintptr, sa unsafe.Pointer, l *uint32) error {
	// On 32-bit x86 Linux, socket operations are multiplexed via socketcall (102).
	// Subcall 15 is SYS_GETSOCKOPT.
	const sysGETSOCKOPT = 15
	args := [5]uintptr{
		fd,
		uintptr(syscall.SOL_IP),
		uintptr(80), // SO_ORIGINAL_DST
		uintptr(sa),
		uintptr(unsafe.Pointer(l)),
	}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, sysGETSOCKOPT, uintptr(unsafe.Pointer(&args[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func getOriginalDstV6(fd uintptr, sa unsafe.Pointer, l *uint32) error {
	const sysGETSOCKOPT = 15
	const solIPV6 = 41
	const ip6tSOOriginalDst = 80
	args := [5]uintptr{
		fd,
		uintptr(solIPV6),
		uintptr(ip6tSOOriginalDst),
		uintptr(sa),
		uintptr(unsafe.Pointer(l)),
	}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, sysGETSOCKOPT, uintptr(unsafe.Pointer(&args[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
