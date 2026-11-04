//go:build linux && !386

package main

import (
	"syscall"
	"unsafe"
)

func getOriginalDst(fd uintptr, sa unsafe.Pointer, l *uint32) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		uintptr(syscall.SOL_IP),
		uintptr(80), // SO_ORIGINAL_DST
		uintptr(sa),
		uintptr(unsafe.Pointer(l)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func getOriginalDstV6(fd uintptr, sa unsafe.Pointer, l *uint32) error {
	const solIPV6 = 41
	const ip6tSOOriginalDst = 80
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		uintptr(solIPV6),
		uintptr(ip6tSOOriginalDst),
		uintptr(sa),
		uintptr(unsafe.Pointer(l)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
