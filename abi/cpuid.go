//go:build !amd64 || gccgo
// +build !amd64 gccgo

package abi

func init() {
	cpuid = func(op uint32) (eax, ebx, ecx, edx uint32) {
		return 0, 0, 0, 0
	}
}
