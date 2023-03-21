package perf_cgo

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	errCodeBufferSize = 512
)

func NullTerminatedStringToString(val []byte) string {
	slen := len(val)
	for idx, ch := range val {
		if ch == 0 {
			slen = idx
			break
		}
	}
	return string(val[:slen])
}

type perfEventHandler struct {
	pmuFd     int
	shMem     unsafe.Pointer
	shMemByte []byte
	shMemSize int

	ringBuffer *mmapRingBuffer
}

func newPerfEventHandler(cpu, pid int, bufferSize int) (*perfEventHandler, error) {

	res := &perfEventHandler{
		shMemSize: calculateMmapSize(bufferSize),
	}

	// Create perf event fd
	watermark := 1
	//Open perf event
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        unix.PerfBitWatermark,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	attr.Size = uint32(unsafe.Sizeof(attr))

	var err error
	res.pmuFd, err = unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("Failed to open perf event %v", err)
	}

	if err := unix.SetNonblock(res.pmuFd, true); err != nil {
		return nil, err
	}

	// Create shared memory
	shMem, err := unix.Mmap(res.pmuFd, 0, res.shMemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(res.pmuFd)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}
	res.shMem = unsafe.Pointer(&shMem[0])
	res.shMemByte = shMem
	res.ringBuffer = NewMmapRingBuffer(unsafe.Pointer(res.shMem), shMem)

	return res, nil
}

func (pe *perfEventHandler) Enable() error {
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(pe.pmuFd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		return fmt.Errorf("error enabling perf event: %v", err)
	}

	return nil
}

func (pe *perfEventHandler) Disable() {
	if pe.pmuFd > 0 {
		if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(pe.pmuFd)), uintptr(uint(unix.PERF_EVENT_IOC_DISABLE)), 0); err != 0 {
			fmt.Errorf("error disabling perf event: %v", err)
		}
		pe.pmuFd = 0
	}
}

func (pe *perfEventHandler) Release() {
	pe.Disable()

	if pe.shMem != nil {
		if err := unix.Munmap(pe.shMemByte); err != nil {
			fmt.Errorf("Unmap failed but we ignore..")
		}
		pe.shMemByte = nil
		pe.shMem = nil
	}

	if pe.pmuFd > 0 {
		unix.Close(pe.pmuFd)
		pe.pmuFd = 0
	}
}

func calculateMmapSize(size int) int {
	pageSize := os.Getpagesize()
	pageCnt := size / pageSize

	// Extra page for mmap metadata header
	return (pageCnt + 2) * pageSize
}
