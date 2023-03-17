package perf_cgo

/*
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#ifdef __linux__
#include <syscall.h>
#include <linux/perf_event.h>
#else
// mocks for Mac
#define PERF_SAMPLE_RAW             1U << 10
#define PERF_TYPE_SOFTWARE          1
#define PERF_COUNT_SW_BPF_OUTPUT    10
#define PERF_EVENT_IOC_DISABLE      0
#define PERF_EVENT_IOC_ENABLE       1
#define __NR_perf_event_open        364
struct perf_event_attr {
    int type, config, sample_type, wakeup_events;
};
#endif


// Disables perf events on pmu_fd create by perf_event_open()
static int perf_event_disable(int pmu_fd)
{
    return ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE, 0);
}

*/
import "C"

import (
	"fmt"
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
	res.ringBuffer = NewMmapRingBuffer(unsafe.Pointer(res.shMem), shMem)

	return res, nil
}

// Enable enables perf events on this fd
func (pe *perfEventHandler) Enable() error {
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(pe.pmuFd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		return fmt.Errorf("error enabling perf event: %v", err)
	}

	return nil
}

// Disable disables perf events on this fd
func (pe *perfEventHandler) Disable() {
	if pe.pmuFd > 0 {
		C.perf_event_disable(C.int(pe.pmuFd))
		pe.pmuFd = 0
	}
}

// Release releases allocated resources:
// - close perf_event fd
// - unmap shared memory
func (pe *perfEventHandler) Release() {
	pe.Disable()

	if pe.shMem != nil {
		C.munmap(pe.shMem, C.size_t(pe.shMemSize))
		pe.shMem = nil
	}

	if pe.pmuFd > 0 {
		C.close(C.int(pe.pmuFd))
		pe.pmuFd = 0
	}
}

// Helper to calculate aligned memory size for mmap.
// First memory page is reserved for mmap metadata,
// so allocating +1 page.
func calculateMmapSize(size int) int {
	pageSize := int(C.getpagesize())
	pageCnt := size / pageSize

	// Extra page for mmap metadata header
	return (pageCnt + 2) * pageSize
}
