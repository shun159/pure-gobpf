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

// Opens perf event on given cpu_id and/or pid
// Returns pmu_fd (processor monitoring unit fd)
static int perf_event_open(int cpu_id, int pid, void *error_buf, size_t error_size)
{
    struct perf_event_attr attr = {
        .sample_type    = PERF_SAMPLE_RAW,
        .type           = PERF_TYPE_SOFTWARE,
        .config         = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events  = 1,
    };

    // Open perf events for given CPU
#ifdef __linux
	int pmu_fd = syscall(__NR_perf_event_open, &attr, pid, cpu_id, -1, 0);
    if (pmu_fd <= 0) {
        strncpy(error_buf, strerror(errno), error_size);
    }
	return pmu_fd;
#else
	return 0;
#endif
}

// Enables perf events on pmu_fd create by perf_event_open()
static int perf_event_enable(int pmu_fd, void *error_buf, size_t error_size)
{
    int res = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
    if (res < 0) {
        strncpy(error_buf, strerror(errno), error_size);
    }

    return res;
}

// Disables perf events on pmu_fd create by perf_event_open()
static int perf_event_disable(int pmu_fd)
{
    return ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE, 0);
}

// Makes shared memory between kernel and user spaces (mmap)
// returns pointer to shared memory
static void *perf_event_mmap(int perf_map_fd, size_t size, void *error_buf, size_t error_size)
{
    void *buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_map_fd, 0);
    if (buf == MAP_FAILED) {
        strncpy(error_buf, strerror(errno), error_size);
        return NULL;
    }

    return buf;
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
	// Calculate null terminated string len
	slen := len(val)
	for idx, ch := range val {
		if ch == 0 {
			slen = idx
			break
		}
	}
	return string(val[:slen])
}
// perfEventHandler is responsible for open / close / configure system perf_events
type perfEventHandler struct {
	pmuFd     int
	shMem     unsafe.Pointer
	shMemSize int

	ringBuffer *mmapRingBuffer
}

// newPerfEventHandler opens perf_event on given CPU / PID
// it also mmap memory of bufferSize to new perf event fd.
func newPerfEventHandler(cpu, pid int, bufferSize int) (*perfEventHandler, error) {
	//var errorBuf [errCodeBufferSize]byte

	res := &perfEventHandler{
		shMemSize: calculateMmapSize(bufferSize),
	}

	// Create perf event fd

	/*
	res.pmuFd = C.perf_event_open(
		C.int(cpu),
		C.int(pid),
		unsafe.Pointer(&errorBuf[0]), C.size_t(unsafe.Sizeof(errorBuf)),
	)
	if res.pmuFd <= 0 {
		return nil, fmt.Errorf("Unable to perf_event_open(): %v",
			NullTerminatedStringToString(errorBuf[:]))
	}
	*/

	watermark := 1
	//log.Infof("NewPerfPerCPUReader %d", cpu)
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

	// Create shared memory between kernel and userspace (mmap)
	/*
	res.shMem = C.perf_event_mmap(
		res.pmuFd,
		C.size_t(res.shMemSize),
		unsafe.Pointer(&errorBuf[0]), C.size_t(unsafe.Sizeof(errorBuf)),
	)
	if res.shMem == nil {
		C.close(res.pmuFd)
		res.pmuFd = 0
		return nil, fmt.Errorf("Unable to mmap(): %v",
			NullTerminatedStringToString(errorBuf[:]))
	}*/

	shMem, err := unix.Mmap(res.pmuFd, 0, res.shMemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(res.pmuFd)
		//log.Infof("can't mmap: %v", err)
		return nil, fmt.Errorf("can't mmap: %v", err)
	} 
	res.shMem = unsafe.Pointer(&shMem[0])
	res.ringBuffer = NewMmapRingBuffer(unsafe.Pointer(res.shMem))

	return res, nil
}

// Enable enables perf events on this fd
func (pe *perfEventHandler) Enable() error {
	var errorBuf [errCodeBufferSize]byte

	res := C.perf_event_enable(
		C.int(pe.pmuFd),
		unsafe.Pointer(&errorBuf[0]), C.size_t(unsafe.Sizeof(errorBuf)), // error message
	)
	if res < 0 {
		return fmt.Errorf("Unable to perf_event_enable(): %v",
			NullTerminatedStringToString(errorBuf[:]))
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
