package ebpf_tracepoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	//"syscall"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

// if event is nil, we pick funcName
func TracepointAttach(progFD int, subSystem, eventName string) error {

	//var log = logger.Get()

	if progFD <= 0 {
		log.Infof("Invalid BPF prog FD %d", progFD)
		return fmt.Errorf("Invalid BPF prog FD %d", progFD)

	}

	if len(subSystem) == 0 || len(eventName) == 0 {
		log.Infof("Invalid Arg")
		return fmt.Errorf("Invalid Arguement")
	}

	//Get the TP ID
	tracepointIDpath := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", subSystem, eventName)
	data, err := os.ReadFile(tracepointIDpath)
	if err != nil {
		log.Infof("Unable to read the tracepointID: %v", err)
		return fmt.Errorf("Unable to read the tracepointID: %v", err)
	}
	id := strings.TrimSpace(string(data))
	eventID, err := strconv.Atoi(id)
	if err != nil {
		log.Infof("Invalid ID during parsing: %s - %v", id, err)
		return fmt.Errorf("Invalid ID during parsing: %s - %w", id, err)
	}

	log.Infof("Got eventID %d", eventID)

	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Sample: 1,
		Wakeup: 1,
		Config: uint64(eventID),
	}
	attr.Size = uint32(unsafe.Sizeof(attr))

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		log.Infof("Failed to open perf event %v", err)
		return fmt.Errorf("Failed to open perf event %v", err)
	}
	//defer unix.Close(fd)

	log.Infof("Attach bpf program to perf event Prog FD %d Event FD %d", progFD, fd)

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_SET_BPF)), uintptr(progFD)); err != 0 {
		log.Infof("error attaching bpf program to perf event: %v", err)
		return fmt.Errorf("error attaching bpf program to perf event: %v", err)
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		log.Infof("error enabling perf event: %v", err)
		return fmt.Errorf("error enabling perf event: %v", err)
	}

	log.Infof("Attach done!!! %d", fd)
	return nil

}
