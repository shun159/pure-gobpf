package ebpf

import (
	"fmt"
	"os"
	//"syscall"
	"unsafe"
	"strings"
	"strconv"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"golang.org/x/sys/unix"
)

// if event is nil, we pick funcName
func KprobeAttach(progFD int, eventName string, funcName string) error {

	var log = logger.Get()
	// Register the Kprobe event
	if len(eventName) == 0 {
		eventName = funcName
	}

	kprobeSysEventsFile := "/sys/kernel/debug/tracing/kprobe_events"
	file, err := os.OpenFile(kprobeSysEventsFile, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		log.Infof("error opening kprobe_events file: %v", err)
	    	return fmt.Errorf("error opening kprobe_events file: %v", err)
	}
	defer file.Close()
   
	eventString := fmt.Sprintf("p:kprobes/%s %s", eventName, funcName)
	_, err = file.WriteString(eventString)
	if err != nil {
		log.Infof("error writing to kprobe_events file: %v", err)
	    	return fmt.Errorf("error writing to kprobe_events file: %v", err)
	}

	//Get the Kprobe ID
	kprobeIDpath := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	data, err := os.ReadFile(kprobeIDpath)
	if err != nil {
		log.Infof("Unable to read the kprobeID: %v", err)
		return fmt.Errorf("Unable to read the kprobeID: %v", err)
	}
	id := strings.TrimSpace(string(data))
	eventID, err := strconv.Atoi(id)
	if err != nil {
		log.Infof("Invalid ID during parsing: %s - %v", id, err)
		return fmt.Errorf("Invalid ID during parsing: %s - %w", id, err)
	}
/*
	path := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Infof("Unable to get the ID %v", err)
	    	return fmt.Errorf("Unable to get the ID %v", err)
	}
	id := strings.TrimSpace(string(data))
	eventID := strconv.Atoi(id)
*/
	log.Infof("Got eventID %d", eventID)
	// Open the perf event
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(eventID),
	}
	/*
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Config: unix.PerfEventConfig{Sample_type: unix.PERF_SAMPLE_IP},
	}*/
	attr.Size = uint32(unsafe.Sizeof(attr))

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		log.Infof("Failed to open perf event %v", err)
		return fmt.Errorf("Failed to open perf event %v", err)
	}
	defer unix.Close(fd)

	log.Infof("Attach bpf program to perf event Prog FD %d Event FD %d", progFD, fd)
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(progFD)); err != 0 {
		log.Infof("error attaching bpf program to perf event: %v", err)
		return fmt.Errorf("error attaching bpf program to perf event: %v", err)
	}
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		log.Infof("error enabling perf event: %v", err)
		return fmt.Errorf("error enabling perf event: %v", err)
	}

	/*
	probeAttachAttr := unix.BpfProgAttachAttr{
		TargetFd: fd,
		AttachType: unix.BPF_PROG_TYPE_KPROBE,
		ProgFd: progFD,
	}
	err = unix.IoctlSetPointer(fd, unix.PERF_EVENT_IOC_SET_BPF, uintptr(unsafe.Pointer(&probeAttachAttr)))
	if err != nil {
		panic(err)
	}

	// Enable the event
	err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0)
	if err != nil {
		panic(err)
	}
	*/
	
	return nil

}