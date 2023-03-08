package ebpf
/*
	#include <linux/perf_event.h>
	#include <linux/version.h>
	#include <sys/syscall.h>
	#define SYSCALL(...) syscall(__VA_ARGS__)
	#include <unistd.h>
	#include <sys/ioctl.h>
	//#include "bpf_helpers.h"

	static int kprobe_perf_event_open(int progFd, long id) {
		struct perf_event_attr attr = {};
		attr.config = id;
		attr.type = PERF_TYPE_TRACEPOINT;
		attr.sample_period = 1;
		attr.wakeup_events = 1;
		int pfd = SYSCALL(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
		if (pfd < 0) {
			//fprintf(stderr, "perf_event_open(%s/id): %s\n", event_path,
			//strerror(errno));
			return -1;
		}
		if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, progFd) < 0) {
			//perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
			return -2;
		}
		if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
			//perror("ioctl(PERF_EVENT_IOC_ENABLE)");
			return -3;
		}
		return pfd;
	}
*/
import "C"
import (
	"fmt"
	"os"
	"syscall"
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
	
	log.Infof("Got eventID %d", eventID)

	//TEMP FIX

	retFD := int(C.kprobe_perf_event_open(C.int(progFD), C.long(eventID)))
	if retFD < 0 {
		return fmt.Errorf("kprobe_perf_event_open error %d", retFD)
	}

	
	// Open the perf event
	testeventString := fmt.Sprintf("p:kprobes/%s %s", "test", funcName)
	_, err = file.WriteString(testeventString)
	if err != nil {
		log.Infof("error writing to kprobe_events file: %v", err)
	    	return fmt.Errorf("error writing to kprobe_events file: %v", err)
	}

	//Get the Kprobe ID
	testkprobeIDpath := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", "test")
	testdata, err := os.ReadFile(testkprobeIDpath)
	if err != nil {
		log.Infof("Unable to read the kprobeID: %v", err)
		return fmt.Errorf("Unable to read the kprobeID: %v", err)
	}
	testid := strings.TrimSpace(string(testdata))
	testeventID, err := strconv.Atoi(testid)
	if err != nil {
		log.Infof("Invalid ID during parsing: %s - %v", testid, err)
		return fmt.Errorf("Invalid ID during parsing: %s - %w", testid, err)
	}
	
	log.Infof("Got eventID %d", testeventID)

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(testeventID),
	}
	attr.Size = uint32(unsafe.Sizeof(attr))

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		log.Infof("Failed to open perf event %v", err)
		return fmt.Errorf("Failed to open perf event %v", err)
	}
	defer unix.Close(fd)
	log.Infof("Unix call returned FD %d", fd)

	/*
	log.Infof("Attach bpf program to perf event Prog FD %d Event FD %d", progFD, fd)
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_SET_BPF)), uintptr(progFD)); err != 0 {
		log.Infof("error attaching bpf program to perf event: %v", err)
		return fmt.Errorf("error attaching bpf program to perf event: %v", err)
	}
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		log.Infof("error enabling perf event: %v", err)
		return fmt.Errorf("error enabling perf event: %v", err)
	}
	*/

	/*
	attr := unix.PerfEventAttr{}
	attr.Type, err = kprobePerfType()
	if err != nil {
		log.Infof("unable to determine kprobe perf type: %w", err)
		return fmt.Errorf("unable to determine kprobe perf type: %w", err)
	}
	attr.Size = uint32(unsafe.Sizeof(attr))
	attr.Ext1 = uint64(uintptr(cstr(funcName)))
	attr.Ext2 = 0

	efd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 || err != nil {
		log.Infof("perf_event_open error: %w", err)
		return fmt.Errorf("perf_event_open error: %w", err)
	}
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(progFD)); err != 0 {
		log.Infof("error attaching bpf program to perf event: %w", err)
		return fmt.Errorf("error attaching bpf program to perf event: %w", err)
	}
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		log.Infof("error enabling perf event: %w", err)
		return fmt.Errorf("error enabling perf event: %w", err)
	}*/
	
	log.Infof("Attach done!!! %d", retFD)
	return nil

}

func cstr(s string) unsafe.Pointer {
	// zero terminate the string
	buf := make([]byte, len(s)+1)
	copy(buf, s)

	return unsafe.Pointer(&buf[0])
}

func kprobePerfType() (uint32, error) {
	f, err := os.Open("/sys/bus/event_source/devices/kprobe/type")
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	var kt int
	_, err = fmt.Fscanf(f, "%d\n", &kt)
	return uint32(kt), err
}

func KprobeDetach(eventName string) error {
	var log = logger.Get()
	log.Infof("Calling Detach on %s", eventName)
	kprobeSysEventsFile := "/sys/kernel/debug/tracing/kprobe_events"
	file, err := os.OpenFile(kprobeSysEventsFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		log.Infof("Cannot open file to detach")
		return fmt.Errorf("cannot open kprobe events: %v", err)
	}
	defer file.Close()
	
	eventString := fmt.Sprintf("-:%s\n", eventName)
	if _, err = file.WriteString(eventString); err != nil {
		pathErr, ok := err.(*os.PathError)
		if ok && pathErr.Err == syscall.ENOENT {
			log.Infof("File is already cleanedup, maybe some other process?")
			return nil
		}
		log.Infof("Cannot update the kprobe events %v", err)
		return fmt.Errorf("cannot update the kprobe_events: %v", err)
	}
	log.Infof("Detach done!!!")
	return nil
}