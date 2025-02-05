// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

package ebpf_kprobe

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"golang.org/x/sys/unix"
)

const (
	kprobeSysEventsFile = "/sys/kernel/debug/tracing/kprobe_events"
)

var log = logger.Get()

/*
 p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]  : Set a probe
 r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]  : Set a return probe
 -:[GRP/]EVENT
*/
// if event is nil, we pick funcName
func KprobeAttach(progFD int, eventName string, funcName string) error {

	//var log = logger.Get()

	if progFD <= 0 {
		log.Infof("Invalid BPF prog FD %d", progFD)
		return fmt.Errorf("Invalid BPF prog FD %d", progFD)

	}

	if len(eventName) == 0 {
		eventName = funcName
	}

	// Register the Kprobe event
	file, err := os.OpenFile(kprobeSysEventsFile, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		log.Infof("error opening kprobe_events file: %v", err)
		return fmt.Errorf("error opening kprobe_events file: %v", err)
	}
	//defer file.Close()

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

/*
 p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]  : Set a probe
 r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]  : Set a return probe
 -:[GRP/]EVENT

MAXACTIVE      : Maximum number of instances of the specified function that
                 can be probed simultaneously, or 0 for the default value
                 as defined in Documentation/kprobes.txt section 1.3.1.

*/

// if event is nil, we pick funcName
func KretprobeAttach(progFD int, eventName string, funcName string) error {

	//var log = logger.Get()

	if progFD <= 0 {
		log.Infof("Invalid BPF prog FD %d", progFD)
		return fmt.Errorf("Invalid BPF prog FD %d", progFD)

	}

	if len(eventName) == 0 {
		eventName = funcName
	}

	// Register the Kprobe event
	file, err := os.OpenFile(kprobeSysEventsFile, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		log.Infof("error opening kprobe_events file: %v", err)
		return fmt.Errorf("error opening kprobe_events file: %v", err)
	}
	//defer file.Close()

	eventString := fmt.Sprintf("r4096:kretprobes/%s %s", eventName, funcName)
	_, err = file.WriteString(eventString)
	if err != nil {
		log.Infof("error writing to kprobe_events file: %v", err)
		return fmt.Errorf("error writing to kprobe_events file: %v", err)
	}

	//Get the Kprobe ID
	kprobeIDpath := fmt.Sprintf("/sys/kernel/debug/tracing/events/kretprobes/%s/id", eventName)
	data, err := os.ReadFile(kprobeIDpath)
	if err != nil {
		log.Infof("Unable to read the kretprobeID: %v", err)
		return fmt.Errorf("Unable to read the kretprobeID: %v", err)
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

func KprobeDetach(eventName string) error {
	//var log = logger.Get()
	log.Infof("Calling Detach on %s", eventName)
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
