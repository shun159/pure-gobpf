package perf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"
	"strings"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"golang.org/x/sys/unix"

)

var (
	ErrClosed                            = os.ErrClosed
	errEOR                               = errors.New("end of ring")
	NativeEndian        binary.ByteOrder = binary.BigEndian
	perfEventHeaderSize                  = binary.Size(perfEventHeader{})
	perfEventSampleSize                  = binary.Size(uint32(0))
)

// perfEventHeader must match 'struct perf_event_header` in <linux/perf_event.h>.
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

type PerfReader struct {
	updatesChannel chan []byte
	stopChannel    chan struct{}
	wg             sync.WaitGroup
	CpuReaders     []*PerfEventPerCPUReader
	PerfEvents     map[int]int
	//Epollfd        int
	CpuCount       int
	poller *Poller
}

type Poller struct {
	// mutexes protect the fields declared below them. If you need to
	// acquire both at once you must lock epollMu before eventMu.
	epollMu sync.Mutex
	epollFd int

	eventMu sync.Mutex
	event   *eventFd
}

//Ref: https://github.com/iovisor/gobpf/blob/b5e5715ad84d6349cb29aea30990bf88f973376d/elf/perf.go
type PerfEventPerCPUReader struct {
	perfFD          int
	cpu             int
	shmmap          []byte
	eventRingBuffer *PerfEventRingBuffer
}

type PerfEventRingBuffer struct {
	meta       *unix.PerfEventMmapPage
	head, tail uint64
	mask       uint64
	ringbuffer []byte
}

type PerfRecord struct {
	CPU int

	// The data submitted via bpf_perf_event_output.
	// Due to a kernel bug, this can contain between 0 and 7 bytes of trailing
	// garbage from the ring depending on the input sample's length.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64
}

// 1+2^n pages
func sharedMemoryPageSize(bufferSize int) int {
	pageSize := os.Getpagesize()
	numPages := bufferSize / pageSize

	return (numPages + 2) * pageSize
}

func newPerfPerCPUReader(cpu, bufferSize, mapFD int, mapAPI ebpf_maps.APIs) (*PerfEventPerCPUReader, error) {

	var log = logger.Get()
	p := PerfEventPerCPUReader{}
	p.cpu = cpu
	watermark := 1
	log.Infof("NewPerfPerCPUReader %d", cpu)
	//Open perf event
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        unix.PerfBitWatermark,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	attr.Size = uint32(unsafe.Sizeof(attr))

	log.Infof("open perf FD")
	perf_fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		log.Infof("Failed to open perf event %v", err)
		return nil, fmt.Errorf("Failed to open perf event %v", err)
	}
	log.Infof("Got ", perf_fd)
	p.perfFD = perf_fd

	log.Info("Got perf_fd and now setting nonblock - ", perf_fd)
	if err := unix.SetNonblock(p.perfFD, true); err != nil {
		unix.Close(p.perfFD)
		return nil, err
	}

	//Shared memory setup
	log.Infof("Setting shared memory for perffd")
	mmap, err := unix.Mmap(p.perfFD, 0, sharedMemoryPageSize(bufferSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(p.perfFD)
		log.Infof("can't mmap: %v", err)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}

	p.shmmap = mmap

	meta_data := (*unix.PerfEventMmapPage)(unsafe.Pointer(&p.shmmap[0]))

	eventRingBuffer := &PerfEventRingBuffer{}
	//BUFFER - p.shmmap[meta_data.Data_offset:meta_data.Data_offset+meta_data.Data_size]
	eventRingBuffer.head = atomic.LoadUint64(&meta_data.Data_head)
	eventRingBuffer.tail = atomic.LoadUint64(&meta_data.Data_tail)
	eventRingBuffer.meta = meta_data
	eventRingBuffer.ringbuffer = p.shmmap[meta_data.Data_offset : meta_data.Data_offset+meta_data.Data_size]
	eventRingBuffer.mask = uint64(cap(eventRingBuffer.ringbuffer) - 1)

	p.eventRingBuffer = eventRingBuffer

	log.Infof("Update perf map %d", mapFD)
	//Map update
	err = mapAPI.UpdateMapEntry(uintptr(unsafe.Pointer(&cpu)), uintptr(unsafe.Pointer(&p.perfFD)), uint32(mapFD))
	if err != nil {
		log.Infof("Failed to updated map, check if BPF_ANY is set")
		unix.Close(p.perfFD)
		return nil, fmt.Errorf("Failed to update map %v", err)
	}

	log.Infof("Enable perf")
	//Enable perf
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(p.perfFD)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		log.Infof("error enabling perf event: %v", err)
		return nil, fmt.Errorf("error enabling perf event: %v", err)
	}
	log.Infof("Done setup for CPU %d", cpu)
	return &p, nil
}

func getCPUCount() (int, error) {
	/*
	cmd := exec.Command("nproc")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(string(output))
	if err != nil {
		return 0, err
	}
	return n, nil
	*/
	path := "/sys/devices/system/cpu/possible"
	specBytes, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	spec := string(specBytes)
	if strings.Trim(spec, "\n") == "0" {
		return 1, nil
	}

	var low, high int
	n, err := fmt.Sscanf(spec, "%d-%d\n", &low, &high)
	if n != 2 || err != nil {
		return 0, fmt.Errorf("invalid format: %s", spec)
	}
	if low != 0 {
		return 0, fmt.Errorf("CPU spec doesn't start at zero: %s", spec)
	}

	// cpus is 0 indexed
	return high + 1, nil
}

func InitPerfBuffer(mapFD int, mapAPI ebpf_maps.APIs) (*PerfReader, error) {
	var log = logger.Get()
	//cpuCount, err := unix.Sysconf(unix._SC_NPROCESSORS_ONLN)
	//cpuCount, err := syscall.Sysconf(syscall._SC_NPROCESSORS_ONLN)
	cpuCount, err := getCPUCount()
	if err != nil {
		log.Infof("Failed to get CPU count: %v", err)
		return nil, fmt.Errorf("Failed to get CPU count: %v", err)
	}

	perfReader := &PerfReader{}

	perfReader.CpuReaders = make([]*PerfEventPerCPUReader, cpuCount)
	//perfReader.Pollfds := make([]syscall.PollFd, 0)
	perfReader.PerfEvents = make(map[int]int)

	for cpu := 0; cpu < cpuCount; cpu++ {
		//This is done for only online CPUs
		cpuReader, err := newPerfPerCPUReader(cpu, 4096, mapFD, mapAPI) 
		//err := perfReader.CpuReaders[cpu].newPerfPerCPUReader(cpu, 4096, mapFD, mapAPI)
		if err != nil {
			//TODO need cleanup here
			log.Infof("Setting up perf buffer failed at cpu %d", cpu)
			return nil, fmt.Errorf("Setting up perf buffer failed at cpu %d", cpu)
		}
		perfReader.CpuReaders[cpu] = cpuReader

		perfReader.PerfEvents[cpu] = perfReader.CpuReaders[cpu].perfFD
		log.Infof("CPU %d -> FD %d", cpu, perfReader.CpuReaders[cpu].perfFD)

	}

	//Add the perfFD to poll
	log.Infof("Create Epoll create")
	pollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create call epollCreate1: %v", err)
	}
	log.Infof("Got pollFD - ", pollFD)

	p := &Poller{epollFd: pollFD}

	p.event, err = newEventFd()
	if err != nil {
		unix.Close(pollFD)
		return nil, err
	}

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(p.event.raw),
		Pad:    int32(0),
	}

	if err := unix.EpollCtl(pollFD, unix.EPOLL_CTL_ADD, p.event.raw, &event); err != nil {
		log.Infof("Failed to add eventFD to manage epoll: %v", err)
		return nil, fmt.Errorf("Failed to add eventFD to manage epoll: %v", err)
	}

	/*
	if err := p.Add(p.event.raw, 0); err != nil {
		unix.Close(epollFd)
		p.event.close()
		return nil, fmt.Errorf("add eventfd: %w", err)
	}
	*/

	//Ideally this can be in previous loop but if any CPU
	//perf-buf fails we don't need to proceed.
	for cpu, perfFD := range perfReader.PerfEvents {
		log.Infof("Adding CPU %d and perfFD %d and epollFD %d to epoll event", cpu, perfFD, pollFD)
		event := unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(perfFD),
			Pad:    int32(cpu),
		}

		if err := unix.EpollCtl(pollFD, unix.EPOLL_CTL_ADD, perfFD, &event); err != nil {
			log.Infof("Failed to add perfFD to manage epoll: %v", err)
			return nil, fmt.Errorf("Failed to add perfFD to manage epoll: %v", err)
		}
	}

	//perfReader.Epollfd = pollFD
	perfReader.poller = p
	perfReader.stopChannel = make(chan struct{})
	perfReader.updatesChannel = make(chan []byte)
	perfReader.wg.Add(1)
	perfReader.CpuCount = cpuCount
	log.Infof("Done Init perf buffer")
	return perfReader, nil

}

/*
func (pe *PerfReader) startPolling() {
	for {
		// Wait for an event to occur on any of the file descriptors in pollfds
		_, err := syscall.Poll(pe.Pollfds, -1)
		if err != nil {
		    log.Fatalf("Error in poll: %v", err)
		}

		// Check which file descriptor has an event
		for cpu, perfFd := range pe.perfEvents {
		    // Get the pollfd struct for this perf event fd
		    pollfd := pe.Pollfds[cpu]

		    if pollfd.REvents&syscall.POLLIN != 0 {
			//At this point we know the CPU and CpuReaders
			pe.parseEvent(pe.CpuReaders[cpu])

		}
	    }
	}
}

func (pe *PerfReader) parseEvent(CpuReaders *PerfEventPerCPUReader) {
	//Read from ring buffer
	for CpuReaders.head != CpuReaders.tail {


	}
}
*/

func (pe *PerfReader) Read() (PerfRecord, error) {
	var rec PerfRecord
	return rec, pe.parseEvent(&rec)
}

func (pe *PerfReader) parseEvent(rec *PerfRecord) error {
	var log = logger.Get()
	if len(pe.PerfEvents) == 0 {
		return fmt.Errorf("None of the perf buffers are initialized")
	}
	log.Info("In Parse Events to read")

	epollEvents := make([]unix.EpollEvent, pe.CpuCount)
	for {
		//Poll for events
		/*
		numEvents, err := unix.EpollWait(pe.Epollfd, epollEvents, -1)
		if err != nil {
			log.Infof("Failed to wait %v", err)
			return err
		}*/
		numEvents, err := pe.wait(epollEvents)
		if err != nil {
			log.Infof("Failed to wait %v", err)
			return err
		}
		log.Info("For num events ", numEvents)
		for _, event := range epollEvents[:numEvents] {
			//Get the CPU
			cpuNum := event.Pad
			rec.CPU = int(cpuNum)
			log.Info("Got for cpu ", int(cpuNum))
			err := pe.readFromRingBuffer(pe.CpuReaders[cpuNum].eventRingBuffer, rec)
			if err == errEOR {
				//continue to next event
				continue
			}
			return err

		}
	}
}

func (pe *PerfReader) wait(events []unix.EpollEvent) (int, error) {
	pe.poller.epollMu.Lock()
	defer pe.poller.epollMu.Unlock()
	for {
		timeout := int(-1)
		n, err := unix.EpollWait(pe.poller.epollFd, events, timeout)
		if temp, ok := err.(temporaryError); ok && temp.Temporary() {
			// Retry the syscall if we were interrupted, see https://github.com/golang/go/issues/20400
			continue
		}

		if err != nil {
			return 0, err
		}

		if n == 0 {
			return 0, fmt.Errorf("epoll wait: %w", os.ErrDeadlineExceeded)
		}

		for _, event := range events[:n] {
			if int(event.Fd) == pe.poller.event.raw {
				// Since we don't read p.event the event is never cleared and
				// we'll keep getting this wakeup until Close() acquires the
				// lock and sets p.epollFd = -1.
				return 0, fmt.Errorf("epoll wait: %w", os.ErrClosed)
			}
		}

		return n, nil
	}
}

func (pe *PerfReader) readFromRingBuffer(rd io.Reader, rec *PerfRecord) error {
	var log = logger.Get()
	buf := make([]byte, perfEventHeaderSize)
	_, err := io.ReadFull(rd, buf)
	if errors.Is(err, io.EOF) {
		log.Info("EOF")
		return errEOR
	} else if err != nil {
		log.Info("Read perf event header %v", err)
		return fmt.Errorf("read perf event header: %v", err)
	}
	header := perfEventHeader{
		NativeEndian.Uint32(buf[0:4]),
		NativeEndian.Uint16(buf[4:6]),
		NativeEndian.Uint16(buf[6:8]),
	}
	switch header.Type {
	case unix.PERF_RECORD_LOST:
		log.Info("Lost record")
		rec.RawSample = rec.RawSample[:0]
		rec.LostSamples, err = readLostRecords(rd)
		return err

	case unix.PERF_RECORD_SAMPLE:
		log.Info("record sample")
		rec.LostSamples = 0
		rec.RawSample, err = readRawSample(rd, buf, rec.RawSample)
		return err
	default:
		return nil
	}

}

//Ref : Cilium
func readLostRecords(rd io.Reader) (uint64, error) {
	// lostHeader must match 'struct perf_event_lost in kernel sources.
	var lostHeader struct {
		ID   uint64
		Lost uint64
	}

	err := binary.Read(rd, NativeEndian, &lostHeader)
	if err != nil {
		return 0, fmt.Errorf("can't read lost records header: %v", err)
	}

	return lostHeader.Lost, nil
}

//Ref : Cilium
// This must match 'struct perf_event_sample in kernel sources.
type perfEventSample struct {
	Size uint32
}

//Ref : Cilium
func readRawSample(rd io.Reader, buf, sampleBuf []byte) ([]byte, error) {
	var log = logger.Get()
	buf = buf[:perfEventSampleSize]
	if _, err := io.ReadFull(rd, buf); err != nil {
		log.Info("Read sample size %v", err)
		return nil, fmt.Errorf("read sample size: %v", err)
	}

	sample := perfEventSample{
		NativeEndian.Uint32(buf),
	}

	var data []byte
	if size := int(sample.Size); cap(sampleBuf) < size {
		data = make([]byte, size)
	} else {
		data = sampleBuf[:size]
	}

	if _, err := io.ReadFull(rd, data); err != nil {
		log.Info("Read sample %v", err)
		return nil, fmt.Errorf("read sample: %v", err)
	}
	log.Info("returning data")
	return data, nil
}

//Ref : Cilium
func (rr *PerfEventRingBuffer) Read(p []byte) (int, error) {
	start := int(rr.tail & rr.mask)

	n := len(p)
	if remainder := cap(rr.ringbuffer) - start; n > remainder {
		n = remainder
	}

	if remainder := int(rr.head - rr.tail); n > remainder {
		n = remainder
	}

	copy(p, rr.ringbuffer[start:start+n])
	rr.tail += uint64(n)

	if rr.tail == rr.head {
		return n, io.EOF
	}

	return n, nil
}

type temporaryError interface {
	Temporary() bool
}

type eventFd struct {
	file *os.File
	// prefer raw over file.Fd(), since the latter puts the file into blocking
	// mode.
	raw int
}

func newEventFd() (*eventFd, error) {
	fd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "event")
	return &eventFd{file, fd}, nil
}

func (efd *eventFd) close() error {
	return efd.file.Close()
}

func (efd *eventFd) add(n uint64) error {
	var buf [8]byte
	NativeEndian.PutUint64(buf[:], 1)
	_, err := efd.file.Write(buf[:])
	return err
}

func (efd *eventFd) read() (uint64, error) {
	var buf [8]byte
	_, err := efd.file.Read(buf[:])
	return NativeEndian.Uint64(buf[:]), err
}
