package perf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps"
	"golang.org/x/sys/unix"
)

var (
	perfEventHeaderSize = binary.Size(perfEventHeader{})
	perfBufferSize      = 4096
	possibleCPUpath     = "/sys/devices/system/cpu/possible"
)

type Perf struct {
	MapFD             uint32
	MapAPI            ebpf_maps.APIs
	eventsDataChannel chan []byte
	receivedEvents    chan int
	lostEvents        chan int
	unknownEvents     chan int
	eventsStopChannel chan struct{}
	wg                sync.WaitGroup
	cpuBuffer         []*PerCPUbuffer
	cpuBufferEpoll    *perfEventPoller
}

type PerCPUbuffer struct {
	pmuFd     int
	shMem     unsafe.Pointer
	shMemByte []byte
	shMemSize int

	ringBuffer *ShmmapRingBuffer
}

//Refer to struct perf_event_header
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

//Refer to struct perf_event_lost
type perfEventLost struct {
	Id   uint64
	Lost uint64
}

func getCPUCount() (int, error) {
	specBytes, err := os.ReadFile(possibleCPUpath)
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

	return high + 1, nil
}

func calculateMmapSize() int {
	pageSize := os.Getpagesize()
	pageCnt := perfBufferSize / pageSize
	return (pageCnt + 2) * pageSize
}

func (p *Perf) SetupPerfBuffer() (<-chan []byte, <-chan int, <-chan int, <-chan int, error) {

	// 1. Get number of CPUs running
	nCpus, err := getCPUCount()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to get CPU count: %v", err)
	}

	var buffer *PerCPUbuffer
	p.cpuBuffer = make([]*PerCPUbuffer, nCpus)

	//2. Setup epoll for polling the perf buffers/cpu
	pollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	p.cpuBufferEpoll = &perfEventPoller{
		items:   make(map[int]*ShmmapRingBuffer),
		epollFd: pollFD,
	}

	// 3. Walk thru all CPUs
	for cpu := 0; cpu < nCpus; cpu++ {

		// 4. Setup perf and shared memory per cpu
		buffer, err = SetupPerCPUBuffer(cpu)
		if err != nil {
			p.CleanupBuffers()
			return nil, nil, nil, nil, err
		}

		// 5.. Update the perf FD in the perf event array
		err = p.MapAPI.UpdateMapEntry(uintptr(unsafe.Pointer(&cpu)), uintptr(unsafe.Pointer(&buffer.pmuFd)), p.MapFD)
		if err != nil {
			p.CleanupBuffers()
			return nil, nil, nil, nil, err
		}

		// 6. Enable perf events
		if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(buffer.pmuFd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
			p.CleanupBuffers()
			return nil, nil, nil, nil, fmt.Errorf("error enabling perf event: %v", err)
		}
		p.cpuBuffer[cpu] = buffer

		// 7. Add to epoll ringbuffers of each CPU
		p.cpuBufferEpoll.items[int(buffer.pmuFd)] = buffer.ringBuffer
		p.cpuBufferEpoll.fds = append(p.cpuBufferEpoll.fds, uint32(buffer.pmuFd))

		event := unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(buffer.pmuFd),
		}

		if err := unix.EpollCtl(p.cpuBufferEpoll.epollFd, unix.EPOLL_CTL_ADD, buffer.pmuFd, &event); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	//8. Start channels read
	p.eventsStopChannel = make(chan struct{})
	p.eventsDataChannel = make(chan []byte)
	p.receivedEvents = make(chan int)
	p.lostEvents = make(chan int)
	p.unknownEvents = make(chan int)

	p.wg.Add(1)
	go p.reconcileEventsDataChannel()

	return p.eventsDataChannel, p.receivedEvents, p.lostEvents, p.unknownEvents, nil
}

func (p *Perf) CleanupBuffers() {
	for _, buffer := range p.cpuBuffer {
		if buffer != nil {
			buffer.Release()
		}
	}
}

func (p *Perf) Stop() {
	//Stop epoll
	p.cpuBufferEpoll.Stop()
	//Stop data channel
	close(p.eventsStopChannel)
	p.wg.Wait()
	//Stop all read channels
	close(p.eventsDataChannel)
	close(p.receivedEvents)
	close(p.lostEvents)
	close(p.unknownEvents)
	//Finally cleanup buffers
	p.CleanupBuffers()
}

func (p *Perf) reconcileEventsDataChannel() {

	pollerCh := p.cpuBufferEpoll.Start()
	defer func() {
		p.wg.Done()
	}()

	for {
		select {
		case buffer, ok := <-pollerCh:
			if !ok {
				return
			}

			p.readRingBuffer(buffer)

		case <-p.eventsStopChannel:
			return
		}
	}
}

//Ref: https://github.com/iovisor/gobpf/blob/b5e5715ad84d6349cb29aea30990bf88f973376d/elf/perf.go#L360
func (p *Perf) readRingBuffer(ringBuffer *ShmmapRingBuffer) {
	receivedEvents := 0
	lostEvents := 0
	unknownEvents := 0

	for ringBuffer.GetRingBufferHead() != ringBuffer.GetRingBufferTail() {
		var header perfEventHeader
		//1. Read header
		headerData := ringBuffer.Read(perfEventHeaderSize)
		headerReader := bytes.NewReader(headerData)
		err := binary.Read(headerReader, binary.LittleEndian, &header)
		if err != nil {
			fmt.Errorf("Failed to read header from ringBuffer")
		}
		//2. Get the data part
		dataSize := int(header.Size) - perfEventHeaderSize
		data := ringBuffer.Read(dataSize)

		switch header.Type {
		//3. Read data to channel
		case unix.PERF_RECORD_SAMPLE:
			dataReader := bytes.NewReader(data)
			_, err := io.CopyN(io.Discard, dataReader, 4)
			if err != nil {
				fmt.Errorf("Failed to discard initial 4 bytes")
			}
			dataBuf, err := io.ReadAll(dataReader) // Read remaining bytes into a buffer
			if err != nil {
				fmt.Errorf("Failed to read the data")
			}
			p.eventsDataChannel <- dataBuf
			receivedEvents++

		case unix.PERF_RECORD_LOST:
			var lost perfEventLost
			lostReader := bytes.NewReader(data)
			err := binary.Read(lostReader, binary.LittleEndian, &lost)
			if err != nil {
				fmt.Errorf("Failed to read the lost data")
			}
			lostEvents += int(lost.Lost)

		default:
			unknownEvents++
		}
	}

	//4. read stats to channel
	//Upto the consumer to accumate the total stats
	p.receivedEvents <- receivedEvents
	p.lostEvents <- lostEvents
	p.unknownEvents <- unknownEvents

	ringBuffer.RingBufferReadDone()
}

func SetupPerCPUBuffer(cpu int) (*PerCPUbuffer, error) {

	res := PerCPUbuffer{}

	//Open perf event
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        unix.PerfBitWatermark,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(1),
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

	//Create shared memory
	res.shMemSize = calculateMmapSize()
	shMem, err := unix.Mmap(res.pmuFd, 0, res.shMemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(res.pmuFd)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}
	res.shMem = unsafe.Pointer(&shMem[0])
	res.shMemByte = shMem

	//Setup Ring buffer
	res.ringBuffer = NewMmapRingBuffer(unsafe.Pointer(res.shMem), shMem)

	return &res, nil
}

func (b *PerCPUbuffer) Disable() {
	if b.pmuFd > 0 {
		if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(b.pmuFd)), uintptr(uint(unix.PERF_EVENT_IOC_DISABLE)), 0); err != 0 {
			fmt.Errorf("error disabling perf event: %v", err)
		}
		b.pmuFd = 0
	}
}

func (b *PerCPUbuffer) Release() {
	b.Disable()

	if b.shMem != nil {
		if err := unix.Munmap(b.shMemByte); err != nil {
			fmt.Errorf("Unmap Failed")
		}
		b.shMemByte = nil
		b.shMem = nil
	}

	if b.pmuFd > 0 {
		unix.Close(b.pmuFd)
		b.pmuFd = 0
	}
}
