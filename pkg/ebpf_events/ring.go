package ebpf_events

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps"
	"golang.org/x/sys/unix"
)

const (
	BPF_MAP_TYPE_RINGBUF = 27
)

type Ring struct {
	Consumer_pos    unsafe.Pointer
	Consumer        []byte
	Producer_pos    unsafe.Pointer
	Producer        []byte
	Mask            uint64
	RingBufferMapFD int
	Data            unsafe.Pointer
}

type RingBuffer struct {
	EpollEvent           []unix.EpollEvent
	Rings                []*Ring
	PageSize             int
	EpollFD              int
	RingCnt              int
	stopRingBufferChan   chan struct{}
	updateRingBufferChan chan *Ring
	eventsStopChannel    chan struct{}
	wg                   sync.WaitGroup
	eventsDataChannel    chan []byte
	receivedEvents       chan int
}

func InitRingBuffer(mapFD int) (<-chan []byte, <-chan int, error) {
	if mapFD == -1 {
		return nil, nil, fmt.Errorf("Invalid map FD")
	}
	mapInfo, err := ebpf_maps.GetBPFmapInfo(mapFD)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to map info")
	}

	if mapInfo.Type != BPF_MAP_TYPE_RINGBUF {
		return nil, nil, fmt.Errorf("Unsupported map type, should be - BPF_MAP_TYPE_RINGBUF")
	}

	rb := &RingBuffer{
		PageSize: os.Getpagesize(),
		EpollFD:  -1,
		RingCnt:  0,
	}

	rb.EpollFD, err = unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create epoll instance: %s", err)
	}

	eventsChan, eventsCnt, err := rb.SetupRingBuffer(mapFD, mapInfo.MaxEntries)
	if err != nil {
		rb.CleanupRingBuffer()
		return nil, nil, fmt.Errorf("Failed to add ring buffer: %s", err)
	}

	return eventsChan, eventsCnt, nil
	//return rb, nil
}

func (rb *RingBuffer) SetupRingBuffer(mapFD int, maxEntries uint32) (<-chan []byte, <-chan int, error) {
	ring := &Ring{
		RingBufferMapFD: mapFD,
		Mask:            uint64(maxEntries - 1),
	}

	tmp, err := unix.Mmap(mapFD, 0, rb.PageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create Mmap for consumer -> %d: %s", mapFD, err)
	}

	ring.Consumer_pos = unsafe.Pointer(&tmp[0])
	ring.Consumer = tmp

	mmap_sz := uint32(rb.PageSize) + 2*maxEntries

	tmp, err = unix.Mmap(mapFD, int64(rb.PageSize), int(mmap_sz), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(tmp)
		return nil, nil, fmt.Errorf("Failed to create Mmap for producer -> %d: %s", mapFD, err)
	}

	ring.Producer_pos = unsafe.Pointer(&tmp[0])
	ring.Producer = tmp
	ring.Data = unsafe.Pointer(uintptr(unsafe.Pointer(&tmp[0])) + uintptr(rb.PageSize))
	//ring.Data = tmp[os.Getpagesize():]
	epollEvent := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(rb.RingCnt),
	}

	err = unix.EpollCtl(rb.EpollFD, unix.EPOLL_CTL_ADD, mapFD, &epollEvent)
	if err != nil {
		unix.Munmap(tmp)
		return nil, nil, fmt.Errorf("Failed to Epoll event: %s", err)
	}

	rb.Rings = append(rb.Rings, ring)
	rb.EpollEvent = append(rb.EpollEvent, epollEvent)
	rb.RingCnt++

	//8. Start channels read
	rb.eventsStopChannel = make(chan struct{})
	rb.eventsDataChannel = make(chan []byte)
	rb.receivedEvents = make(chan int)

	rb.wg.Add(1)
	go rb.reconcileEventsDataChannel()
	return rb.eventsDataChannel, rb.receivedEvents, nil
}

func (rb *RingBuffer) CleanupRingBuffer() {

	for i := 0; i < rb.RingCnt; i++ {
		_ = unix.Munmap(rb.Rings[i].Producer)
		_ = unix.Munmap(rb.Rings[i].Consumer)
		rb.Rings[i].Producer_pos = nil
		rb.Rings[i].Consumer_pos = nil
	}

	if rb.EpollFD >= 0 {
		_ = syscall.Close(rb.EpollFD)
	}
	rb.EpollEvent = nil
	rb.Rings = nil
	return
}

func (rb *RingBuffer) reconcileEventsDataChannel() {

	pollerCh := rb.EpollStart()
	defer func() {
		rb.wg.Done()
	}()

	for {
		select {
		case buffer, ok := <-pollerCh:
			if !ok {
				return
			}

			rb.readRingBuffer(buffer)

		case <-rb.eventsStopChannel:
			return
		}
	}
}

func (rb *RingBuffer) EpollStart() <-chan *Ring {

	rb.stopRingBufferChan = make(chan struct{})
	rb.updateRingBufferChan = make(chan *Ring)

	done := make(chan bool)
	go func() {
		defer func() { done <- true }()

		for {
			select {
			case <-rb.stopRingBufferChan:
				return
			default:
				break
			}
			numEvents := rb.poll(rb.EpollEvent[:rb.RingCnt])
			for _, event := range rb.EpollEvent[:numEvents] {
				select {
				case rb.updateRingBufferChan <- rb.Rings[int(event.Fd)]:

				case <-rb.stopRingBufferChan:
					return
				}
			}
		}
	}()

	<-done
	return rb.updateRingBufferChan
}

func (rb *RingBuffer) poll(events []unix.EpollEvent) int {

	timeoutMs := 150
	n, err := unix.EpollWait(rb.EpollFD, events, timeoutMs)
	if err != nil {
		return 0
	}
	return n
}

func (r *Ring) loadConsumer() uint64 {
	return atomic.LoadUint64((*uint64)(r.Consumer_pos))
}

func (r *Ring) loadProducer() uint64 {
	return atomic.LoadUint64((*uint64)(r.Producer_pos))

}

//Ref: libbpf ring buffer implementation
func roundup_len(len uint32) uint32 {
	// Clear out top 2 bits (discard and busy, if set)
	len = (len << 2) >> 2
	// Add length prefix
	len += uint32(ringbufHeaderSize)
	// Round up to 8 byte alignment
	return (len + 7) / 8 * 8
}

var ringbufHeaderSize = binary.Size(ringbufHeader{})

// ringbufHeader from 'struct bpf_ringbuf_hdr' in kernel/bpf/ringbuf.c
type ringbufHeader struct {
	Len   uint32
	PgOff uint32
}

func memcpy(dst, src unsafe.Pointer, count uintptr) {
	for i := uintptr(0); i < count; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(src) + i))
		*(*byte)(unsafe.Pointer(uintptr(dst) + i)) = b
	}
}

//Ref: libbpf ring buffer implementation
func (rb *RingBuffer) readRingBuffer(eventRing *Ring) {
	receivedEvents := 0
	var gotNewData bool
	cons_pos := eventRing.loadConsumer()
	for {
		gotNewData = false
		prod_pos := eventRing.loadProducer()
		for cons_pos < prod_pos {
			//Get the header
			lenPtr := (*int32)(unsafe.Pointer(uintptr(eventRing.Data) + (uintptr(cons_pos) & uintptr(eventRing.Mask))))
			//Length of the data in header
			len := atomic.LoadInt32(lenPtr)

			//Check if busy then skip
			if uint32(len)&unix.BPF_RINGBUF_BUSY_BIT != 0 {
				rb.receivedEvents <- receivedEvents
				return
			}

			gotNewData = true

			//Update consumer position
			cons_pos += uint64(roundup_len(uint32(len)))

			//if not discard
			if uint32(len)&unix.BPF_RINGBUF_DISCARD_BIT == 0 {

				//Got sample
				sample := unsafe.Pointer(uintptr(unsafe.Pointer(lenPtr)) + uintptr(ringbufHeaderSize))

				//Read sample of len bytes from producer
				dataBuf := make([]byte, int(len))
				memcpy(unsafe.Pointer(&dataBuf[0]), sample, uintptr(len))
				/*
					err = r.sample_cb(r.ctx, sample, int(len))
					if err < 0 {
						// Update consumer pos and bail out
						atomic.StoreUint64((*uint64)(r.consumer_pos), consPos)
						return 0, fmt.Errorf("Failed to process sample: %d", err)
					}*/
				rb.eventsDataChannel <- dataBuf
				receivedEvents++
			}

			atomic.StoreUint64((*uint64)(eventRing.Consumer_pos), cons_pos)
		}
		if !gotNewData {
			break
		}
	}
	rb.receivedEvents <- receivedEvents
	return
}
