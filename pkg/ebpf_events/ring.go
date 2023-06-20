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
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

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
	epoll_wg             sync.WaitGroup
	eventsDataChannel    chan []byte
}

func InitRingBuffer(mapFD int) (<-chan []byte, error) {
	//var log = logger.Get()
	if mapFD == -1 {
		return nil, fmt.Errorf("Invalid map FD")
	}
	mapInfo, err := ebpf_maps.GetBPFmapInfo(mapFD)
	if err != nil {
		return nil, fmt.Errorf("Failed to map info")
	}
	log.Infof("Got map FD %d", mapFD)
	if mapInfo.Type != BPF_MAP_TYPE_RINGBUF {
		return nil, fmt.Errorf("Unsupported map type, should be - BPF_MAP_TYPE_RINGBUF")
	}

	rb := &RingBuffer{
		PageSize: os.Getpagesize(),
		EpollFD:  -1,
		RingCnt:  0,
	}

	rb.EpollFD, err = unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("Failed to create epoll instance: %s", err)
	}

	eventsChan, err := rb.SetupRingBuffer(mapFD, mapInfo.MaxEntries)
	if err != nil {
		rb.CleanupRingBuffer()
		return nil, fmt.Errorf("Failed to add ring buffer: %s", err)
	}
	log.Infof("Ringbuffer setup done")
	return eventsChan, nil
}

func (rb *RingBuffer) SetupRingBuffer(mapFD int, maxEntries uint32) (<-chan []byte, error) {
	ring := &Ring{
		RingBufferMapFD: mapFD,
		Mask:            uint64(maxEntries - 1),
	}

	// [Consumer page - 4k][Producer page - 4k][Data section - twice the size of max entries]
	// Refer kernel code, twice the size of max entries will help in boundary scenarios

	tmp, err := unix.Mmap(mapFD, 0, rb.PageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Mmap for consumer -> %d: %s", mapFD, err)
	}

	ring.Consumer_pos = unsafe.Pointer(&tmp[0])
	ring.Consumer = tmp

	mmap_sz := uint32(rb.PageSize) + 2*maxEntries
	tmp, err = unix.Mmap(mapFD, int64(rb.PageSize), int(mmap_sz), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(tmp)
		return nil, fmt.Errorf("Failed to create Mmap for producer -> %d: %s", mapFD, err)
	}

	ring.Producer_pos = unsafe.Pointer(&tmp[0])
	ring.Producer = tmp
	ring.Data = unsafe.Pointer(uintptr(unsafe.Pointer(&tmp[0])) + uintptr(rb.PageSize))
	
	epollEvent := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(rb.RingCnt),
	}

	err = unix.EpollCtl(rb.EpollFD, unix.EPOLL_CTL_ADD, mapFD, &epollEvent)
	if err != nil {
		unix.Munmap(tmp)
		return nil, fmt.Errorf("Failed to Epoll event: %s", err)
	}

	rb.Rings = append(rb.Rings, ring)
	rb.EpollEvent = append(rb.EpollEvent, epollEvent)
	rb.RingCnt++

	//8. Start channels read
	rb.eventsStopChannel = make(chan struct{})
	rb.eventsDataChannel = make(chan []byte)

	rb.wg.Add(1)
	go rb.reconcileEventsDataChannel()
	return rb.eventsDataChannel, nil
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
			rb.ReadRingBuffer(buffer)

		case <-rb.eventsStopChannel:
			return
		}
	}
}

func (rb *RingBuffer) EpollStart() <-chan *Ring {

	rb.stopRingBufferChan = make(chan struct{})
	rb.updateRingBufferChan = make(chan *Ring)
	rb.epoll_wg.Add(1)
	go rb.eventsPoller()

	return rb.updateRingBufferChan
}

func (rb *RingBuffer) eventsPoller() {
	defer rb.epoll_wg.Done()
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
}

func (rb *RingBuffer) poll(events []unix.EpollEvent) int {

	timeoutMs := 150
	n, err := unix.EpollWait(rb.EpollFD, events, timeoutMs)
	if err != nil {
		return 0
	}
	return n
}

func (r *Ring) getConsumerPosition() uint64 {
	return atomic.LoadUint64((*uint64)(r.Consumer_pos))
}

func (r *Ring) getProducerPosition() uint64 {
	return atomic.LoadUint64((*uint64)(r.Producer_pos))

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

// Similar to libbpf poll buffer
func (rb *RingBuffer) ReadRingBuffer(eventRing *Ring) {
	var done bool
	cons_pos := eventRing.getConsumerPosition()
	for {
		done = true
		prod_pos := eventRing.getProducerPosition()
		for cons_pos < prod_pos {

			//Get the header - Data points to the DataPage which will be offset by cons_pos
			buf := (*int32)(unsafe.Pointer(uintptr(eventRing.Data) + (uintptr(cons_pos) & uintptr(eventRing.Mask))))

			//Get the len which is uint32 in header struct
			Hdrlen := atomic.LoadInt32(buf)
			
			//Check if busy then skip
			if uint32(Hdrlen)&unix.BPF_RINGBUF_BUSY_BIT != 0 {
				done = true
				break
			}

			done = false

			// Len in ringbufHeader has busy and discard bit so skip it
			dataLen := (((uint32(Hdrlen) << 2) >> 2) + uint32(ringbufHeaderSize))
			//round up dataLen to nearest 8-byte alignment
			roundedDataLen := (dataLen + 7) &^ 7

			cons_pos += uint64(roundedDataLen)

			if uint32(Hdrlen)&unix.BPF_RINGBUF_DISCARD_BIT == 0 {
				readableSample := unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(ringbufHeaderSize))
				dataBuf := make([]byte, int(roundedDataLen))
				memcpy(unsafe.Pointer(&dataBuf[0]), readableSample, uintptr(roundedDataLen))
				rb.eventsDataChannel <- dataBuf
			}

			atomic.StoreUint64((*uint64)(eventRing.Consumer_pos), cons_pos)
		}
		if done {
			break
		}
	}
}
