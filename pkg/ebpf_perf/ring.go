package perf

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ShmmapRingBuffer struct {
	ptr       unsafe.Pointer
	shMemByte []byte
	tail      int
}

func NewMmapRingBuffer(ptr unsafe.Pointer, shmmap []byte) *ShmmapRingBuffer {

	meta_data := (*unix.PerfEventMmapPage)(ptr)

	res := &ShmmapRingBuffer{
		ptr:       ptr,
		shMemByte: shmmap,
		tail:      int(meta_data.Data_tail),
	}
	return res
}

func memcpy(dst, src unsafe.Pointer, count uintptr) {
	for i := uintptr(0); i < count; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(src) + i))
		*(*byte)(unsafe.Pointer(uintptr(dst) + i)) = b
	}
}

func (b *ShmmapRingBuffer) getRingBufferStart() unsafe.Pointer {
	meta_data := (*unix.PerfEventMmapPage)(b.ptr)
	return unsafe.Pointer(&b.shMemByte[meta_data.Data_offset])
}

func (b *ShmmapRingBuffer) getRingBufferSize() int {
	meta_data := (*unix.PerfEventMmapPage)(b.ptr)
	return int(meta_data.Data_size)
}

func (b *ShmmapRingBuffer) GetRingBufferHead() int {
	meta_data := (*unix.PerfEventMmapPage)(b.ptr)
	return int(meta_data.Data_head)
}

func (b *ShmmapRingBuffer) GetRingBufferTail() int {
	return b.tail
}

// Ref: https://github.com/iovisor/gobpf/blob/b5e5715ad84d6349cb29aea30990bf88f973376d/elf/perf.go#L59
func (b *ShmmapRingBuffer) Read(size int) []byte {
	ringBufferSize := b.getRingBufferSize()
	ringBufferStart := b.getRingBufferStart()
	ringBufferEnd := uintptr(ringBufferStart) + uintptr(ringBufferSize)

	if size > ringBufferSize {
		size = ringBufferSize
	}

	res := make([]byte, size)
	tailPtr := unsafe.Pointer(uintptr(ringBufferStart) + uintptr(b.tail%ringBufferSize))

	if uintptr(tailPtr)+uintptr(size) <= uintptr(ringBufferEnd) {
		//non-overflow case
		memcpy(unsafe.Pointer(&res[0]), tailPtr, uintptr(size))
	} else {
		//Circular buffer
		//Read until the end
		dataToRead := int(uintptr(ringBufferEnd) - uintptr(tailPtr))
		memcpy(unsafe.Pointer(&res[0]), tailPtr, uintptr(dataToRead))
		//read over the size boundary
		memcpy(unsafe.Pointer(&res[dataToRead]), tailPtr, uintptr(size-dataToRead))
	}

	b.tail += size

	return res
}

func (b *ShmmapRingBuffer) RingBufferReadDone() {
	//Reset tail
	meta_data := (*unix.PerfEventMmapPage)(b.ptr)
	atomic.StoreUint64(&meta_data.Data_tail, uint64(b.tail))
}
