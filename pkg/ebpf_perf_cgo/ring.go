package perf_cgo

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

type mmapRingBuffer struct {
	ptr   unsafe.Pointer
	start unsafe.Pointer
	end   uintptr
	size  int

	head int
	tail int
}

func NewMmapRingBuffer(ptr unsafe.Pointer, shmmap []byte) *mmapRingBuffer {

	meta_data := (*unix.PerfEventMmapPage)(ptr)
	start := unsafe.Pointer(&shmmap[meta_data.Data_offset])
	size := meta_data.Data_size

	res := &mmapRingBuffer{
		ptr:   ptr,
		start: start,
		size:  int(size),
		end:   uintptr(start) + uintptr(size),
		tail:  int(meta_data.Data_tail),
	}
	return res
}

func memcpy(dst, src unsafe.Pointer, count uintptr) {
	for i := uintptr(0); i < count; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(src) + i))
		*(*byte)(unsafe.Pointer(uintptr(dst) + i)) = b
	}
}

func (b *mmapRingBuffer) Read(size int) []byte {
	if size > b.size {
		size = b.size
	}

	res := make([]byte, size)
	tailPtr := unsafe.Pointer(uintptr(b.start) + uintptr(b.tail%b.size))

	if uintptr(tailPtr)+uintptr(size) > b.end {
		consumed := int(b.end - uintptr(tailPtr))
		memcpy(unsafe.Pointer(&res[0]), tailPtr, uintptr(consumed))
		memcpy(unsafe.Pointer(&res[consumed]), tailPtr, uintptr(size-consumed))
	} else {
		memcpy(unsafe.Pointer(&res[0]), tailPtr, uintptr(size))
	}

	b.tail += size

	return res
}

func (b *mmapRingBuffer) UpdateTail() {
	meta_data := (*unix.PerfEventMmapPage)(b.ptr)
	atomic.StoreUint64(&meta_data.Data_tail, uint64(b.tail))
}

func (b *mmapRingBuffer) DataAvailable() bool {
	meta_data := (*unix.PerfEventMmapPage)(b.ptr)
	b.head = int(meta_data.Data_head)
	return b.head != b.tail
}
