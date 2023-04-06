package perf

import (
	"golang.org/x/sys/unix"
)

type perfEventPoller struct {
	items   map[int]*ShmmapRingBuffer
	fds     []uint32
	epollFd int

	stopRingBufferChan   chan struct{}
	updateRingBufferChan chan *ShmmapRingBuffer
}

func (p *perfEventPoller) Start() <-chan *ShmmapRingBuffer {

	p.stopRingBufferChan = make(chan struct{})
	p.updateRingBufferChan = make(chan *ShmmapRingBuffer)

	done := make(chan bool)
	go func() {
		defer func() { done <- true }()

		for {
			select {
			case <-p.stopRingBufferChan:
				return
			default:
				break
			}
			events := make([]unix.EpollEvent, len(p.items))
			numEvents := p.poll(events)
			for _, event := range events[:numEvents] {
				select {
				case p.updateRingBufferChan <- p.items[int(event.Fd)]:

				case <-p.stopRingBufferChan:
					return
				}
			}
		}
	}()

	<-done
	return p.updateRingBufferChan
}

func (p *perfEventPoller) Stop() {
	close(p.stopRingBufferChan)
	close(p.updateRingBufferChan)
}

func (p *perfEventPoller) poll(events []unix.EpollEvent) int {

	timeoutMs := 150
	n, err := unix.EpollWait(p.epollFd, events, timeoutMs)
	if err != nil {
		return 0
	}
	return n
}
