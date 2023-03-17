package perf_cgo

import (
	"sync"

	"golang.org/x/sys/unix"
)

type perfEventPoller struct {
	items     map[int]*perfEventHandler
	wg        sync.WaitGroup
	fds       []uint32
	timeoutMs int
	epollFd   int

	stopChannel   chan struct{}
	updateChannel chan *perfEventHandler
}

func newPerfEventPoller() *perfEventPoller {
	pollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil
	}
	return &perfEventPoller{
		items:   make(map[int]*perfEventHandler),
		epollFd: pollFD,
	}
}

func (p *perfEventPoller) Add(handler *perfEventHandler) {
	p.items[int(handler.pmuFd)] = handler

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(handler.pmuFd),
	}

	if err := unix.EpollCtl(p.epollFd, unix.EPOLL_CTL_ADD, handler.pmuFd, &event); err != nil {
		return
	}
}

func (p *perfEventPoller) Start(timeoutMs int) <-chan *perfEventHandler {
	p.fds = make([]uint32, len(p.items))
	var idx int
	for fd := range p.items {
		p.fds[idx] = uint32(fd)
		idx++
	}

	p.timeoutMs = timeoutMs
	p.stopChannel = make(chan struct{})
	p.updateChannel = make(chan *perfEventHandler)
	p.wg.Add(1)

	go p.loop()

	return p.updateChannel
}

func (p *perfEventPoller) Stop() {
	close(p.stopChannel)
	p.wg.Wait()
	close(p.updateChannel)
}

/*
type temporaryError interface {
	Temporary() bool
}*/

func (p *perfEventPoller) poll(events []unix.EpollEvent) int {
	var fds []unix.PollFd
	for _, perfFD := range p.fds {
		fd := unix.PollFd{Fd: int32(perfFD), Events: unix.POLLIN | unix.POLLERR}
		fds = append(fds, fd)
	}

	n, err := unix.EpollWait(p.epollFd, events, p.timeoutMs)
	/*
		if temp, ok := err.(temporaryError); ok && temp.Temporary() {
			// Retry the syscall if we were interrupted, see https://github.com/golang/go/issues/20400
			continue
		}*/
	if err != nil {
		return 0
	}

	return n
}

func (p *perfEventPoller) loop() {
	defer p.wg.Done()

	for {
		select {
		case <-p.stopChannel:
			return
		default:
			break
		}
		events := make([]unix.EpollEvent, len(p.items))
		readyCnt := p.poll(events)
		for _, event := range events[:readyCnt] {
			select {
			case p.updateChannel <- p.items[int(event.Fd)]:

			case <-p.stopChannel:
				return
			}
		}
	}
}
