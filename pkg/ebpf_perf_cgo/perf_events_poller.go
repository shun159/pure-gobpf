package perf_cgo 

/*
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int perf_events_poll(void *_fds, int cnt, int timeout)
{
    int *fds = _fds;
    int *fds_end = fds + cnt;

    // Allocate N pollfd structs
    size_t pollfds_size = sizeof(struct pollfd) * cnt;
    void *pollfds_memory = malloc(pollfds_size);
    memset(pollfds_memory, 0, pollfds_size);

    // Initialize pollfds from GO array of uint32 fds
    struct pollfd *pollfds = pollfds_memory;
    struct pollfd *pollfds_end = pollfds + cnt;
    for (; fds != fds_end; fds++, pollfds++) {
        pollfds->fd = *fds;
        pollfds->events = POLLIN;
    }
    // Re-set pointers to start of arrays
    pollfds = pollfds_memory;
    fds = _fds;

    int ready_cnt = poll(pollfds, cnt, timeout);

    // Copy all ready descriptors back into golang array of uint32s
    for (int remain = ready_cnt; remain > 0 && pollfds != pollfds_end; pollfds++) {
        if (pollfds->revents & POLLIN) {
            *fds = pollfds->fd;
            fds++;
            remain--;
        }
    }

    free(pollfds_memory);
    return ready_cnt;
}

*/
import "C"
import (
	"sync"
	//"unsafe"
	"golang.org/x/sys/unix"
)

type perfEventPoller struct {
	items     map[int]*perfEventHandler
	wg        sync.WaitGroup
	fds       []uint32
	timeoutMs int
	epollFd int

	stopChannel   chan struct{}
	updateChannel chan *perfEventHandler
}

func newPerfEventPoller() *perfEventPoller {
	pollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil
	}
	return &perfEventPoller{
		items: make(map[int]*perfEventHandler),
		epollFd: pollFD,
	}
}

func (p *perfEventPoller) Add(handler *perfEventHandler) {
	p.items[int(handler.pmuFd)] = handler

	//Add to epoll FD
	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(handler.pmuFd),
	}

	if err := unix.EpollCtl(p.epollFd, unix.EPOLL_CTL_ADD, handler.pmuFd, &event); err != nil {
		//log.Infof("Failed to add perfFD to manage epoll: %v", err)
		//return nil, fmt.Errorf("Failed to add perfFD to manage epoll: %v", err)
		return
	}
}

func (p *perfEventPoller) Start(timeoutMs int) <-chan *perfEventHandler {
	// Create array of uint32 for fds to be used from C function
	p.fds = make([]uint32, len(p.items))
	var idx int
	for fd := range p.items {
		p.fds[idx] = uint32(fd)
		idx++
	}

	// Start poll loop
	p.timeoutMs = timeoutMs
	p.stopChannel = make(chan struct{})
	p.updateChannel = make(chan *perfEventHandler)
	p.wg.Add(1)

	go p.loop()

	return p.updateChannel
}

func (p *perfEventPoller) Stop() {
	// Stop loop
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

	/*
	n, err := unix.PerfEventPoll(fds, p.timeoutMs) 
	if err != nil {
		n = 0
	}*/
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
		// Check stopChannel for close
		select {
		case <-p.stopChannel:
			return
		default:
			break
		}

		// Run poll()
		/*
		readyCnt := int(C.perf_events_poll(
			unsafe.Pointer(&p.fds[0]),
			C.int(len(p.items)),
			C.int(p.timeoutMs),
		))*/
		//Events will be length of fd items
		events := make([]unix.EpollEvent, len(p.items))
		readyCnt := p.poll(events)
		// Send perfEventHandlers with pending updates, if any
		for _, event := range events[:readyCnt] {
		//for i := 0; i < readyCnt; i++ {
			select {
			case p.updateChannel <- p.items[int(event.Fd)]:

			case <-p.stopChannel:
				return
			}
		}
	}
}
