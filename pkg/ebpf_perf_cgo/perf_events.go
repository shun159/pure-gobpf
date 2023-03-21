package perf_cgo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps"
	"golang.org/x/sys/unix"
)

var (
	perfEventHeaderSize                  = binary.Size(perfEventHeader{})
)

type PerfEvents struct {
	EventsReceived   int
	EventsLost       int
	EventsUnknowType int

	PollTimeoutMs int
	poller        *perfEventPoller

	mapFD  int
	mapAPI ebpf_maps.APIs

	updatesChannel chan []byte
	stopChannel    chan struct{}
	wg             sync.WaitGroup

	handlers []*perfEventHandler
}

// Same as struct perf_event_header
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

// Same as struct perf_event_lost
type perfEventLost struct {
	Id   uint64
	Lost uint64
}

func NewPerfEvents(mapFD int, mapAPI ebpf_maps.APIs) (*PerfEvents, error) {
	/*
		if m.GetType() != MapTypePerfEventArray {
			return nil, fmt.Errorf("Invalid map type '%v'", m.GetType())
		}*/

	return &PerfEvents{
		mapFD:         mapFD,
		mapAPI:        mapAPI,
		PollTimeoutMs: 100,
	}, nil
}

func getCPUCount() (int, error) {
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

func (pe *PerfEvents) StartForAllProcessesAndCPUs(bufferSize int) (<-chan []byte, error) {

	nCpus, err := getCPUCount()
	if err != nil {
		return nil, fmt.Errorf("Failed to get CPU count: %v", err)
	}

	var handler *perfEventHandler
	pe.handlers = make([]*perfEventHandler, nCpus)
	for cpu := 0; cpu < nCpus; cpu++ {
		handler, err = newPerfEventHandler(cpu, -1, bufferSize) // All processes
		if err != nil {
			// Error handling to be done after for loop
			break
		}
		err = pe.mapAPI.UpdateMapEntry(uintptr(unsafe.Pointer(&cpu)), uintptr(unsafe.Pointer(&handler.pmuFd)), uint32(pe.mapFD))
		if err != nil {
			break
		}
		handler.Enable()
		pe.handlers[cpu] = handler
	}
	if err != nil {
		for _, handler := range pe.handlers {
			if handler != nil {
				handler.Release()
			}
		}
		return nil, err
	}

	pe.startLoop()
	return pe.updatesChannel, nil
}

func (pe *PerfEvents) Stop() {
	pe.poller.Stop()
	close(pe.stopChannel)
	pe.wg.Wait()
	close(pe.updatesChannel)

	for _, handler := range pe.handlers {
		handler.Release()
	}
}

func (pe *PerfEvents) startLoop() {
	pe.stopChannel = make(chan struct{})
	pe.updatesChannel = make(chan []byte)
	pe.wg.Add(1)

	go pe.loop()
}

func (pe *PerfEvents) loop() {
	pe.poller = newPerfEventPoller()
	for _, handler := range pe.handlers {
		pe.poller.Add(handler)
	}

	pollerCh := pe.poller.Start(pe.PollTimeoutMs)
	defer func() {
		pe.wg.Done()
	}()

	for {
		select {
		case handler, ok := <-pollerCh:
			if !ok {
				return
			}

			pe.handlePerfEvent(handler)

		case <-pe.stopChannel:
			return
		}
	}
}

func (pe *PerfEvents) handlePerfEvent(handler *perfEventHandler) {
	for handler.ringBuffer.DataAvailable() {
		var header perfEventHeader
		reader := bytes.NewReader(
			handler.ringBuffer.Read(perfEventHeaderSize),
		)
		binary.Read(reader, binary.LittleEndian, &header)

		data := handler.ringBuffer.Read(
			int(int(header.Size) - perfEventHeaderSize),
		)

		switch header.Type {
		case unix.PERF_RECORD_SAMPLE:
			// Same as struct perf_event_sample and data_size has the data without header
			dataSize := binary.LittleEndian.Uint32(data)
			pe.updatesChannel <- data[4 : dataSize+4]
			pe.EventsReceived++

		case unix.PERF_RECORD_LOST:	
			var lost perfEventLost
			reader := bytes.NewReader(data)
			binary.Read(reader, binary.LittleEndian, &lost)
			pe.EventsLost += int(lost.Lost)

		default:
			pe.EventsUnknowType++
		}
	}

	handler.ringBuffer.UpdateTail()
}
