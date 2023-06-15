package ebpf

import (
	"fmt"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"github.com/vishvananda/netlink"
)

const (
	XDP_ATTACH_MODE_NONE = 0
	XDP_ATTACH_MODE_SKB  = 1
	XDP_ATTACH_MODE_DRV  = 2
	XDP_ATTACH_MODE_HW   = 3
)

var log = logger.Get()

func XDPAttach(interfaceName string, progFD int) error {

	//var log = logger.Get()
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Infof("Failed linkbyname")
		return fmt.Errorf("Get LinkByName failed: %v", err)
	}

	log.Infof("Attaching xdp to interface %s and prog %d", interfaceName, progFD)
	if err := netlink.LinkSetXdpFdWithFlags(link, progFD, int(XDP_ATTACH_MODE_SKB)); err != nil {
		log.Infof("failed to setxdp: %v", err)
		return fmt.Errorf("LinkSetXdpFd failed: %v", err)
	}
	log.Infof("Attached XDP to interface %s", interfaceName)
	return nil
}

func XDPDetach(interfaceName string) error {

	//var log = logger.Get()
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Infof("Failed linkbyname")
		return fmt.Errorf("Get LinkByName failed: %v", err)
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, -1, int(XDP_ATTACH_MODE_SKB)); err != nil {
		log.Infof("failed to setxdp")
		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
	}
	return nil
}
