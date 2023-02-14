package ebpf

import (
	"fmt"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TCIngressAttach(interfaceName string, progFD int) error {
	var log = logger.Get()
	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Infof("Failed to find device name")
		return fmt.Errorf("failed to find device by name %s: %w", interfaceName, err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_INGRESS,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Infof("Cannot add clsact")
		return fmt.Errorf("cannot add clsact qdisc: %v", err)
	}

	// construct the filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: attrs.LinkIndex,
			Parent:    uint32(netlink.HANDLE_MIN_INGRESS),
			Handle:    0x1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFD,
		Name:         "handle_ingress",
		DirectAction: true,
	}

	if err = netlink.FilterAdd(filter); err != nil {
		log.Infof("while loading egress program %q on fd %d: %v", "handle ingress", progFD, err)
		return fmt.Errorf("while loading egress program %q on fd %d: %v", "handle ingress", progFD, err)
	}
	log.Infof("TC filter add done")
	return nil
}

func TCEgressAttach(interfaceName string, progFD int) error {
	var log = logger.Get()
	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Infof("Failed to find device name")
		return fmt.Errorf("failed to find device by name %s: %w", interfaceName, err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_INGRESS,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Infof("Cannot add clsact")
		return fmt.Errorf("cannot add clsact qdisc: %v", err)
	}

	// construct the filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: attrs.LinkIndex,
			Parent:    uint32(netlink.HANDLE_MIN_EGRESS),
			Handle:    0x1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFD,
		Name:         "handle_egress",
		DirectAction: true,
	}

	if err = netlink.FilterAdd(filter); err != nil {
		log.Infof("while loading egress program %q on fd %d: %v", "handle egress", progFD, err)
		return fmt.Errorf("while loading egress program %q on fd %d: %v", "handle egress", progFD, err)
	}
	log.Infof("TC filter add done")
	return nil
}
