package ebpf

import (
	"fmt"
	"strings"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

func enableQdisc(link netlink.Link) bool {
	//var log = logger.Get()
	log.Infof("Check if qdisc has to be enabled")
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		log.Infof("Unable to check qdisc hence try installing")
		return true
	}

	qdiscHandle := netlink.MakeHandle(0xffff, 0)
	for _, qdisc := range qdiscs {
		attrs := qdisc.Attrs()
		if attrs.LinkIndex != link.Attrs().Index {
			continue
		}
		if (attrs.Handle&qdiscHandle) == qdiscHandle && attrs.Parent == netlink.HANDLE_INGRESS {
			log.Infof("Found qdisc hence don't install again")
			return false
		}
	}
	log.Infof("Qdisc is not enabled hence install")
	return true

}

func TCIngressAttach(interfaceName string, progFD int) error {
	//var log = logger.Get()
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

	if enableQdisc(intf) {
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: attrs,
			QdiscType:  "clsact",
		}

		if err := netlink.QdiscAdd(qdisc); err != nil {
			log.Infof("Cannot add clsact")
			return fmt.Errorf("cannot add clsact qdisc: %v", err)
		}
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

func TCIngressDetach(interfaceName string) error {
	//var log = logger.Get()
	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Infof("Failed to find device name")
		return fmt.Errorf("failed to find device by name %s: %w", interfaceName, err)
	}

	//Currently supports only one handle, in future we might need to cache the handle
	filterHandle := uint32(0x1)
	filterParent := uint32(netlink.HANDLE_MIN_INGRESS)

	filters, err := netlink.FilterList(intf, filterParent)
	if err != nil {
		log.Infof("Failed to filter list")
		return fmt.Errorf("Failed to get filter list: %v", err)
	}

	for _, filter := range filters {
		if filter.Attrs().Handle == filterHandle {
			err = netlink.FilterDel(filter)
			if err != nil {
				return fmt.Errorf("Delete filter failed on intf %s : %v", interfaceName, err)
			}
			log.Infof("TC filter detach done")
			return nil
		}
	}
	return fmt.Errorf("Detach failed on ingress interface - %s", interfaceName)
}

func TCEgressAttach(interfaceName string, progFD int) error {
	//var log = logger.Get()
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

	if enableQdisc(intf) {
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: attrs,
			QdiscType:  "clsact",
		}

		if err := netlink.QdiscAdd(qdisc); err != nil {
			log.Infof("Cannot add clsact")
			return fmt.Errorf("cannot add clsact qdisc: %v", err)
		}
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

func TCEgressDetach(interfaceName string) error {
	//var log = logger.Get()
	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Infof("Failed to find device name")
		return fmt.Errorf("failed to find device by name %s: %w", interfaceName, err)
	}

	//Currently supports only one handle, in future we might need to cache the handle
	filterHandle := uint32(0x1)
	filterParent := uint32(netlink.HANDLE_MIN_EGRESS)

	filters, err := netlink.FilterList(intf, filterParent)
	if err != nil {
		log.Infof("Failed to filter list")
		return fmt.Errorf("Failed to get filter list: %v", err)
	}

	for _, filter := range filters {
		if filter.Attrs().Handle == filterHandle {
			err = netlink.FilterDel(filter)
			if err != nil {
				return fmt.Errorf("Delete filter failed on intf %s : %v", interfaceName, err)
			}
			log.Infof("TC filter detach done")
			return nil
		}
	}
	return fmt.Errorf("Detach failed on egress interface - %s", interfaceName)
}

func CleanupQdiscs(prefix string) error {
	//var log = logger.Get()

	if prefix == "" {
		log.Infof("Prefix should be given")
		return nil
	}

	linkList, err := netlink.LinkList()
	if err != nil {
		log.Infof("Unable to get link list")
		return err
	}

	for _, link := range linkList {
		linkName := link.Attrs().Name
		if strings.HasPrefix(linkName, prefix) {
			log.Infof("Trying to cleanup on %s", linkName)
			err = TCIngressDetach(linkName)
			if err != nil {
				log.Infof("Failed to detach ingress, might not be present so moving on")
			}

			err = TCEgressDetach(linkName)
			if err != nil {
				log.Infof("Failed to detach ingress, might not be present so moving on")
			}
		}
	}
	return nil
}
