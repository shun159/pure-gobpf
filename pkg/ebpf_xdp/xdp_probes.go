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

package ebpf_xdp

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
