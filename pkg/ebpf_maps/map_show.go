package ebpf_maps

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

const (
	BPF_OBJ_GET            = 7
	BPF_MAP_GET_NEXT_ID    = 12
	BPF_MAP_GET_FD_BY_ID   = 14
	BPF_OBJ_GET_INFO_BY_FD = 15

	BPFObjNameLen    = 16
	BPFProgInfoAlign = 8
	BPFTagSize       = 8
)

// Ref: https://github.com/libbpf/libbpf/blob/f8cd00f61302ca4d8645e007acf7f546dc323b33/include/uapi/linux/bpf.h
type BpfMapInfo struct {
	Type                  uint32
	Id                    uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	Name                  [BPFObjNameLen]byte
	IfIndex               uint32
	BtfVmLinuxValueTypeId uint32
	NetnsDev              uint64
	NetnsIno              uint64
	BTFID                 uint32
	BTFKeyTypeID          uint32
	BTFValueTypeId        uint32
	_                     uint32
	MapExtra              uint64
}

/*
 *
 *	struct { anonymous struct used by BPF_*_GET_*_ID
 *		union {
 *			__u32		start_id;
 *			__u32		prog_id;
 *			__u32		map_id;
 *			__u32		btf_id;
 *			__u32		link_id;
 *		};
 *		__u32		next_id;
 *		__u32		open_flags;
 *	};
 */

type BpfMapShowAttr struct {
	map_id     uint32
	next_id    uint32
	open_flags uint32
}

/*
 * struct { anonymous struct used by BPF_OBJ_GET_INFO_BY_FD
 *	__u32		bpf_fd;
 *	__u32		info_len;
 *	__aligned_u64	info;
 * } info;
*
*/
type BpfObjGetInfo struct {
	bpf_fd   uint32
	info_len uint32
	info     uintptr
}

/*
 *	struct { anonymous struct used by BPF_OBJ_* commands
 *	__aligned_u64	pathname;
 *	__u32		bpf_fd;
 *	__u32		file_flags;
 * };
 */
type BpfObjGet struct {
	pathname   uintptr
	bpf_fd     uint32
	file_flags uint32
}

func (attr *BpfMapShowAttr) isBpfMapGetNextID() bool {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_NEXT_ID,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Infof("Done get_next_id for Map - ret %d and err %s", int(ret), errno)
		return false
	}

	attr.map_id = attr.next_id
	return true
}

func (attr *BpfMapShowAttr) BpfMapGetFDbyID() (int, error) {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_FD_BY_ID,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Infof("Failed to get Map FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	return int(ret), nil
}

func (objattr *BpfObjGetInfo) BpfGetMapInfoForFD() error {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_GET_INFO_BY_FD,
		uintptr(unsafe.Pointer(objattr)),
		unsafe.Sizeof(*objattr),
	)
	if errno != 0 {
		log.Infof("Failed to get object info by FD - ret %d and err %s", int(ret), errno)
		return errno
	}
	//TODO maybe get info here itself
	return nil
}

func getBPFmapInfo(mapFD int) (BpfMapInfo, error) {
	var log = logger.Get()
	var bpfMapInfo BpfMapInfo
	objInfo := BpfObjGetInfo{
		bpf_fd:   uint32(mapFD),
		info_len: uint32(unsafe.Sizeof(bpfMapInfo)),
		info:     uintptr(unsafe.Pointer(&bpfMapInfo)),
	}

	err := objInfo.BpfGetMapInfoForFD()
	if err != nil {
		log.Infof("Failed to get map Info for FD - ", mapFD)
		return BpfMapInfo{}, err
	}

	log.Infof("TYPE - ", bpfMapInfo.Type)
	log.Infof("Prog Name - ", string(bpfMapInfo.Name[:]))
	return bpfMapInfo, nil
}

func BpfGetAllMapInfo() ([]BpfMapInfo, error) {
	var log = logger.Get()
	loadedMaps := []BpfMapInfo{}
	attr := BpfMapShowAttr{}
	log.Infof("In get all prog info")
	for attr.isBpfMapGetNextID() {
		log.Infof("Got ID - %d", attr.next_id)
		fileAttr := BpfMapShowAttr{
			map_id: attr.next_id,
		}
		mapfd, err := fileAttr.BpfMapGetFDbyID()
		if err != nil {
			log.Infof("Failed to get map Info")
			return nil, err
		}
		log.Infof("Found map FD - %d", mapfd)
		bpfMapInfo, err := getBPFmapInfo(mapfd)
		if err != nil {
			log.Infof("Failed to get map Info for FD", mapfd)
			return nil, err
		}
		runtime.KeepAlive(mapfd)

		loadedMaps = append(loadedMaps, bpfMapInfo)
	}
	log.Infof("Done all map info!!!")
	return loadedMaps, nil
}

func (attr *BpfObjGet) BpfGetObject() (int, error) {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_GET,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Infof("Failed to get Map FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	return int(ret), nil
}

func BpfGetMapFromPinPath(pinPath string) (BpfMapInfo, error) {
	var log = logger.Get()
	log.Infof("Printing pinpath - %s ", pinPath)
	if len(pinPath) == 0 {
		return BpfMapInfo{}, fmt.Errorf("Invalid pinPath")
	}

	cPath := []byte(pinPath + "\x00")
	objInfo := BpfObjGet{
		pathname: uintptr(unsafe.Pointer(&cPath[0])),
	}

	mapFD, err := objInfo.BpfGetObject()
	if err != nil {
		log.Infof("Failed to get object")
		return BpfMapInfo{}, err

	}
	runtime.KeepAlive(mapFD)

	log.Infof("Got progFD - %d", mapFD)
	bpfMapInfo, err := getBPFmapInfo(mapFD)
	if err != nil {
		log.Infof("Failed to get map Info for FD - %d", mapFD)
		return bpfMapInfo, err
	}

	return bpfMapInfo, nil
}