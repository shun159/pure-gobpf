package ebpf_maps

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"github.com/jayanthvn/pure-gobpf/pkg/utils"
)

type BpfMapInfo struct {
	Type                  uint32
	Id                    uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	Name                  [utils.BPFObjNameLen]byte
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
	Map_id     uint32
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
		utils.BPF_MAP_GET_NEXT_ID,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Infof("Done get_next_id for Map - ret %d and err %s", int(ret), errno)
		return false
	}

	attr.Map_id = attr.next_id
	return true
}

func (objattr *BpfObjGetInfo) BpfGetMapInfoForFD() error {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_OBJ_GET_INFO_BY_FD,
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

func GetIDFromFD(mapFD int) (int, error) {
	mapInfo, err := GetBPFmapInfo(mapFD)
	if err != nil {
		return -1, err
	}
	return int(mapInfo.Id), nil
}

/*
func GetFDFromID(mapID int) (int, error) {
	var log = logger.Get()
	fileAttr := BpfMapShowAttr{
		Map_id: uint32(mapID),
	}
	mapfd, err := fileAttr.BpfMapGetFDbyID()
	if err != nil {
		log.Infof("Failed to get map Info")
		return -1, err
	}
	log.Infof("Found map FD - %d", mapfd)
	return mapfd, nil
}
*/

func GetBPFmapInfo(mapFD int) (BpfMapInfo, error) {
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
	log.Infof("Prog Name - ", unix.ByteSliceToString(bpfMapInfo.Name[:]))
	return bpfMapInfo, nil
}

func BpfGetAllMapInfo() ([]BpfMapInfo, error) {
	var log = logger.Get()
	loadedMaps := []BpfMapInfo{}
	attr := BpfMapShowAttr{}
	log.Infof("In get all prog info")
	for attr.isBpfMapGetNextID() {
		log.Infof("Got ID - %d", attr.next_id)

		/*
			fileAttr := BpfMapShowAttr{
				Map_id: attr.next_id,
			}
			mapfd, err := fileAttr.BpfMapGetFDbyID()
			if err != nil {
				log.Infof("Failed to get map Info")
				return nil, err
			}*/
		mapfd, err := utils.GetMapFDFromID(int(attr.next_id))
		if err != nil {
			log.Infof("Failed to get map Info")
			return nil, err
		}
		log.Infof("Found map FD - %d", mapfd)
		bpfMapInfo, err := GetBPFmapInfo(mapfd)
		if err != nil {
			log.Infof("Failed to get map Info for FD", mapfd)
			return nil, err
		}
		unix.Close(mapfd)

		loadedMaps = append(loadedMaps, bpfMapInfo)
	}
	log.Infof("Done all map info!!!")
	return loadedMaps, nil
}

func (attr *BpfObjGet) BpfGetObject() (int, error) {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_OBJ_GET,
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

	log.Infof("Got mapFD - %d", mapFD)
	bpfMapInfo, err := GetBPFmapInfo(mapFD)
	if err != nil {
		log.Infof("Failed to get map Info for FD - %d", mapFD)
		return bpfMapInfo, err
	}
	log.Infof("Close FD now...")
	err = unix.Close(int(mapFD))
	if err != nil {
		log.Infof("Failed to close but return the mapinfo")
	}

	return bpfMapInfo, nil
}
