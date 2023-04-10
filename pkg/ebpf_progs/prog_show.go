package ebpf_progs

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

const (
	BPF_PROG_GET_NEXT_ID   = 11
	BPF_PROG_GET_FD_BY_ID  = 13
	BPF_OBJ_GET_INFO_BY_FD = 15

	BPFObjNameLen    = 16
	BPFProgInfoAlign = 8
	BPFTagSize       = 8
)

// Ref: https://github.com/libbpf/libbpf/blob/f8cd00f61302ca4d8645e007acf7f546dc323b33/include/uapi/linux/bpf.h#L6281
type BpfProgInfo struct {
	Type                 uint32
	ID                   uint32
	Tag                  [BPFTagSize]byte
	JitedProgLen         uint32
	XlatedProgLen        uint32
	JitedProgInsns       uint64
	XlatedProgInsns      uint64
	LoadTime             syscall.Timespec
	CreatedByUID         uint32
	NrMapIDs             uint32
	MapIDs               uint64
	Name                 [BPFObjNameLen]byte
	IfIndex              uint32
	GPLCompatible        uint32
	_                    uint32
	NetnsDev             uint64
	NetnsIno             uint64
	NrJitedKsyms         uint32
	NrJitedFuncLens      uint32
	JitedKsyms           uint64
	JitedFuncLens        uint64
	BTFID                uint32
	FuncInfoRecSize      uint32
	FuncInfo             uint64
	NrFuncInfo           uint32
	NrLineInfo           uint32
	LineInfo             uint64
	JitedLineInfo        uint64
	NrJitedLineInfo      uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
	NrProgTags           uint32
	ProgTags             uint64
	RunTimeNS            uint64
	RunCnt               uint64
	RecursionMisses      uint64
	VerifiedInsns        uint32
	AttachBTFObjID       uint32
	AttachBTFID          uint32
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

type BpfProgAttr struct {
	prog_id    uint32
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

func (attr *BpfProgAttr) isBpfProgGetNextID() bool {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_PROG_GET_NEXT_ID,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Done get_next_id for Prog - ret %d and err %s", int(ret), errno)
		return false
	}

	attr.prog_id = attr.next_id
	return true
}

func (attr *BpfProgAttr) BpfProgGetFDbyID() (int, error) {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_PROG_GET_FD_BY_ID,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Failed to get Prog FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	return int(ret), nil
}

func (objattr *BpfObjGetInfo) BpfGetProgramInfoForFD() error {
	var log = logger.Get()
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_GET_INFO_BY_FD,
		uintptr(unsafe.Pointer(objattr)),
		unsafe.Sizeof(objattr),
	)
	if errno != 0 {
		log.Infof("Failed to get object info by FD - ret %d and err %s", int(ret), errno)
		return errno
	}
	//TODO maybe get info here itself
	return nil
}

func BpfGetAllProgramInfo() ([]BpfProgInfo, error) {
	var log = logger.Get()
	loadedPrograms := []BpfProgInfo{}
	attr := BpfProgAttr{}
	log.Infof("In get all prog info")
	for attr.isBpfProgGetNextID() {
		log.Infof("Got ID - %d", attr.next_id)
		fileAttr := BpfProgAttr{
			prog_id: attr.next_id,
		}
		progfd, err := fileAttr.BpfProgGetFDbyID()
		if err != nil {
			log.Infof("Failed to get program Info")
			return nil, err
		}
		log.Infof("Found prog FD - %d", progfd)
		/*
		bpfProgInfo := BpfProgInfo{}
		objInfo := BpfObjGetInfo{
			bpf_fd:   uint32(progfd),
			info_len: uint32(unsafe.Sizeof(BpfProgInfo{})),
			info:     uintptr(unsafe.Pointer(&bpfProgInfo)),
		}

		err = objInfo.BpfGetProgramInfoForFD()
		if err != nil {
			log.Infof("Failed to get program Info for FD - ", progfd)
			return nil, err

		}

		log.Infof("TYPE - ", bpfProgInfo.Type)
		log.Infof("Prog Name - ", string(bpfProgInfo.Name[:]))
		log.Infof("Maps linked - ", bpfProgInfo.NrMapIDs)
		loadedPrograms = append(loadedPrograms, bpfProgInfo)
		*/
	}
	log.Infof("Done all prog info!!!")
	return loadedPrograms, nil
}
