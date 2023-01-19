package ebpf

/*
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BPF_OBJ_NAME_LEN 16U

#define BPF_INS_DEF_SIZE sizeof(struct bpf_insn)

*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
	BPF_MAP_TYPE_UNSPEC           = 0
	BPF_MAP_TYPE_HASH             = 1
	BPF_MAP_TYPE_ARRAY            = 2
	BPF_MAP_TYPE_PROG_ARRAY       = 3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
	BPF_MAP_TYPE_PERCPU_HASH      = 5
	BPF_MAP_TYPE_PERCPU_ARRAY     = 6
	BPF_MAP_TYPE_STACK_TRACE      = 7
	BPF_MAP_TYPE_CGROUP_ARRAY     = 8
	BPF_MAP_TYPE_LRU_HASH         = 9
	BPF_MAP_TYPE_LRU_PERCPU_HASH  = 10
	BPF_MAP_TYPE_LPM_TRIE         = 11
	BPF_MAP_TYPE_ARRAY_OF_MAPS    = 12
	BPF_MAP_TYPE_HASH_OF_MAPS     = 13
	BPF_MAP_TYPE_DEVMAP           = 14

	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	BPF_MAP_CREATE         = 0
	BPF_MAP_LOOKUP_ELEM    = 1
	BPF_MAP_UPDATE_ELEM    = 2
	BPF_MAP_DELETE_ELEM    = 3
	BPF_MAP_GET_NEXT_KEY   = 4
	BPF_PROG_LOAD          = 5
	BPF_OBJ_PIN            = 6
	BPF_OBJ_GET            = 7
	BPF_PROG_ATTACH        = 8
	BPF_PROG_DETACH        = 9
	BPF_PROG_TEST_RUN      = 10
	BPF_PROG_GET_NEXT_ID   = 11
	BPF_MAP_GET_NEXT_ID    = 12
	BPF_PROG_GET_FD_BY_ID  = 13
	BPF_MAP_GET_FD_BY_ID   = 14
	BPF_OBJ_GET_INFO_BY_FD = 15

	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2

	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1

	// BPF MAP pinning
	PIN_NONE      = 0
	PIN_OBJECT_NS = 1
	PIN_GLOBAL_NS = 2
	PIN_CUSTOM_NS = 3

	BPF_DIR_MNT     = "/sys/fs/bpf/"
	BPF_DIR_GLOBALS = "globals"
)

type BpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	InnerMapFd uint32
	Pinning    uint32
}

type BpfMapData struct {
	Def      BpfMapDef
	numaNode uint32
	//Name     [16]byte
	Name string
}

type BpfPin struct {
	Pathname  uintptr
	Fd        uint32
	FileFlags uint32
}

func (m *BpfMapData) CreateMap() (int, error) {
	var log = logger.Get()

	mapCont := BpfMapData{
		Def: BpfMapDef{
			Type:       uint32(m.Def.Type),
			KeySize:    m.Def.KeySize,
			ValueSize:  m.Def.ValueSize,
			MaxEntries: m.Def.MaxEntries,
			Flags:      m.Def.Flags,
			InnerMapFd: 0,
		},
		Name: m.Name,
	}
	mapData := unsafe.Pointer(&mapCont)
	mapDataSize := unsafe.Sizeof(mapCont)

	log.Infof("Calling BPFsys for name %s mapType %d keysize %d valuesize %d max entries %d and flags %d", string(m.Name[:]), m.Def.Type, m.Def.KeySize, m.Def.ValueSize, m.Def.MaxEntries, m.Def.Flags)

	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(mapData),
		mapDataSize,
	)

	if errno < 0 {
		log.Infof("Unable to create map and ret %d and err %s", int(ret), errno)
		return int(ret), fmt.Errorf("Unable to create map: %s", errno)
	}

	log.Infof("Create map done with fd : %d", int(ret))
	return int(ret), nil
}

func mount_bpf_fs() error {
	var log = logger.Get()
	log.Infof("Let's mount BPF FS")
	err := syscall.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "mode=0700")
	if err != nil{
		log.Errorf("error mounting bpffs: %v", err)
	}
	return err
}

func (m *BpfMapData) PinMap(mapFD int, pinPath string) error {
	var log = logger.Get()
	if m.Def.Pinning == PIN_NONE {
		return nil
	}

	if m.Def.Pinning == PIN_GLOBAL_NS {

		err := os.MkdirAll(filepath.Dir(pinPath), 0755)
		if err != nil {
			log.Infof("error creating directory %q: %v", filepath.Dir(pinPath), err)
			return fmt.Errorf("error creating directory %q: %v", filepath.Dir(pinPath), err)
		}
		_, err = os.Stat(pinPath)
		if err == nil {
			log.Infof("aborting, found file at %q", pinPath)
			return fmt.Errorf("aborting, found file at %q", pinPath)
		}
		if err != nil && !os.IsNotExist(err) {
			log.Infof("failed to stat %q: %v", pinPath, err)
			return fmt.Errorf("failed to stat %q: %v", pinPath, err)
		}

		return PinObject(mapFD, pinPath)

	}
	return nil

}

func PinProg(progFD int, pinPath string) error {
	var log = logger.Get()
/*
	err := mount_bpf_fs()
	if err != nil{
		log.Errorf("error mounting bpffs: %v", err)
		return err
	}

 */

	err := os.MkdirAll(filepath.Dir(pinPath), 0755)
	if err != nil {
		log.Infof("error creating directory %q: %v", filepath.Dir(pinPath), err)
		return fmt.Errorf("error creating directory %q: %v", filepath.Dir(pinPath), err)
	}
	_, err = os.Stat(pinPath)
	if err == nil {
		log.Infof("aborting, found file at %q", pinPath)
		return fmt.Errorf("aborting, found file at %q", pinPath)
	}
	if err != nil && !os.IsNotExist(err) {
		log.Infof("failed to stat %q: %v", pinPath, err)
		return fmt.Errorf("failed to stat %q: %v", pinPath, err)
	}

	return PinObject(progFD, pinPath)
}

func PinObject(objFD int, pinPath string) error {
	var log = logger.Get()
	cPath := []byte(pinPath + "\x00")

	pinAttr := BpfPin{
		Fd:       uint32(objFD),
		Pathname: uintptr(unsafe.Pointer(&cPath[0])),
	}
	pinData := unsafe.Pointer(&pinAttr)
	pinDataSize := unsafe.Sizeof(pinAttr)

	log.Infof("Calling BPFsys for FD %d and Path %s", objFD, pinPath)

	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(BPF_OBJ_PIN),
		uintptr(pinData),
		uintptr(int(pinDataSize)),
	)
	if errno < 0 {
		log.Infof("Unable to pin map and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to pin map: %s", errno)
	}
	//TODO : might have to return FD for node agent
	log.Infof("Pin done with fd : %d and errno %d", ret, errno)
	return nil
}

func LoadProg(progType string, data []byte, licenseStr string, pinPath string) (int, error) {
	var log = logger.Get()

	insDefSize := C.BPF_INS_DEF_SIZE
	var prog_type uint32
	switch progType {
	case "xdp":
		prog_type = uint32(netlink.BPF_PROG_TYPE_XDP)
	case "tc_cls":
		prog_type = uint32(netlink.BPF_PROG_TYPE_SCHED_CLS)
	case "tc_act":
		prog_type = uint32(netlink.BPF_PROG_TYPE_SCHED_ACT)
	default:
		prog_type = uint32(netlink.BPF_PROG_TYPE_UNSPEC)
	}

	logBuf := make([]byte, 65535)
	program := netlink.BPFAttr{
		ProgType: prog_type,
		LogBuf:   uintptr(unsafe.Pointer(&logBuf[0])),
		LogSize:  uint32(cap(logBuf) - 1),
		LogLevel: 1,
	}

	program.Insns = uintptr(unsafe.Pointer(&data[0]))
	program.InsnCnt = uint32(len(data) / insDefSize)

	license := []byte(licenseStr)
	program.License = uintptr(unsafe.Pointer(&license[0]))

	fd, _, errno := unix.Syscall(unix.SYS_BPF,
		BPF_PROG_LOAD,
		uintptr(unsafe.Pointer(&program)),
		unsafe.Sizeof(program))
	runtime.KeepAlive(data)
	runtime.KeepAlive(license)

	log.Infof("Load prog done with fd : %d", int(fd))
	if errno != 0 {
		log.Infof(string(logBuf))
		return 0, errno
	}

	//Pin the prog
	err := PinProg(int(fd), pinPath)
	if err != nil {
		log.Infof("pin prog failed %v", err)
		return 0, err
	}
	return int(fd), nil
}
