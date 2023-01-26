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
	"unsafe"
	"runtime"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
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

type BPFMap struct {
	MapFD       uint32
	MapMetaData BpfMapData
}

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
	Name     string
}

type BpfPin struct {
	Pathname  uintptr
	Fd        uint32
	FileFlags uint32
}

type BpfMapAttr struct {
	MapFD uint32
	pad0  [4]byte
	Key   uint64
	Value uint64 // union: value or next_key
	Flags uint64
}

func (m *BPFMap) CreateMap() (int, error) {
	var log = logger.Get()

	mapCont := BpfMapData{
		Def: BpfMapDef{
			Type:       uint32(m.MapMetaData.Def.Type),
			KeySize:    m.MapMetaData.Def.KeySize,
			ValueSize:  m.MapMetaData.Def.ValueSize,
			MaxEntries: m.MapMetaData.Def.MaxEntries,
			Flags:      m.MapMetaData.Def.Flags,
			InnerMapFd: 0,
		},
		Name: m.MapMetaData.Name,
	}
	mapData := unsafe.Pointer(&mapCont)
	mapDataSize := unsafe.Sizeof(mapCont)

	log.Infof("Calling BPFsys for name %s mapType %d keysize %d valuesize %d max entries %d and flags %d", string(m.MapMetaData.Name[:]), m.MapMetaData.Def.Type, m.MapMetaData.Def.KeySize, m.MapMetaData.Def.ValueSize, m.MapMetaData.Def.MaxEntries, m.MapMetaData.Def.Flags)

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

func (m *BPFMap) PinMap(mapFD int, pinPath string) error {
	var log = logger.Get()
	if m.MapMetaData.Def.Pinning == PIN_NONE {
		return nil
	}

	if m.MapMetaData.Def.Pinning == PIN_GLOBAL_NS {

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

func (m *BPFMap) CreateMapEntry(key , value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(BPF_NOEXIST))
}

func (m *BPFMap) UpdateMapEntry(key , value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(BPF_NOEXIST))
}

func (m *BPFMap) CreateUpdateMap(key , value uintptr, updateFlags uint64) error {

	var log = logger.Get()

	attr := BpfMapAttr{
		MapFD: uint32(m.MapFD),
		Flags: updateFlags,
		Key: uint64(key),
		Value: uint64(value),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)

	if errno !=0 {
		log.Infof("Unable to create/update map entry and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to update map: %s", errno)
	}

	log.Infof("Create/Update map entry done with fd : %d and err %s", int(ret), errno)
	return nil
}

func (m *BPFMap) DeleteMapEntry(key uintptr) error {

	var log = logger.Get()

	attr := BpfMapAttr{
		MapFD: uint32(m.MapFD),
		Key: uint64(key),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno !=0 {
		log.Infof("Unable to delete map entry and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to update map: %s", errno)
	}

	log.Infof("Delete map entry done with fd : %d and err %s", int(ret), errno)
	return nil
}
