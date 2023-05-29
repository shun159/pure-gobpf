package ebpf_maps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

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
	BPF_MAP_CREATE            = 0
	BPF_MAP_LOOKUP_ELEM       = 1
	BPF_MAP_UPDATE_ELEM       = 2
	BPF_MAP_DELETE_ELEM       = 3
	BPF_MAP_GET_NEXT_KEY      = 4
	BPF_PROG_LOAD             = 5
	BPF_OBJ_PIN               = 6
	BPF_PROG_ATTACH           = 8
	BPF_PROG_DETACH           = 9
	BPF_PROG_TEST_RUN         = 10
	BPF_PROG_GET_NEXT_ID      = 11
	BPF_PROG_GET_FD_BY_ID     = 13
	TEST_BPF_MAP_GET_FD_BY_ID = 14

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
	MapID       uint32
	MapMetaData BpfMapData
}

type TestBpfMapShowAttr struct {
	Map_id     uint32
	next_id    uint32
	open_flags uint32
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

type BpfMapAPIs interface {
	CreateMap(MapMetaData BpfMapData) (BPFMap, error)
	PinMap(pinPath string) error
	UnPinMap(pinPath string) error
	CreateMapEntry(key, value uintptr) error
	UpdateMapEntry(key, value uintptr) error
	CreateUpdateMap(key, value uintptr, updateFlags uint64) error
	DeleteMapEntry(key uintptr) error
	GetFirstMapEntry(nextKey uintptr) error
	GetNextMapEntry(key, nextKey uintptr) error
	GetMapEntry(key, value uintptr) error
	BulkUpdateMapEntry(keyvalue map[uintptr]uintptr) error
	BulkDeleteMapEntry(keyvalue map[uintptr]uintptr) error
	//GetMapFD() uint32
	BulkRefreshMapEntries(newMapContents map[string]uintptr) error
}

func (m *BPFMap) CreateMap(MapMetaData BpfMapData) (BPFMap, error) {
	var log = logger.Get()

	mapCont := BpfMapData{
		Def: BpfMapDef{
			Type:       uint32(MapMetaData.Def.Type),
			KeySize:    MapMetaData.Def.KeySize,
			ValueSize:  MapMetaData.Def.ValueSize,
			MaxEntries: MapMetaData.Def.MaxEntries,
			Flags:      MapMetaData.Def.Flags,
			InnerMapFd: 0,
		},
		Name: MapMetaData.Name,
	}
	mapData := unsafe.Pointer(&mapCont)
	mapDataSize := unsafe.Sizeof(mapCont)

	log.Infof("Calling BPFsys for name %s mapType %d keysize %d valuesize %d max entries %d and flags %d", string(MapMetaData.Name[:]), MapMetaData.Def.Type, MapMetaData.Def.KeySize, MapMetaData.Def.ValueSize, MapMetaData.Def.MaxEntries, MapMetaData.Def.Flags)

	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(mapData),
		mapDataSize,
	)

	if (errno < 0) || (int(ret) == -1) {
		log.Infof("Unable to create map and ret %d and err %s", int(ret), errno)
		return BPFMap{}, fmt.Errorf("Unable to create map: %s", errno)
	}

	log.Infof("Create map done with fd : %d", int(ret))

	bpfMap := BPFMap{
		MapFD:       uint32(ret),
		MapMetaData: MapMetaData,
	}
	return bpfMap, nil
}

func (m *BPFMap) PinMap(pinPath string) error {
	var log = logger.Get()
	if m.MapMetaData.Def.Pinning == PIN_NONE {
		return nil
	}

	if m.MapMetaData.Def.Pinning == PIN_GLOBAL_NS {

		//If pinPath is already present lets delete and create a new one
		if IsfileExists(pinPath) {
			log.Infof("Found file %s so deleting the path", pinPath)
			err := UnPinObject(pinPath, int(m.MapFD))
			if err != nil {
				log.Infof("Failed to UnPinObject during pinning")
				return err
			}
		}
		err := os.MkdirAll(filepath.Dir(pinPath), 0755)
		if err != nil {
			log.Infof("error creating directory %s: %v", filepath.Dir(pinPath), err)
			return fmt.Errorf("error creating directory %s: %v", filepath.Dir(pinPath), err)
		}
		_, err = os.Stat(pinPath)
		if err == nil {
			log.Infof("aborting, found file at %s", pinPath)
			return fmt.Errorf("aborting, found file at %s", pinPath)
		}
		if err != nil && !os.IsNotExist(err) {
			log.Infof("failed to stat %s: %v", pinPath, err)
			return fmt.Errorf("failed to stat %s: %v", pinPath, err)
		}

		return PinObject(m.MapFD, pinPath)

	}
	return nil

}

func (m *BPFMap) UnPinMap(pinPath string) error {
	return UnPinObject(pinPath, int(m.MapFD))
}

func PinObject(objFD uint32, pinPath string) error {
	var log = logger.Get()

	if pinPath == "" {
		return nil
	}
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

func IsfileExists(fname string) bool {
	info, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func UnPinObject(pinPath string, objFD int) error {
	var log = logger.Get()
	if pinPath == "" || !IsfileExists(pinPath) {
		log.Infof("PinPath is empty or file doesn't exist")
		return nil
	}

	err := os.Remove(pinPath)
	if err != nil {
		log.Infof("File remove failed ", pinPath)
		return err
	}

	if objFD <= 0 {
		log.Infof("FD is invalid or closed %d", objFD)
		return nil
	}
	return unix.Close(objFD)
}

func (m *BPFMap) CreateMapEntry(key, value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(BPF_NOEXIST))
}

//TODO : This should be updated to behave like update
func (m *BPFMap) UpdateMapEntry(key, value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(BPF_ANY))
}

func TestGetFDFromID(mapID int) (int, error) {
	var log = logger.Get()
	log.Infof("Getting FD for ID - %d", mapID)
	fileAttr := TestBpfMapShowAttr{
		Map_id: uint32(mapID),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		TEST_BPF_MAP_GET_FD_BY_ID,
		uintptr(unsafe.Pointer(&fileAttr)),
		unsafe.Sizeof(fileAttr),
	)
	if errno != 0 {
		log.Infof("Failed to get Map FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	fd := int(ret)
	log.Infof("Returning FD %d", fd)
	runtime.KeepAlive(fd)
	return fd, nil
}

func (m *BPFMap) CreateUpdateMap(key, value uintptr, updateFlags uint64) error {

	var log = logger.Get()

	mapFD, err := TestGetFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}

	attr := BpfMapAttr{
		MapFD: uint32(mapFD),
		Flags: updateFlags,
		Key:   uint64(key),
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

	if errno != 0 {
		log.Infof("Unable to create/update map entry and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to update map: %s", errno)
	}

	log.Infof("Create/Update map entry done with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

func (m *BPFMap) DeleteMapEntry(key uintptr) error {

	var log = logger.Get()

	mapFD, err := TestGetFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Unable to delete map entry and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to update map: %s", errno)
	}

	log.Infof("Delete map entry done with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

// To get the first entry pass key as `nil`
func (m *BPFMap) GetFirstMapEntry(nextKey uintptr) error {
	return m.GetNextMapEntry(uintptr(unsafe.Pointer(nil)), nextKey)
}

func (m *BPFMap) GetNextMapEntry(key, nextKey uintptr) error {

	var log = logger.Get()

	mapFD, err := TestGetFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(nextKey),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errors.Is(errno, unix.ENOENT) {
		log.Infof("Last entry read done")
		unix.Close(mapFD)
		return errno
	}
	if errno != 0 {
		log.Infof("Unable to get next map entry and ret %d and err %s", int(ret), errno)
		unix.Close(mapFD)
		return fmt.Errorf("Unable to get next map entry: %s", errno)
	}

	log.Infof("Got next map entry with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

func (m *BPFMap) GetAllMapKeys() ([]string, error) {
	var log = logger.Get()
	var keyList []string
	keySize := m.MapMetaData.Def.KeySize

	curKey := make([]byte, keySize)
	nextKey := make([]byte, keySize)

	err := m.GetFirstMapEntry(uintptr(unsafe.Pointer(&curKey[0])))
	if err != nil {
		log.Infof("Unable to get first key %s", err)
		return nil, fmt.Errorf("Unable to get first key entry: %s", err)
	} else {
		for {
			err = m.GetNextMapEntry(uintptr(unsafe.Pointer(&curKey[0])), uintptr(unsafe.Pointer(&nextKey[0])))
			log.Info("Adding to key list %v", curKey)
			keyList = append(keyList, string(curKey))
			if errors.Is(err, unix.ENOENT) {
				log.Infof("Done reading all entries")
				return keyList, nil
			}
			if err != nil {
				log.Infof("Unable to get next key %s", err)
				break
			}
			//curKey = nextKey
			copy(curKey, nextKey)
		}
	}
	log.Infof("Done get all keys")
	return keyList, err
}

func (m *BPFMap) GetMapEntry(key, value uintptr) error {

	var log = logger.Get()

	mapFD, err := TestGetFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(value),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Unable to get map entry and ret %d and err %s", int(ret), errno)
		unix.Close(mapFD)
		return fmt.Errorf("Unable to get next map entry: %s", errno)
	}

	log.Infof("Got map entry with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

func (m *BPFMap) BulkDeleteMapEntry(keyvalue map[uintptr]uintptr) error {
	var log = logger.Get()
	for k, _ := range keyvalue {
		err := m.DeleteMapEntry(k)
		if err != nil {
			log.Infof("One of the element delete failed hence returning from bulk update")
			return err
		}
	}
	log.Infof("Bulk delete is successful for mapID: %d", int(m.MapID))
	return nil
}

func (m *BPFMap) BulkUpdateMapEntry(keyvalue map[uintptr]uintptr) error {
	var log = logger.Get()
	for k, v := range keyvalue {
		log.Info("Key being programmed - in bytearray ", *((*uint64)(unsafe.Pointer(k))))
		err := m.UpdateMapEntry(k, v)
		if err != nil {
			log.Infof("One of the element update failed hence returning from bulk update")
			return err
		}
	}
	log.Infof("Bulk update is successful for mapID: %d", int(m.MapID))
	return nil
}

/*
func (m *BPFMap) GetMapFD() uint32 {
	return m.MapFD
}
*/

func (m *BPFMap) BulkRefreshMapEntries(newMapContents map[string]uintptr) error {
	var log = logger.Get()

	// 1. Construct i/p to bulkMap
	keyvaluePtr := make(map[uintptr]uintptr)

	for k, v := range newMapContents {
		keyByte := []byte(k)
		log.Info("Converted string to bytearray %v", keyByte)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
		keyvaluePtr[keyPtr] = v
	}

	// 2. Update all map entries
	err := m.BulkUpdateMapEntry(keyvaluePtr)
	if err != nil {
		log.Infof("Refresh map failed: during update %v", err)
		return err
	}

	// 3. Read all map entries
	retrievedMapKeyList, err := m.GetAllMapKeys()
	if err != nil {
		log.Infof("Get all map keys failed: during Refresh %v", err)
		return err
	}

	// 4. Delete stale Keys
	log.Infof("Check for stale entries and got %d entries from BPF map", len(retrievedMapKeyList))
	for _, key := range retrievedMapKeyList {
		log.Infof("Checking if key %s is deltable", key)
		if _, ok := newMapContents[key]; !ok {
			log.Infof("This can be deleted, not needed anymore...")
			deletableKeyByte := []byte(key)
			deletableKeyBytePtr := uintptr(unsafe.Pointer(&deletableKeyByte[0]))
			err = m.DeleteMapEntry(deletableKeyBytePtr)
			if err != nil {
				log.Infof("Unable to delete entry %s but will continue and err %v", key, err)
			}
		}
	}
	return nil
}
