package ebpf_maps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"github.com/jayanthvn/pure-gobpf/pkg/utils"
	"golang.org/x/sys/unix"
)

type BPFMap struct {
	MapFD       uint32
	MapID       uint32
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
		utils.BPF_MAP_CREATE,
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
	if m.MapMetaData.Def.Pinning == utils.PIN_NONE {
		return nil
	}

	if m.MapMetaData.Def.Pinning == utils.PIN_GLOBAL_NS {

		//If pinPath is already present lets delete and create a new one
		if utils.IsfileExists(pinPath) {
			log.Infof("Found file %s so deleting the path", pinPath)
			err := utils.UnPinObject(pinPath)
			if err != nil {
				log.Infof("Failed to UnPinObject %v", err)
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

		return utils.PinObject(m.MapFD, pinPath)

	}
	return nil

}

func (m *BPFMap) UnPinMap(pinPath string) error {
	var log = logger.Get()
	err := utils.UnPinObject(pinPath)
	if err != nil {
		log.Infof("Failed to unpin map")
		return err
	}
	if m.MapFD <= 0 {
		log.Infof("FD is invalid or closed %d", m.MapFD)
		return nil
	}
	return unix.Close(int(m.MapFD))
}

func (m *BPFMap) CreateMapEntry(key, value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(utils.BPF_NOEXIST))
}

//TODO : This should be updated to behave like update
func (m *BPFMap) UpdateMapEntry(key, value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(utils.BPF_ANY))
}

func (m *BPFMap) CreateUpdateMap(key, value uintptr, updateFlags uint64) error {

	var log = logger.Get()

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}

	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Flags: updateFlags,
		Key:   uint64(key),
		Value: uint64(value),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_UPDATE_ELEM,
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

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_DELETE_ELEM,
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

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(nextKey),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_GET_NEXT_KEY,
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

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(value),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_LOOKUP_ELEM,
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
