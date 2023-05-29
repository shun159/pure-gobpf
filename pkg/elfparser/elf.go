package elfparser

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps"
	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_progs"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

var (
	/*
	 * C struct of bpf_ins is 8 bytes because of this -
	 * struct bpf_insn {
	 *	__u8	code;
	 * 	__u8	dst_reg:4;
	 *	__u8	src_reg:4;
	 * 	__s16	off;
	 * 	__s32	imm;
	 *	};
	 * while go struct will return 9 since we dont have bit fields hence we dec(1).
	 */
	bpfInsDefSize = (binary.Size(BPFInsn{}) - 1)
	bpfMapDefSize = binary.Size(BPFMapDef{})
	bpfFS         = "/sys/fs/bpf"
	progbpfFS     = "/sys/fs/bpf/globals/aws/programs/"
	mapbpfFS      = "/sys/fs/bpf/globals/aws/maps/"
	BPF_FS_MAGIC  = 0xcafe4a11
)

type BPFMapDef struct {
	map_type     uint32
	key_size     uint32
	value_size   uint32
	max_entries  uint32
	map_flags    uint32
	pinning      uint32
	inner_map_fd uint32
}

type ELFContext struct {
	// .elf will have multiple sections and maps
	Section       map[string]ELFSection       // Indexed by section type
	Maps          map[string]ebpf_maps.BPFMap // Index by map name
	BPFloadedprog map[string]BPFdata
}

type ELFSection struct {
	// Each sections will have a program but a single section type can have multiple programs
	// like tc_cls
	Programs map[string]ebpf_progs.BPFProgram // Index by program name
}

type BPFdata struct {
	Program ebpf_progs.BPFProgram       // Return the program
	Maps    map[string]ebpf_maps.BPFMap // List of associated maps
}

type BPFInsn struct {
	Code   uint8 // Opcode
	DstReg uint8 // 4 bits: destination register, r0-r10
	SrcReg uint8 // 4 bits: source register, r0-r10
	Off    int16 // Signed offset
	Imm    int32 // Immediate constant
}

// Converts BPF instruction into bytes
func (b *BPFInsn) convertBPFInstructionToByteStream() []byte {
	res := make([]byte, 8)
	res[0] = b.Code
	res[1] = (b.SrcReg << 4) | (b.DstReg & 0x0f)
	binary.LittleEndian.PutUint16(res[2:], uint16(b.Off))
	binary.LittleEndian.PutUint32(res[4:], uint32(b.Imm))

	return res
}

type relocationEntry struct {
	relOffset int
	symbol    elf.Symbol
}

// This is not needed 5.11 kernel onwards because per-cgroup mem limits
// https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com/
func IncreaseRlimit() error {
	var log = logger.Get()
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	if err != nil {
		log.Infof("Failed to bump up the rlimit")
		return err
	}
	return nil
}

func LoadBpfFile(path, customizedPinPath string) (map[string]BPFdata, error) {
	var log = logger.Get()
	f, err := os.Open(path)
	if err != nil {
		log.Infof("LoadBpfFile failed to open")
		return nil, err
	}
	defer f.Close()

	c := &ELFContext{}
	bpfMap := &ebpf_maps.BPFMap{}
	bpfProg := &ebpf_progs.BPFProgram{}

	err = c.doLoadELF(f, bpfMap, bpfProg, customizedPinPath)
	if err != nil {
		return nil, err
	}
	return c.BPFloadedprog, nil
}

func (c *ELFContext) loadElfMapsSection(mapsShndx int, dataMaps *elf.Section, elfFile *elf.File, bpfMapApi ebpf_maps.BpfMapAPIs, customizedPinPath string) error {
	var log = logger.Get()
	//Replace this TODO
	mapDefinitionSize := bpfMapDefSize
	GlobalMapData := []ebpf_maps.BpfMapData{}

	data, err := dataMaps.Data()
	if err != nil {
		log.Infof("Error while loading section")
		return fmt.Errorf("error while loading section': %w", err)
	}

	symbols, err := elfFile.Symbols()
	if err != nil {
		log.Infof("Get symbol failed")
		return fmt.Errorf("get symbols: %w", err)
	}

	log.Infof("Dumping MAP %v and size %d", data, mapDefinitionSize)

	for offset := 0; offset < len(data); offset += mapDefinitionSize {
		log.Infof("Offset %d", offset)
		mapData := ebpf_maps.BpfMapData{}
		mapDef := ebpf_maps.BpfMapDef{
			Type:       uint32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			KeySize:    uint32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			ValueSize:  uint32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			MaxEntries: uint32(binary.LittleEndian.Uint32(data[offset+12 : offset+16])),
			Flags:      uint32(binary.LittleEndian.Uint32(data[offset+16 : offset+20])),
			Pinning:    uint32(binary.LittleEndian.Uint32(data[offset+20 : offset+24])),
		}

		log.Infof("DUMP Type %d KeySize %d ValueSize %d MaxEntries %d Flags %d Pinning %d", uint32(binary.LittleEndian.Uint32(data[offset:offset+4])),
			uint32(binary.LittleEndian.Uint32(data[offset+4:offset+8])), uint32(binary.LittleEndian.Uint32(data[offset+8:offset+12])),
			uint32(binary.LittleEndian.Uint32(data[offset+12:offset+16])), uint32(binary.LittleEndian.Uint32(data[offset+16:offset+20])),
			uint32(binary.LittleEndian.Uint32(data[offset+20:offset+24])))

		for _, sym := range symbols {
			if int(sym.Section) == mapsShndx && int(sym.Value) == offset {
				mapName := path.Base(sym.Name)
				mapData.Name = mapName
			}
		}
		log.Infof("Found map name %s", mapData.Name)
		mapData.Def = mapDef
		GlobalMapData = append(GlobalMapData, mapData)
	}

	log.Infof("Total maps found - %d", len(GlobalMapData))

	for index := 0; index < len(GlobalMapData); index++ {
		log.Infof("Loading maps")
		loadedMaps := GlobalMapData[index]

		/*
			bpfMap := &ebpf_maps.BPFMap{
				MapMetaData: loadedMaps,
			}*/
		bpfMap, err := (bpfMapApi).CreateMap(loadedMaps)
		if err != nil {
			//Even if one map fails, we error out
			log.Infof("Failed to create map, continue to next map..just for debugging")
			continue
		}

		mapNameStr := loadedMaps.Name
		if len(customizedPinPath) != 0 {
			mapNameStr = customizedPinPath + "_" + mapNameStr
		}

		pinPath := mapbpfFS + mapNameStr
		bpfMap.PinMap(pinPath)

		//Fill ID
		mapInfo, err := ebpf_maps.BpfGetMapFromPinPath(pinPath)
		if err != nil {
			return fmt.Errorf("map '%s' doesn't exist", mapNameStr)
		}
		map_id := uint32(mapInfo.Id)
		bpfMap.MapID = map_id

		c.Maps[loadedMaps.Name] = bpfMap
	}
	return nil
}

func parseRelocationSection(reloSection *elf.Section, elfFile *elf.File) ([]relocationEntry, error) {
	var log = logger.Get()
	var result []relocationEntry

	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("unable to load symbols(): %v", err)
	}
	// Read section data
	data, err := reloSection.Data()
	if err != nil {
		return nil, fmt.Errorf("unable to read data from section '%s': %v", reloSection.Name, err)
	}

	reader := bytes.NewReader(data)
	for {
		var err error
		var offset, index int

		switch elfFile.Class {
		case elf.ELFCLASS64:
			var relocEntry elf.Rel64
			err = binary.Read(reader, elfFile.ByteOrder, &relocEntry)
			index = int(elf.R_SYM64(relocEntry.Info)) - 1
			offset = int(relocEntry.Off)
		case elf.ELFCLASS32:
			var relocEntry elf.Rel32
			err = binary.Read(reader, elfFile.ByteOrder, &relocEntry)
			index = int(elf.R_SYM32(relocEntry.Info)) - 1
			offset = int(relocEntry.Off)
		default:
			return nil, fmt.Errorf("Unsupported arch %v", elfFile.Class)
		}

		if err != nil {
			// EOF. Nothing more to do.
			if err == io.EOF {
				return result, nil
			}
			return nil, err
		}

		// Validate the derived index value
		if index >= len(symbols) {
			return nil, fmt.Errorf("Invalid Relocation section entry'%v': index %v does not exist",
				reloSection, index)
		}
		log.Infof("Relocation section entry: %s @ %v", symbols[index].Name, offset)
		result = append(result, relocationEntry{
			relOffset: offset,
			symbol:    symbols[index],
		})
	}
}

func (c *ELFContext) loadElfProgSection(dataProg *elf.Section, reloSection *elf.Section, license string, progType string, subSystem string, subProgType string, sectionIndex int, elfFile *elf.File, bpfProgApi ebpf_progs.BpfProgAPIs, customizedPinPath string) (BPFdata, error) {
	var log = logger.Get()

	insDefSize := bpfInsDefSize

	data, err := dataProg.Data()
	if err != nil {
		return BPFdata{}, err
	}

	log.Infof("Loading Program with relocation section; Info:%v; Name: %s, Type: %s; Size: %v", reloSection.Info,
		reloSection.Name, reloSection.Type, reloSection.Size)

	//Single section might have multiple programs. So we retrieve one prog at a time and load.
	symbolTable, err := elfFile.Symbols()
	if err != nil {
		log.Infof("Get symbol failed")
		return BPFdata{}, fmt.Errorf("get symbols: %w", err)
	}

	relocationEntries, err := parseRelocationSection(reloSection, elfFile)
	if err != nil || len(relocationEntries) == 0 {
		return BPFdata{}, fmt.Errorf("Unable to parse relocation entries....")
	}

	log.Infof("Applying Relocations..")
	mapIDToFD := make(map[int]string)
	// TODO create a map array
	for _, relocationEntry := range relocationEntries {
		if relocationEntry.relOffset >= len(data) {
			return BPFdata{}, fmt.Errorf("Invalid offset for the relocation entry %d", relocationEntry.relOffset)
		}

		//eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
		//of two consecutive 'struct bpf_insn' 8-byte blocks and interpreted as single
		//instruction that loads 64-bit immediate value into a dst_reg.
		ebpfInstruction := &BPFInsn{
			Code:   data[relocationEntry.relOffset],
			DstReg: data[relocationEntry.relOffset+1] & 0xf,
			SrcReg: data[relocationEntry.relOffset+1] >> 4,
			Off:    int16(binary.LittleEndian.Uint16(data[relocationEntry.relOffset+2:])),
			Imm:    int32(binary.LittleEndian.Uint32(data[relocationEntry.relOffset+4:])),
		}

		log.Infof("BPF Instruction code: %s; offset: %d; imm: %d", ebpfInstruction.Code, ebpfInstruction.Off, ebpfInstruction.Imm)

		//Validate for Invalid BPF instructions
		if ebpfInstruction.Code != (unix.BPF_LD | unix.BPF_IMM | unix.BPF_DW) {
			return BPFdata{}, fmt.Errorf("Invalid BPF instruction (at %d): %d",
				relocationEntry.relOffset, ebpfInstruction.Code)
		}

		// Point BPF instruction to the FD of the map referenced. Update the last 4 bytes of
		// instruction (immediate constant) with the map's FD.
		// BPF_MEM | <size> | BPF_STX:  *(size *) (dst_reg + off) = src_reg
		// BPF_MEM | <size> | BPF_ST:   *(size *) (dst_reg + off) = imm32
		mapName := relocationEntry.symbol.Name
		log.Infof("Map to be relocated; Name: %s", mapName)
		var mapFD int
		var map_id int
		if progMap, ok := c.Maps[mapName]; ok {
			map_id = int(progMap.MapID)
			mapIDToFD[map_id] = mapName
			mapFD = int(progMap.MapFD)

		} else {
			//This might be a shared global map so get from pinpath
			pinLocation := "global_" + mapName
			globalPinPath := mapbpfFS + pinLocation
			mapInfo, err := ebpf_maps.BpfGetMapFromPinPath(globalPinPath)
			if err != nil {
				return BPFdata{}, fmt.Errorf("map '%s' doesn't exist", mapName)
			}
			map_id = int(mapInfo.Id)
			mapIDToFD[map_id] = mapName
			mapFD, err = ebpf_maps.GetFDFromID(map_id)
			if err != nil {
				return BPFdata{}, fmt.Errorf("Failed to get map FD '%s' doesn't exist", mapName)
			}
		}

		log.Infof("Map found. Replace the offset with corresponding Map FD: %v", mapFD)
		ebpfInstruction.SrcReg = 1 //dummy value for now
		ebpfInstruction.Imm = int32(mapFD)
		copy(data[relocationEntry.relOffset:relocationEntry.relOffset+8], ebpfInstruction.convertBPFInstructionToByteStream())
		log.Infof("From data: BPF Instruction code: %d; offset: %d; imm: %d",
			uint8(data[relocationEntry.relOffset]),
			uint16(binary.LittleEndian.Uint16(data[relocationEntry.relOffset+2:relocationEntry.relOffset+4])),
			uint32(binary.LittleEndian.Uint32(data[relocationEntry.relOffset+4:relocationEntry.relOffset+8])))
	}

	var pgmList = make(map[string]ebpf_progs.BPFProgram)
	bpfData := BPFdata{}
	// Iterate over the symbols in the symbol table
	for _, symbol := range symbolTable {
		// Check if the symbol is a function
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			// Check if sectionIndex matches
			if int(symbol.Section) == sectionIndex && elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL {
				// Check if the symbol's value (offset) is within the range of the section data

				progSize := symbol.Size
				secOff := symbol.Value
				ProgName := symbol.Name

				if secOff+progSize > dataProg.Size {
					log.Infof("Section out of bound secOff %d - progSize %d for name %s and data size %d", progSize, secOff, ProgName, dataProg.Size)
					return BPFdata{}, fmt.Errorf("Failed to Load the prog")
				}

				log.Infof("Sec '%s': found program '%s' at insn offset %d (%d bytes), code size %d insns (%d bytes)\n", progType, ProgName, secOff/uint64(insDefSize), secOff, progSize/uint64(insDefSize), progSize)
				if symbol.Value >= dataProg.Addr && symbol.Value < dataProg.Addr+dataProg.Size {
					// Extract the BPF program data from the section data
					log.Infof("Data offset - %d", symbol.Value-dataProg.Addr)
					log.Infof("Data len - %d", len(data))

					dataStart := (symbol.Value - dataProg.Addr)
					dataEnd := dataStart + progSize
					programData := make([]byte, progSize)
					copy(programData, data[dataStart:dataEnd])

					log.Infof("Program Data size - %d", len(programData))

					pinLocation := ProgName
					if len(customizedPinPath) != 0 {
						pinLocation = customizedPinPath + "_" + ProgName
					}
					pinPath := progbpfFS + pinLocation
					progFD, _ := bpfProgApi.LoadProg(progType, programData, license, pinPath, bpfInsDefSize)
					if progFD == -1 {
						log.Infof("Failed to load prog")
						return BPFdata{}, fmt.Errorf("Failed to Load the prog")
					}
					log.Infof("loaded prog with %d", progFD)

					//Fill ID
					progInfo, newProgFD, err := ebpf_progs.BpfGetProgFromPinPath(pinPath)
					if err != nil {
						return BPFdata{}, fmt.Errorf("Failed to get ProgID")
					}
					//TODO : need to refactor this
					unix.Close(int(newProgFD))

					progID := int(progInfo.ID)
					pgmList[ProgName] = ebpf_progs.BPFProgram{
						ProgID:      progID,
						ProgFD:      progFD,
						PinPath:     pinPath,
						ProgType:    progType,
						SubSystem:   subSystem,
						SubProgType: subProgType,
					}

					// TODO get prog info by FD and get list of maps..to fill
					associatedMaps, err := ebpf_progs.GetBPFProgAssociatedMapsIDs(progFD)
					if err != nil {
						log.Infof("Failed to load prog")
						return BPFdata{}, fmt.Errorf("Failed to Load the prog, get associatedmapIDs failed")
					}
					//walk thru all mapIDs and get loaded FDs and fill BPFData

					progMaps := make(map[string]ebpf_maps.BPFMap)
					for mapInfoIdx := 0; mapInfoIdx < len(associatedMaps); mapInfoIdx++ {
						mapID := associatedMaps[mapInfoIdx]
						//TODO - Need an error check for unkown map ID
						if mapName, ok := mapIDToFD[int(mapID)]; ok {
							progMaps[mapName] = c.Maps[mapName]
						}
					}

					bpfData.Program = ebpf_progs.BPFProgram{
						ProgID:      progID,
						ProgFD:      progFD,
						PinPath:     pinPath,
						ProgType:    progType,
						SubSystem:   subSystem,
						SubProgType: subProgType,
					}
					bpfData.Maps = progMaps

				} else {
					log.Infof("Invalid ELF file\n")
					return BPFdata{}, fmt.Errorf("Failed to Load the prog")
				}
			}
		}
	}

	elfSection, ok := c.Section[progType]
	if !ok {
		// if the progType section does not exist, create a new ELFSection object for it
		elfSection = ELFSection{
			Programs: make(map[string]ebpf_progs.BPFProgram),
		}
	}

	//This will just run once
	for pgmName, pgmValue := range pgmList {
		elfSection.Programs[pgmName] = pgmValue
	}
	c.Section[progType] = elfSection

	return bpfData, nil
}

func (c *ELFContext) doLoadELF(r io.ReaderAt, bpfMap ebpf_maps.BpfMapAPIs, bpfProg ebpf_progs.BpfProgAPIs, customizedPinPath string) error {
	var log = logger.Get()
	var err error
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return err
	}

	c.Section = make(map[string]ELFSection)
	c.Maps = make(map[string]ebpf_maps.BPFMap)
	c.BPFloadedprog = make(map[string]BPFdata)
	reloSectionMap := make(map[uint32]*elf.Section)

	var dataMaps *elf.Section
	var mapsShndx int
	var strtabidx uint32
	license := ""
	for index, section := range elfFile.Sections {
		if section.Name == "license" {
			data, _ := section.Data()
			if err != nil {
				return fmt.Errorf("Failed to read data for section %s", section.Name)
			}
			license = string(data)
			log.Infof("License %s", license)
			break
		} else if section.Name == "maps" {
			dataMaps = section
			mapsShndx = index
		}
	}

	log.Infof("strtabidx %d", strtabidx)

	if dataMaps != nil {
		err := c.loadElfMapsSection(mapsShndx, dataMaps, elfFile, bpfMap, customizedPinPath)
		if err != nil {
			return nil
		}
	}

	//Gather relocation section info
	for _, reloSection := range elfFile.Sections {
		if reloSection.Type == elf.SHT_REL {
			log.Infof("Found a relocation section; Info:%v; Name: %s, Type: %s; Size: %v", reloSection.Info,
				reloSection.Name, reloSection.Type, reloSection.Size)
			reloSectionMap[reloSection.Info] = reloSection
		}
	}

	//Load prog
	for sectionIndex, section := range elfFile.Sections {
		if section.Type != elf.SHT_PROGBITS {
			continue
		}

		//TODO Create BPF Data ->

		log.Infof("Found PROG Section at Index %v", sectionIndex)
		splitProgType := strings.Split(section.Name, "/")
		progType := strings.ToLower(splitProgType[0])
		var subProgType string
		retrievedProgParams := len(splitProgType)
		// Kprobe <kprobe/<prog name>>
		if retrievedProgParams == 2 {
			subProgType = strings.ToLower(splitProgType[1])
			log.Infof("Found subprog type %s", subProgType)
		}
		//Tracepoint <tracepoint/sched/<prog_name>>
		var subSystem string
		if retrievedProgParams == 3 {
			subSystem = strings.ToLower(splitProgType[1])
			subProgType = strings.ToLower(splitProgType[2])
			log.Infof("Found subprog type %s", subSystem)
		}
		log.Infof("Found the progType %s", progType)
		if progType != "xdp" && progType != "tc_cls" && progType != "tc_act" && progType != "kprobe" && progType != "tracepoint" && progType != "kretprobe" {
			log.Infof("Not supported program %s", progType)
			continue
		}
		dataProg := section
		bpfData, err := c.loadElfProgSection(dataProg, reloSectionMap[uint32(sectionIndex)], license, progType, subSystem, subProgType, sectionIndex, elfFile, bpfProg, customizedPinPath)
		if err != nil {
			log.Infof("Failed to load the prog")
			return fmt.Errorf("Failed to load prog %q - %v", dataProg.Name, err)
		}
		c.BPFloadedprog[bpfData.Program.PinPath] = bpfData
	}

	return nil
}

func GetMapNameFromBPFPinPath(pinPath string) (string, string) {
	var log = logger.Get()
	//Get non-global first
	/*
		pinPathName := strings.Split(pinPath, "/")
		log.Infof("pinPathName: ", pinPathName[7])

		replicaNamespaceNameIdentifier := strings.SplitN(pinPathName[7], "_", 2)

		replicaNamespace := replicaNamespaceNameIdentifier[0]
		MapName := replicaNamespaceNameIdentifier[1]
	*/

	replicaNamespaceNameIdentifier := strings.Split(pinPath, "/")
	podIdentifier := strings.SplitN(replicaNamespaceNameIdentifier[7], "_", 2)
	log.Infof("Found Identified - %s : %s", podIdentifier[0], podIdentifier[1])

	replicaNamespace := podIdentifier[0]
	mapName := podIdentifier[1]

	log.Infof("JAYANTH ->  ", replicaNamespace, mapName)

	directionIdentifier := strings.Split(replicaNamespaceNameIdentifier[7], "_")
	direction := directionIdentifier[1]

	if direction == "ingress" {
		log.Infof("Adding ingress_map -> ", replicaNamespace)
		return "ingress_map", replicaNamespace
	} else if direction == "egress" {
		log.Infof("Adding egress_map -> ", replicaNamespace)
		return "egress_map", replicaNamespace
	}

	//This is global map, we cannot use global since there are multiple maps
	log.Infof("Adding GLOBAL %s -> %s", mapName, mapName)
	return mapName, mapName
}

func RecoverAllBpfProgramsAndMaps() (map[string]BPFdata, error) {
	var log = logger.Get()
	_, err := os.Stat(bpfFS)
	if err != nil {
		log.Infof("BPF FS director is not present")
		return nil, fmt.Errorf("BPF directory is not present %v", err)
	}

	var statfs syscall.Statfs_t
	//Pass DS here
	loadedPrograms := make(map[string]BPFdata)
	mapIDsToNames := make(map[int]string)
	mapPodSelector := make(map[string]map[int]string)
	if err := syscall.Statfs(bpfFS, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		log.Infof("BPF FS is mounted")
		if err := filepath.Walk(mapbpfFS, func(pinPath string, fsinfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !fsinfo.IsDir() {
				log.Infof("Dumping pinpaths - ", pinPath)
				bpfMapInfo, err := ebpf_maps.BpfGetMapFromPinPath(pinPath)
				if err != nil {
					log.Infof("Error getting mapInfo for pin path, this shouldn't happen")
					return err
				}
				mapID := bpfMapInfo.Id
				log.Infof("Got ID %d", mapID)

				//Get map name
				mapName, replicaNamespace := GetMapNameFromBPFPinPath(pinPath)

				log.Infof("Adding ID %d to name %s and NS %s", mapID, mapName, replicaNamespace)
				mapIDsToNames[int(mapID)] = mapName
				mapPodSelector[replicaNamespace] = mapIDsToNames
			}
			return nil
		}); err != nil {
			log.Infof("Error walking bpfdirectory:", err)
			return nil, fmt.Errorf("Error walking the bpfdirectory %v", err)
		}

		if err := filepath.Walk(progbpfFS, func(pinPath string, fsinfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !fsinfo.IsDir() {
				log.Infof("Dumping pinpaths - ", pinPath)
				pgmData := ebpf_progs.BPFProgram{
					PinPath: pinPath,
				}
				//mapData := [string]ebpf_maps.BPFMap{}
				bpfProgInfo, progFD, err := ebpf_progs.BpfGetProgFromPinPath(pinPath)
				if err != nil {
					log.Infof("Failed to progInfo for pinPath %s", pinPath)
					return err
				}
				pgmData.ProgFD = progFD
				//Conv type to string here
				//pgmData.ProgType = bpfProgInfo.Type

				recoveredMapData := make(map[string]ebpf_maps.BPFMap)
				if bpfProgInfo.NrMapIDs > 0 {
					log.Infof("Have associated maps to link")
					_, associatedBpfMapList, _, associatedBPFMapIDs, err := ebpf_progs.BpfGetMapInfoFromProgInfo(progFD, bpfProgInfo.NrMapIDs)
					if err != nil {
						log.Infof("Failed to get associated maps")
						return err
					}
					for mapInfoIdx := 0; mapInfoIdx < len(associatedBpfMapList); mapInfoIdx++ {
						bpfMapInfo := associatedBpfMapList[mapInfoIdx]
						newMapID := associatedBPFMapIDs[mapInfoIdx]
						recoveredBpfMap := ebpf_maps.BPFMap{}

						//Fill BPF map
						recoveredBpfMap.MapID = uint32(newMapID)

						replicaNamespaceNameIdentifier := strings.Split(pinPath, "/")
						podIdentifier := strings.SplitN(replicaNamespaceNameIdentifier[7], "_", 2)
						log.Infof("Found Identified - %s : %s", podIdentifier[0], podIdentifier[1])

						replicaNamespace := podIdentifier[0]
						mapIds, ok := mapPodSelector[replicaNamespace]
						if !ok {
							log.Infof("Failed to ID for %s", replicaNamespace)
							return fmt.Errorf("Failed to get err")
						}
						mapName := mapIds[int(recoveredBpfMap.MapID)]

						log.Infof("Mapinfo MapName - %v", bpfMapInfo.Name)
						//Fill BPF map metadata
						recoveredBpfMapMetaData := ebpf_maps.BpfMapData{
							Def: ebpf_maps.BpfMapDef{
								Type:       bpfMapInfo.Type,
								KeySize:    bpfMapInfo.KeySize,
								ValueSize:  bpfMapInfo.ValueSize,
								MaxEntries: bpfMapInfo.MaxEntries,
								Flags:      bpfMapInfo.MapFlags,
							},
							Name: mapName,
						}
						recoveredBpfMap.MapMetaData = recoveredBpfMapMetaData
						recoveredMapData[mapName] = recoveredBpfMap
					}

				}
				recoveredBPFdata := BPFdata{
					Program: pgmData,
					Maps:    recoveredMapData,
				}
				loadedPrograms[pinPath] = recoveredBPFdata
				//loadedPrograms = append(loadedPrograms, recoveredBPFdata)
			}
			return nil
		}); err != nil {
			log.Infof("Error walking bpfdirectory:", err)
			return nil, fmt.Errorf("Error walking the bpfdirectory %v", err)
		}
	} else {
		log.Infof("error checking BPF FS, might not be mounted %v", err)
		return nil, fmt.Errorf("error checking BPF FS might not be mounted %v", err)
	}
	//Return DS here
	return loadedPrograms, nil
}
