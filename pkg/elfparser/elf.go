package elfparser

/*
 #include <stdint.h>
 #include <linux/unistd.h>
 #include <linux/bpf.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>

 struct bpf_map_def {
   uint32_t map_type;
   uint32_t key_size;
   uint32_t value_size;
   uint32_t max_entries;
   uint32_t map_flags;
   uint32_t pinning;
   uint32_t inner_map_fd;
 };

#define BPF_MAP_DEF_SIZE sizeof(struct bpf_map_def)

#define BPF_INS_DEF_SIZE sizeof(struct bpf_insn)
*/
import "C"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps"
	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_progs"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
)

var (
	bpfInsDefSize = binary.Size(BPFInsn{})
	bpfMapDefSize = binary.Size(BPFMapDef{})
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

//Ref:https://github.com/torvalds/linux/blob/v5.10/samples/bpf/bpf_load.c
type BPFParser struct {
	BpfMapAPIs  ebpf_maps.APIs
	BpfProgAPIs ebpf_progs.APIs
	ElfContext  ELFContext
}

type ELFContext struct {
	// .elf will have multiple sections and maps
	Section map[string]ELFSection       // Indexed by section type
	Maps    map[string]ebpf_maps.BPFMap // Index by map name
}

type ELFSection struct {
	// Each sections will have a program but a single section type can have multiple programs
	// like tc_cls
	Programs map[string]ebpf_progs.BPFProgram // Index by program name
}

//https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L71
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

func LoadBpfFile(path string) (*BPFParser, error) {
	var log = logger.Get()
	f, err := os.Open(path)
	if err != nil {
		log.Infof("LoadBpfFile failed to open")
		return nil, err
	}
	defer f.Close()

	c := &BPFParser{}
	c.BpfMapAPIs, _ = ebpf_maps.New(log, "/sys/fs/bpf/", "globals")
	c.BpfProgAPIs, _ = ebpf_progs.New(log, "/sys/fs/bpf/", "globals")
	c.ElfContext = ELFContext{}
	err = c.doLoadELF(f)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func NullTerminatedStringToString(val []byte) string {
	// Calculate null terminated string len
	slen := len(val)
	for idx, ch := range val {
		if ch == 0 {
			slen = idx
			break
		}
	}
	return string(val[:slen])
}

func (c *BPFParser) loadElfMapsSection(mapsShndx int, dataMaps *elf.Section, elfFile *elf.File) error {
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

		bpfMap, err := c.BpfMapAPIs.CreateMap(loadedMaps)
		if err != nil {
			//Even if one map fails, we error out
			log.Infof("Failed to create map, continue to next map..just for debugging")
			continue
		}

		mapNameStr := loadedMaps.Name
		pinPath := "/sys/fs/bpf/globals/" + mapNameStr
		c.BpfMapAPIs.PinMap(bpfMap, pinPath)

		c.ElfContext.Maps[mapNameStr] = bpfMap
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

func (c *BPFParser) loadElfProgSection(dataProg *elf.Section, reloSection *elf.Section, license string, progType string, subSystem string, subProgType string, sectionIndex int, elfFile *elf.File) error {
	var log = logger.Get()

	//insDefSize := bpfInsDefSize
	insDefSize := uint64(bpfInsDefSize)

	log.Infof("Compare inssize gostruct %d cstruct %d", bpfInsDefSize, insDefSize)
	data, err := dataProg.Data()
	if err != nil {
		return err
	}

	//TODO : kprobe check is temp until we fix realloc null issue
	//if progType != "kprobe" {
	log.Infof("Loading Program with relocation section; Info:%v; Name: %s, Type: %s; Size: %v", reloSection.Info,
		reloSection.Name, reloSection.Type, reloSection.Size)
	//}

	//Single section might have multiple programs. So we retrieve one prog at a time and load.
	symbolTable, err := elfFile.Symbols()
	if err != nil {
		log.Infof("Get symbol failed")
		return fmt.Errorf("get symbols: %w", err)
	}

	//TODO : kprobe check is temp until we fix realloc null issue
	//if progType != "kprobe" {
	relocationEntries, err := parseRelocationSection(reloSection, elfFile)
	if err != nil || len(relocationEntries) == 0 {
		return fmt.Errorf("Unable to parse relocation entries....")
	}

	log.Infof("Applying Relocations..")
	for _, relocationEntry := range relocationEntries {
		if relocationEntry.relOffset >= len(data) {
			return fmt.Errorf("Invalid offset for the relocation entry %d", relocationEntry.relOffset)
		}

		//eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
		//of two consecutive 'struct bpf_insn' 8-byte blocks and interpreted as single
		//instruction that loads 64-bit immediate value into a dst_reg.
		//Ref: https://www.kernel.org/doc/Documentation/networking/filter.txt
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
			return fmt.Errorf("Invalid BPF instruction (at %d): %d",
				relocationEntry.relOffset, ebpfInstruction.Code)
		}

		// Point BPF instruction to the FD of the map referenced. Update the last 4 bytes of
		// instruction (immediate constant) with the map's FD.
		// BPF_MEM | <size> | BPF_STX:  *(size *) (dst_reg + off) = src_reg
		// BPF_MEM | <size> | BPF_ST:   *(size *) (dst_reg + off) = imm32
		mapName := relocationEntry.symbol.Name
		log.Infof("Map to be relocated; Name: %s", mapName)
		if progMap, ok := c.ElfContext.Maps[mapName]; ok {
			log.Infof("Map found. Replace the offset with corresponding Map FD: %v", progMap.MapFD)
			ebpfInstruction.SrcReg = 1 //dummy value for now
			ebpfInstruction.Imm = int32(progMap.MapFD)
			copy(data[relocationEntry.relOffset:relocationEntry.relOffset+8], ebpfInstruction.convertBPFInstructionToByteStream())
			log.Infof("From data: BPF Instruction code: %d; offset: %d; imm: %d",
				uint8(data[relocationEntry.relOffset]),
				uint16(binary.LittleEndian.Uint16(data[relocationEntry.relOffset+2:relocationEntry.relOffset+4])),
				uint32(binary.LittleEndian.Uint32(data[relocationEntry.relOffset+4:relocationEntry.relOffset+8])))
		} else {
			return fmt.Errorf("map '%s' doesn't exist", mapName)
		}
	}
	//}

	var pgmList = make(map[string]ebpf_progs.BPFProgram)
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
					return fmt.Errorf("Failed to Load the prog")
				}

				log.Infof("Sec '%s': found program '%s' at insn offset %d (%d bytes), code size %d insns (%d bytes)\n", progType, ProgName, secOff/(insDefSize), secOff, progSize/(insDefSize), progSize)
				if symbol.Value >= dataProg.Addr && symbol.Value < dataProg.Addr+dataProg.Size {
					// Extract the BPF program data from the section data
					log.Infof("Data offset - %d", symbol.Value-dataProg.Addr)
					log.Infof("Data len - %d", len(data))

					dataStart := (symbol.Value - dataProg.Addr)
					dataEnd := dataStart + progSize
					programData := make([]byte, progSize)
					copy(programData, data[dataStart:dataEnd])

					log.Infof("Program Data size - %d", len(programData))

					pinPath := "/sys/fs/bpf/globals/" + ProgName
					progFD, _ := c.BpfProgAPIs.LoadProg(progType, programData, license, pinPath, bpfInsDefSize)
					if progFD == -1 {
						log.Infof("Failed to load prog")
						return fmt.Errorf("Failed to Load the prog")
					}
					log.Infof("loaded prog with %d", progFD)
					pgmList[ProgName] = ebpf_progs.BPFProgram{
						ProgFD:      progFD,
						PinPath:     pinPath,
						ProgType:    progType,
						SubSystem:   subSystem,
						SubProgType: subProgType,
					}
				} else {
					log.Infof("Invalid ELF file\n")
					return fmt.Errorf("Failed to Load the prog")
				}
			}
		}
	}

	elfSection, ok := c.ElfContext.Section[progType]
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
	c.ElfContext.Section[progType] = elfSection

	return nil
}

func (c *BPFParser) doLoadELF(r io.ReaderAt) error {
	var log = logger.Get()
	var err error
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return err
	}

	c.ElfContext.Section = make(map[string]ELFSection)
	c.ElfContext.Maps = make(map[string]ebpf_maps.BPFMap)
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
		err := c.loadElfMapsSection(mapsShndx, dataMaps, elfFile)
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
		if progType != "xdp" && progType != "tc_cls" && progType != "tc_act" && progType != "kprobe" && progType != "tracepoint" {
			log.Infof("Not supported program %s", progType)
			continue
		}
		dataProg := section
		err = c.loadElfProgSection(dataProg, reloSectionMap[uint32(sectionIndex)], license, progType, subSystem, subProgType, sectionIndex, elfFile)
		if err != nil {
			log.Infof("Failed to load the prog")
			return fmt.Errorf("Failed to load prog %q - %v", dataProg.Name, err)
		}
	}

	return nil
}
