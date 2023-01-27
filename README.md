# pure-gobpf

This is a SDK to load BPF programs implemented in golang. The SDK internally calls the bpf() system calls to load the programs and maps defined in the elf. Initial release will support only attaching TC and XDP but will support all map types.

Contributions welcome!

# Getting started

## How to build elf file?

```
clang -I../../.. -O2 -target bpf -c <C file> -o <ELF file>
```

## How to build SDK?

Run `make buid-linux` - this will build the sdk binary.

## How to use the SDK?

In your application, 

1. Get the latest SDK -

```
GOPROXY=direct go get github.com/jayanthvn/pure-gobpf
```

2. Import the elfparser - 

```
goebpfelfparser "gitlab.aws.dev/varavaj/aws-ebpf-gosdk/pkg/elfparser"
```

3. Load the elf -

```
goebpfelfparser.LoadBpfFile(<ELF file>)
```

This return ELFContext which contains all programs under a section and all maps.

```
type ELFContext struct {
	// .elf will have multiple sections and maps
	Section map[string]ELFSection // Indexed by section type
	Maps    map[string]ELFMap     // Index by map name
}

type ELFSection struct {
	// Each sections will have a program but a single section type can have multiple programs
	// like tc_cls
	Programs map[string]ELFProgram // Index by program name
}

type ELFProgram struct {
	// return program name, prog FD and pinPath
	ProgFD  int
	PinPath string
}

type ELFMap struct {
	// return map type, map FD and pinPath
	MapType int
	MapFD   int
	PinPath string
}
```

## How to attach XDP?

1. Import the ebpf package - 

```
goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
```

2. Attach XDP -

Pass the interface name, program FD and program name.

```
elfcontext, err := goebpfelfparser.LoadBpfFile(<ELF file>)

Retrieve the progFD for the intended program from elfcontext -

err = goebpf.XDPAttach(hostVethName, progFD)
```

## How to attach TC?

1. Import the ebpf package - 

```
goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
```

2. Attach TC - 

```
elfcontext, err := goebpfelfparser.LoadBpfFile(<ELF file>)

Retrieve the progFD for the intended program from elfcontext -

err = goebpf.TCIngressAttach(hostVethName, progFD)
```

## Sample example

### Fetch program from ELFContext - 

```
    var elfContext *goebpfelfparser.ELFContext
    elfContext, err = goebpfelfparser.LoadBpfFile(<ELF file>)
    if err != nil {
	    log.Errorf("LoadElf() failed: %v", err)
    }

    for pgmName, pgmData := range elfContext.Section["xdp"].Programs {
	    log.Infof("xdp -> PgmName %s : ProgFD %d and PinPath %s", pgmName, pgmData.ProgFD, pgmData.PinPath)
    }

    for pgmName, pgmData := range elfContext.Section["tc_cls"].Programs {
	    log.Infof("tc_cls -> PgmName %s : ProgFD %d and PinPath %s", pgmName, pgmData.ProgFD, pgmData.PinPath)
    }
```

### Map operations -

```
    var elfContext *goebpfelfparser.ELFContext
	elfContext, err = goebpfelfparser.LoadBpfFile(<ELF file>)
	if err != nil {
		log.Errorf("LoadElf() failed: %v", err)
	}

	for pgmName, pgmData := range elfContext.Section["xdp"].Programs {
		log.Infof("xdp -> PgmName %s : ProgFD %d and PinPath %s", pgmName, pgmData.ProgFD, pgmData.PinPath)
	}

	for pgmName, pgmData := range elfContext.Section["tc_cls"].Programs {
		log.Infof("tc_cls -> PgmName %s : ProgFD %d and PinPath %s", pgmName, pgmData.ProgFD, pgmData.PinPath)
	}

	for k, v := range elfContext.Maps {
		log.Infof("Found map %s with fd %d", k, v.MapFD)
	}

	//Insert into map
	type BPFInetTrieKey struct {
		Prefixlen uint32
		Addr [4]byte
	}
	dummykey := BPFInetTrieKey{
		Prefixlen: 32,
		Addr: [4]byte{192, 168, 0, 0},
	}
	dummyvalue := uint32(40)

	dummykey2 := BPFInetTrieKey{
		Prefixlen: 32,
		Addr: [4]byte{192, 168, 0, 1},
	}
	dummyvalue2 := uint32(30)

	if mapToUpdate, ok := elfContext.Maps["ingressmap"]; ok {
		log.Infof("Found map to Create entry")
		err = mapToUpdate.CreateMapEntry(uintptr(unsafe.Pointer((&dummykey))), uintptr(unsafe.Pointer((&dummyvalue))))
		if err != nil {
			log.Errorf("Unable to Insert into eBPF map: %v", err)
		}
		dummyvalue := uint32(20)

		log.Infof("Found map to Update entry")
		err = mapToUpdate.UpdateMapEntry(uintptr(unsafe.Pointer((&dummykey))), uintptr(unsafe.Pointer((&dummyvalue))))
		if err != nil {
			log.Errorf("Unable to Update into eBPF map: %v", err)
		}

		var mapVal uint32
		log.Infof("Get map entry")
		err := mapToUpdate.GetMapEntry(uintptr(unsafe.Pointer(&dummykey)), uintptr(unsafe.Pointer(&mapVal)))
		if err != nil {
			log.Errorf("Unable to get map entry: %v", err)
		} else {
			log.Infof("Found the map entry and value %d", mapVal)
		}

		log.Infof("Found map to Create dummy2 entry")
		err = mapToUpdate.CreateMapEntry(uintptr(unsafe.Pointer((&dummykey2))), uintptr(unsafe.Pointer((&dummyvalue2))))
		if err != nil {
			log.Errorf("Unable to Insert into eBPF map: %v", err)
		}

		log.Infof("Try next key")
		nextKey := BPFInetTrieKey{}
		err = mapToUpdate.GetNextMapEntry(uintptr(unsafe.Pointer(&dummykey)), uintptr(unsafe.Pointer(&nextKey)))
		if err != nil {
			log.Errorf("Unable to get next key: %v", err)
		} else {
			log.Infof("Get map entry of next key")
			var newMapVal uint32
			err := mapToUpdate.GetMapEntry(uintptr(unsafe.Pointer(&nextKey)), uintptr(unsafe.Pointer(&newMapVal)))
			if err != nil {
				log.Errorf("Unable to get next map entry: %v", err)
			} else {
				log.Infof("Found the next map entry and value %d", newMapVal)
			}
		}

		log.Infof("Found map to Delete entry")
		err = mapToUpdate.DeleteMapEntry(uintptr(unsafe.Pointer((&dummykey))))
		if err != nil {
			log.Errorf("Unable to Delete in eBPF map: %v", err)
		}
	}
```

### Map dump all -

```
		iterKey := BPFInetTrieKey{}
		iterNextKey := BPFInetTrieKey{}

		err = mapToUpdate.GetFirstMapEntry(uintptr(unsafe.Pointer(&iterKey)))
		if err != nil {
			log.Errorf("Unable to get First key: %v", err)
		} else {
			for {
				var newMapVal uint32
				err = mapToUpdate.GetMapEntry(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&newMapVal)))
				if err != nil {
					log.Errorf("Unable to get map entry: %v", err)
				} else {
					log.Infof("Found the map entry and value %d", newMapVal)
				}

				err = mapToUpdate.GetNextMapEntry(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterNextKey)))
				if err != nil {
					log.Errorf("Done searching : %v", err)
					break
				}
				iterKey = iterNextKey
			}
		}
```
