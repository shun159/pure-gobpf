package ebpf_progs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_maps"
	"github.com/jayanthvn/pure-gobpf/pkg/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	BPF_PROG_LOAD   = 5
	BPF_PROG_ATTACH = 8
	BPF_PROG_DETACH = 9
	bpfFS           = "/sys/fs/bpf"
	//Ref - https://man7.org/linux/man-pages/man2/statfs.2.html
	BPF_FS_MAGIC = 0xcafe4a11
)

type BpfProgAPIs interface {
	PinProg(progFD uint32, pinPath string) error
	LoadProg(progType string, data []byte, licenseStr string, pinPath string, insDefSize int) (int, error)
}

type BPFProgram struct {
	// return program name, prog FD and pinPath
	ProgFD      int
	PinPath     string
	ProgType    string
	SubSystem   string
	SubProgType string
}

func mount_bpf_fs() error {
	var log = logger.Get()
	log.Infof("Let's mount BPF FS")
	err := syscall.Mount("bpf", bpfFS, "bpf", 0, "mode=0700")
	if err != nil {
		log.Errorf("error mounting bpffs: %v", err)
	}
	return err
}

func (m *BPFProgram) PinProg(progFD uint32, pinPath string) error {
	var log = logger.Get()

	var statfs syscall.Statfs_t
	err := syscall.Statfs(bpfFS, &statfs)
	if err != nil {
		fmt.Println("Error:", err)
		log.Infof("error checking BPF FS %v", err)
		return fmt.Errorf("error checking BPF FS %v", err)
	}

	if statfs.Type != BPF_FS_MAGIC {
		err = mount_bpf_fs()
		if err != nil {
			log.Errorf("error mounting bpffs: %v", err)
			return err
		}
	}

	err = os.MkdirAll(filepath.Dir(pinPath), 0755)
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

	return ebpf_maps.PinObject(progFD, pinPath)
}

func (m *BPFProgram) LoadProg(progType string, data []byte, licenseStr string, pinPath string, insDefSize int) (int, error) {
	var log = logger.Get()

	var prog_type uint32
	switch progType {
	case "xdp":
		prog_type = uint32(netlink.BPF_PROG_TYPE_XDP)
	case "tc_cls":
		prog_type = uint32(netlink.BPF_PROG_TYPE_SCHED_CLS)
	case "tc_act":
		prog_type = uint32(netlink.BPF_PROG_TYPE_SCHED_ACT)
	case "kprobe":
		prog_type = uint32(netlink.BPF_PROG_TYPE_KPROBE)
	case "kretprobe":
		prog_type = uint32(netlink.BPF_PROG_TYPE_KPROBE)
	case "tracepoint":
		prog_type = uint32(netlink.BPF_PROG_TYPE_TRACEPOINT)
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
	err := m.PinProg(uint32(fd), pinPath)
	if err != nil {
		log.Infof("pin prog failed %v", err)
		return 0, err
	}
	return int(fd), nil
}
