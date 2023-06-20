package main

import (
	"fmt"
	"syscall"
	"text/tabwriter"
	"os"
	"strings"
	"github.com/fatih/color"
	goelf "github.com/jayanthvn/pure-gobpf/pkg/elfparser"
	"github.com/jayanthvn/pure-gobpf/pkg/ebpf_tc"
)

type testFunc struct {
	Name string
	Func func() error 
}

func mount_bpf_fs() error {
	fmt.Println("Let's mount BPF FS")
	err := syscall.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "mode=0700")
	if err != nil {
		fmt.Println("error mounting bpffs: %v", err)
	}
	return err
}

func unmount_bpf_fs() error {
	fmt.Println("Let's unmount BPF FS")
	err := syscall.Unmount("/sys/fs/bpf", 0)
	if err != nil {
		fmt.Println("error unmounting bpffs: %v", err)
	}
	return err
}

func print_failure() {
	fmt.Println("\x1b[31mFAILED\x1b[0m")
}

func print_success() {
	fmt.Println("\x1b[32mSUCCESS!\x1b[0m")
}

func print_message(message string) {
	color := "\x1b[33m"
	formattedMessage := fmt.Sprintf("%s%s\x1b[0m", color, message)
	fmt.Println(formattedMessage)
}


func main() {
	fmt.Println("\x1b[34mStart testing SDK.........\x1b[0m")
	mount_bpf_fs()
 	testFunctions := []testFunc{
		{Name: "Test loading Program", Func: TestLoadProg},
		{Name: "Test loading TC filter", Func: TestLoadTCfilter},
	}

	testSummary := make(map[string]string)

	for _, fn := range testFunctions {
		message := "Testing "+fn.Name
		print_message(message)
		err := fn.Func()
		if err != nil {
			print_failure()
			testSummary[fn.Name] = "FAILED"
		} else {
			print_success()
			testSummary[fn.Name] = "SUCCESS"
		}
	}
	unmount_bpf_fs()

	fmt.Println(color.MagentaString("==========================================================="))
	fmt.Println(color.MagentaString("                   TESTING SUMMARY                         "))
	fmt.Println(color.MagentaString("==========================================================="))
	summary := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.AlignRight|tabwriter.Debug)
	header := strings.Join([]string{color.YellowString("TestCase"), color.YellowString("Result")}, "\t")

	fmt.Fprintln(summary, header)

	for k, v := range testSummary {
		if v == "FAILED" {
			fmt.Fprintf(summary, "%s\t%s\n", k, color.RedString(v))
		}
		if v == "SUCCESS" {
			fmt.Fprintf(summary, "%s\t%s\n", k, color.GreenString(v))
		}
	}
	summary.Flush()
	fmt.Println(color.MagentaString("==========================================================="))
}

func TestLoadProg() error {
	progInfo, _, err := goelf.LoadBpfFile("c/test.bpf.elf", "test")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for k, _ := range progInfo {
		fmt.Println("Prog Info: ", "Pin Path: ", k)
	}
	return nil
}

func TestLoadTCfilter() error {
	progInfo, _, err := goelf.LoadBpfFile("c/test.bpf.elf", "test")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for k, _ := range progInfo {
		fmt.Println("Prog Info: ", "Pin Path: ", k)
	}

	tcProg := progInfo["/sys/fs/bpf/globals/aws/programs/test_handle_ingress"].Program
	progFD := tcProg.ProgFD

	fmt.Println("Try Attach ingress probe")
	err = ebpf_tc.TCIngressAttach("lo", int(progFD))
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	fmt.Println("Try Attach egress probe")
	err = ebpf_tc.TCEgressAttach("lo", int(progFD))
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	fmt.Println("Try Detach ingress probe")
	err = ebpf_tc.TCIngressDetach("lo")
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	fmt.Println("Try Detach egress probe")
	err = ebpf_tc.TCEgressDetach("lo")
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	return nil
}
