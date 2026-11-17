package k8s

import (
	"testing"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestParseProcNames(t *testing.T) {
	out := "12\t/usr/bin/coreutils\t/usr/bin/sleep\n" +
		"sh: can't open /procRoot/13/cmdline\n" +
		"14\t/usr/bin/dash\tsh\n" + // not a path: ignored
		"x\t/a\t/b\n" +
		"15\t/bin/busybox\t/bin/sh\n"
	got := parseProcNames([]byte(out))
	if len(got) != 2 || got[12] != (startedBy{"/usr/bin/coreutils", "/usr/bin/sleep"}) || got[15].path != "/bin/sh" {
		t.Fatalf("got %+v", got)
	}
}

func TestRenameStartedBy(t *testing.T) {
	proc := func(pid uint32, binary string) *tetragon.Process {
		return &tetragon.Process{Pid: wrapperspb.UInt32(pid), Binary: binary, Flags: "procFS"}
	}
	sleep := proc(12, "/usr/bin/coreutils")
	reused := proc(13, "/usr/bin/nginx") // the ID now belongs to something else
	unknown := proc(14, "/usr/bin/python3.12")
	noPid := &tetragon.Process{Binary: "/usr/bin/coreutils"}
	renameStartedBy([]*tetragon.Process{sleep, reused, unknown, noPid}, map[uint32]startedBy{
		12: {"/usr/bin/coreutils", "/usr/bin/sleep"},
		13: {"/usr/bin/coreutils", "/usr/bin/ls"},
	})
	if sleep.Binary != "/usr/bin/sleep" {
		t.Errorf("sleep: %q", sleep.Binary)
	}
	if reused.Binary != "/usr/bin/nginx" || unknown.Binary != "/usr/bin/python3.12" || noPid.Binary != "/usr/bin/coreutils" {
		t.Errorf("renamed what it should not: %q %q %q", reused.Binary, unknown.Binary, noPid.Binary)
	}
}

func TestScannedFromProc(t *testing.T) {
	if !scannedFromProc(&tetragon.Process{Flags: "procFS auid"}) || scannedFromProc(&tetragon.Process{Flags: "execve clone"}) {
		t.Fatal("flags misread")
	}
}

func TestIsOwnProcNames(t *testing.T) {
	sh := &tetragon.Process{Binary: "/bin/sh", Arguments: "-c \"# " + procNamesMark + " P=/procRoot\""}
	if !isOwnProcNames(sh, nil) || !isOwnProcNames(&tetragon.Process{Binary: "/usr/bin/tr"}, sh) {
		t.Error("the script's own commands were not recognised")
	}
	if isOwnProcNames(&tetragon.Process{Binary: "/usr/bin/tetra", Arguments: "status"}, &tetragon.Process{Binary: "/bin/sh"}) {
		t.Error("an unrelated command was taken for the script's")
	}
}
