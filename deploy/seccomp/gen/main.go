// Command gen writes deploy/seccomp/teknoir-desktop.json, the seccomp profile a
// virtual-mode teknoir-desktop pod runs with (seccompProfile type Localhost,
// localhostProfile profiles/teknoir-desktop.json).
//
// The profile is containerd's RuntimeDefault for a container with no
// capabilities (what the pod runs with: capabilities drop ALL), from the
// containerd that k3s ships (go.mod pins the k3s fork), plus one rule: clone,
// unshare and chroot are allowed without the namespace-flag filter. That is what
// Chromium's renderer sandbox needs (an unprivileged user namespace, then
// chroot inside it). Everything else RuntimeDefault denies stays denied
// (mount, setns, bpf, keyctl, ptrace of other users, ...), and clone3 still
// answers ENOSYS so glibc falls back to clone.
//
// containerd builds RuntimeDefault for the architecture it runs on, so the
// profile is made per architecture and merged:
//
//	gen -arch                  print this architecture's profile
//	gen -merge a.json b.json   merge per-architecture profiles, add the rule, print
//
// The Makefile target "seccomp" runs it for amd64 and arm64 (arm64 under
// qemu-user binfmt). Rules for a syscall an architecture does not have are
// skipped by runc, so one merged file serves both.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// sandboxSyscalls are allowed unconditionally on top of RuntimeDefault.
var sandboxSyscalls = []string{"chroot", "clone", "unshare"}

func main() {
	arch := flag.Bool("arch", false, "print the RuntimeDefault profile (no capabilities) of this architecture")
	merge := flag.Bool("merge", false, "merge the per-architecture profiles given as arguments and add the sandbox rule")
	flag.Parse()
	switch {
	case *arch:
		sp := &specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}}}
		emit(seccomp.DefaultProfile(sp))
	case *merge && flag.NArg() > 0:
		var profiles []*specs.LinuxSeccomp
		for _, f := range flag.Args() {
			b, err := os.ReadFile(f)
			check(err)
			p := &specs.LinuxSeccomp{}
			check(json.Unmarshal(b, p))
			profiles = append(profiles, p)
		}
		emit(mergeProfiles(profiles))
	default:
		fmt.Fprintln(os.Stderr, "usage: gen -arch | gen -merge a.json [b.json ...]")
		os.Exit(2)
	}
}

func mergeProfiles(profiles []*specs.LinuxSeccomp) *specs.LinuxSeccomp {
	out := &specs.LinuxSeccomp{DefaultAction: profiles[0].DefaultAction, DefaultErrnoRet: profiles[0].DefaultErrnoRet}
	arches := map[specs.Arch]bool{}
	seen := map[string]bool{}
	for _, p := range profiles {
		if p.DefaultAction != out.DefaultAction {
			check(fmt.Errorf("default actions differ: %s and %s", out.DefaultAction, p.DefaultAction))
		}
		for _, a := range p.Architectures {
			arches[a] = true
		}
		for _, s := range p.Syscalls {
			if isFilteredClone(s) {
				continue // replaced by the unconditional rule below
			}
			key, err := json.Marshal(s)
			check(err)
			if !seen[string(key)] {
				seen[string(key)] = true
				out.Syscalls = append(out.Syscalls, s)
			}
		}
	}
	for a := range arches {
		out.Architectures = append(out.Architectures, a)
	}
	sort.Slice(out.Architectures, func(i, j int) bool { return out.Architectures[i] < out.Architectures[j] })
	out.Syscalls = append(out.Syscalls, specs.LinuxSyscall{Names: sandboxSyscalls, Action: specs.ActAllow})
	return out
}

// isFilteredClone is RuntimeDefault's "clone without namespace flags" rule.
func isFilteredClone(s specs.LinuxSyscall) bool {
	return len(s.Names) == 1 && s.Names[0] == "clone" && s.Action == specs.ActAllow && len(s.Args) > 0
}

func emit(p *specs.LinuxSeccomp) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	check(enc.Encode(p))
	_, err := os.Stdout.Write(buf.Bytes())
	check(err)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}
