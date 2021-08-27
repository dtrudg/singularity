// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sylabs/singularity/internal/pkg/test"
	"github.com/sylabs/singularity/internal/pkg/test/tool/require"
)

func TestCgroupsV2(t *testing.T) {
	test.EnsurePrivilege(t)
	require.CgroupsV2(t)

	cmd := exec.Command("/bin/cat")
	pipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	pid := cmd.Process.Pid
	strPid := strconv.Itoa(pid)
	group := filepath.Join("/singularity", strPid)

	manager := &ManagerV2{Pid: uint64(pid), Group: group}

	cgroupsToml := "example/cgroups.toml"
	// Some systems, e.g. ppc64le may not have a 2MB page size, so don't
	// apply a 2MB hugetlb limit if that's the case.
	_, err = os.Stat("/sys/fs/cgroup/dev-hugepages.mount/hugetlb.2MB.max")
	if os.IsNotExist(err) {
		t.Log("No hugetlb.2MB.max - using alternate cgroups test file")
		cgroupsToml = "example/cgroups-no-hugetlb.toml"
	}

	if err := manager.ApplyFromFile(cgroupsToml); err != nil {
		t.Fatal(err)
	}
	defer manager.Remove()

	pidsMax := filepath.Join(mountPoint, group, "pids.max")

	i, err := readIntFromFile(pidsMax)
	if err != nil {
		t.Fatalf("failed to read %s: %s", pidsMax, err)
	}

	if i != 1024 {
		t.Errorf("got pids.max = %d, expected 1024", i)
	}

	pipe.Close()

	cmd.Wait()
}

func TestPauseResumeV2(t *testing.T) {
	test.EnsurePrivilege(t)
	require.CgroupsV2(t)

	manager := &ManagerV2{}
	if err := manager.Pause(); err == nil {
		t.Errorf("unexpected success with PID 0")
	}
	if err := manager.Resume(); err == nil {
		t.Errorf("unexpected success with PID 0")
	}

	// Test process is continuous cat on `/dev/zero` so we will be able to see
	// a change to 'S' state when we freeze the cgroup.
	cmd := exec.Command("/bin/cat", "/dev/zero")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	manager.Pid = uint64(cmd.Process.Pid)
	manager.Group = filepath.Join("/singularity", strconv.Itoa(cmd.Process.Pid))

	if err := manager.ApplyFromFile("example/cgroups.toml"); err != nil {
		t.Fatal(err)
	}
	defer manager.Remove()

	manager.Pause()

	file, err := os.Open(fmt.Sprintf("/proc/%d/status", manager.Pid))
	if err != nil {
		t.Error(err)
	}

	scanner := bufio.NewScanner(file)
	stateOk := false

	for scanner.Scan() {
		// freeze in cgroup v2 goes to S state, can be killed by fatal signal
		if strings.HasPrefix(scanner.Text(), "State:\tS") {
			stateOk = true
			break
		}
	}

	if !stateOk {
		t.Errorf("failed to pause process %d", manager.Pid)
	}

	file.Close()

	manager.Resume()

	file, err = os.Open(fmt.Sprintf("/proc/%d/status", manager.Pid))
	if err != nil {
		t.Error(err)
	}

	scanner = bufio.NewScanner(file)
	stateOk = false

	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(text, "State:\tS") || strings.HasPrefix(text, "State:\tR") {
			stateOk = true
			break
		}
	}

	if !stateOk {
		t.Errorf("failed to resume process %d", manager.Pid)
	}

	file.Close()

	cmd.Process.Kill()
}
