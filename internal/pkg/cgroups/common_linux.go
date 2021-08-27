// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cgroups

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/containerd/cgroups"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sylabs/singularity/pkg/sylog"
)

func ApplyFromFile(path string, pid int) (err error) {
	if cgroups.Mode() == cgroups.Unified {
		sylog.Debugf("Applying cgroups v2 configuration")
		return applyFromFileV2(path, pid)
	}
	sylog.Debugf("Applying cgroups v1 configuration")
	return applyFromFileV1(path, pid)
}

func applyFromFileV1(path string, pid int) (err error) {
	cgroupPath := filepath.Join("/singularity", strconv.Itoa(pid))
	cgroupManager := Manager{Pid: pid, Path: cgroupPath}
	if err := cgroupManager.ApplyFromFile(path); err != nil {
		return fmt.Errorf("failed to apply cgroups resources restriction: %s", err)
	}
	return nil
}

func applyFromFileV2(path string, pid int) (err error) {
	cgroupGroup := filepath.Join("/singularity", strconv.Itoa(pid))
	cgroupManager := ManagerV2{Pid: uint64(pid), Group: cgroupGroup}
	if err := cgroupManager.ApplyFromFile(path); err != nil {
		return fmt.Errorf("failed to apply cgroups resources restriction: %s", err)
	}
	return nil
}

func readSpecFromFile(path string) (spec specs.LinuxResources, err error) {
	conf, err := LoadConfig(path)
	if err != nil {
		return
	}

	// convert TOML structures to OCI JSON structures
	data, err := json.Marshal(conf)
	if err != nil {
		return
	}

	if err = json.Unmarshal(data, &spec); err != nil {
		return
	}

	return
}
