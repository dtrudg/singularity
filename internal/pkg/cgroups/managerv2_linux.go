// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cgroups

import (
	"fmt"

	cgroupsv2 "github.com/containerd/cgroups/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const mountPoint = "/sys/fs/cgroup"

// Manager manage container cgroup resources restriction
type ManagerV2 struct {
	Group  string
	Pid    uint64
	cgroup *cgroupsv2.Manager
}

// ApplyFromSpec applies cgroups resources restriction from OCI specification
func (m *ManagerV2) ApplyFromSpec(spec *specs.LinuxResources) (err error) {
	if m.Group == "" {
		return fmt.Errorf("group must be specified")
	}

	s := spec
	if s == nil {
		s = &specs.LinuxResources{}
	}

	// translate the LinuxResources cgroupsv1 / OCI spec to v2 Resources
	res := cgroupsv2.ToResources(s)

	// creates cgroup
	m.cgroup, err = cgroupsv2.NewManager(mountPoint, m.Group, res)
	if err != nil {
		return err
	}

	if err = m.cgroup.AddProc(m.Pid); err != nil {
		return err
	}

	return
}

// ApplyFromFile applies cgroups resources restriction from TOML configuration
// file
func (m *ManagerV2) ApplyFromFile(path string) error {
	spec, err := readSpecFromFile(path)
	if err != nil {
		return err
	}
	return m.ApplyFromSpec(&spec)
}

// Remove removes resources restriction for current managed process
func (m *ManagerV2) Remove() (err error) {
	// deletes subgroup
	return m.cgroup.Delete()
}

func (m *ManagerV2) load() (err error) {
	if m.Group == "" {
		return fmt.Errorf("group must be specified")
	}
	m.cgroup, err = cgroupsv2.LoadManager(mountPoint, m.Group)
	return err
}

// Pause suspends all processes inside the container
func (m *ManagerV2) Pause() (err error) {
	if m.cgroup == nil {
		if err := m.load(); err != nil {
			return err
		}
	}
	return m.cgroup.Freeze()
}

// Resume resumes all processes that have been previously paused
func (m *ManagerV2) Resume() (err error) {
	if m.cgroup == nil {
		if err := m.load(); err != nil {
			return err
		}
	}
	return m.cgroup.Thaw()
}
