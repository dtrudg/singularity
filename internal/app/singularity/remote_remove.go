// Copyright (c) 2019, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package singularity

import (
	"fmt"
	"os"

	"github.com/sylabs/singularity/internal/pkg/remote"
	"github.com/sylabs/singularity/internal/pkg/remote/endpoint"
)

// RemoteRemove deletes a remote endpoint from the configuration
func RemoteRemove(configFile, name string, global bool) (err error) {
	c := &remote.Config{}

	// opening config file
	file, err := os.OpenFile(configFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("while opening remote config file: %s", err)
	}
	defer file.Close()

	// read file contents to config struct
	c, err = remote.ReadFrom(file)
	if err != nil {
		return fmt.Errorf("while parsing remote config data: %s", err)
	}

	// We want to give a nice message if a user tries to remove a global
	// remote without `--global`... so check for that:
	if !global {
		// bring in the global settings
		cSys := &remote.Config{
			Remotes: map[string]*endpoint.Config{},
		}
		if err := syncSysConfig(cSys); err != nil {
			return fmt.Errorf("while parsing global remote config data: %s", err)
		}
		_, ok := cSys.Remotes[name]
		if ok {
			return fmt.Errorf("cannot remove global remote %s without --global as root user", name)
		}
	}

	if err := c.Remove(name); err != nil {
		return err
	}

	// truncating file before writing new contents and syncing to commit file
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("while truncating remote config file: %s", err)
	}

	if n, err := file.Seek(0, os.SEEK_SET); err != nil || n != 0 {
		return fmt.Errorf("failed to reset %s cursor: %s", file.Name(), err)
	}

	if _, err := c.WriteTo(file); err != nil {
		return fmt.Errorf("while writing remote config to file: %s", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to flush remote config file %s: %s", file.Name(), err)
	}

	return nil
}
