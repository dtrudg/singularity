// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)

func readIntFromFile(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		return strconv.ParseInt(scanner.Text(), 10, 64)
	}

	return 0, fmt.Errorf("no data found")
}
