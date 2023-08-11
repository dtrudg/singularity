// Copyright (c) 2019-2023, Sylabs Inc. All rights reserved.
// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package args

import (
	"bytes"
	"fmt"
	"io"
	"regexp"

	"github.com/samber/lo"
)

var buildArgsRegexp = regexp.MustCompile(`{{\s*(\w+)\s*}}`)

// NewReader creates a io.Reader that will provide the contents of a def file
// with build-args replacements applied. src is an io.Reader from which the
// pre-replacement def file will be read. buildArgsMap provides the replacements
// requested by the user, and defaultArgsMap provides the replacements specified
// in the %arguments section of the def file (or build stage). The arguments
// actually encountered in the course of the replacement will be appended to the
// slice designated by consumedArgs.
func NewReader(src io.Reader, buildArgsMap map[string]string, defaultArgsMap map[string]string, consumedArgs *[]string) (io.Reader, error) {
	srcBytes, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	matches := buildArgsRegexp.FindAllSubmatchIndex(srcBytes, -1)
	mapOfConsumedArgs := make(map[string]bool)
	var buf bytes.Buffer
	bufWriter := io.Writer(&buf)
	i := 0
	for _, m := range matches {
		if _, err := bufWriter.Write(srcBytes[i:m[0]]); err != nil {
			return nil, err
		}
		argName := string(srcBytes[m[2]:m[3]])
		val, ok := buildArgsMap[argName]
		if !ok {
			val, ok = defaultArgsMap[argName]
		}
		if !ok {
			return nil, fmt.Errorf("build var %s is not defined through either --build-arg (--build-arg-file) or 'arguments' section", argName)
		}
		if _, err := bufWriter.Write([]byte(val)); err != nil {
			return nil, err
		}
		mapOfConsumedArgs[argName] = true
		i = m[1]
	}
	if _, err := bufWriter.Write(srcBytes[i:]); err != nil {
		return nil, err
	}

	*consumedArgs = append(*consumedArgs, lo.Keys(mapOfConsumedArgs)...)

	r := bytes.NewReader(buf.Bytes())

	return r, nil
}
