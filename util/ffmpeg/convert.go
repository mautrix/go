// Copyright (c) 2022 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ffmpeg

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/util"
)

var ffmpegDefaultParams = []string{"-hide_banner", "-loglevel", "warning"}

// Convert a media file on the disk using ffmpeg.
//
// Args:
// * inputFile: The full path to the file.
// * outputExtension: The extension that the output file should be.
// * inputArgs: Arguments to tell ffmpeg how to parse the input file.
// * outputArgs: Arguments to tell ffmpeg how to convert the file to reach the wanted output.
// * removeInput: Whether the input file should be removed after converting.
//
// Returns: the path to the converted file.
func ConvertPath(inputFile string, outputExtension string, inputArgs []string, outputArgs []string, removeInput bool) (string, error) {
	outputFilename := strings.TrimSuffix(inputFile, filepath.Ext(inputFile)) + outputExtension

	args := []string{}
	args = append(args, ffmpegDefaultParams...)
	args = append(args, inputArgs...)
	args = append(args, "-i", inputFile)
	args = append(args, outputArgs...)
	args = append(args, outputFilename)

	cmd := exec.Command("ffmpeg", args...)
	vcLog := log.Sub("ffmpeg").Writer(log.LevelWarn)
	cmd.Stdout = vcLog
	cmd.Stderr = vcLog
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("ffmpeg error: %+w", err)
	}

	if removeInput {
		os.Remove(inputFile)
	}

	return outputFilename, nil
}

// Convert media data using ffmpeg.
//
// Args:
// * data: The media data to convert
// * outputExtension: The extension that the output file should be.
// * inputArgs: Arguments to tell ffmpeg how to parse the input file.
// * outputArgs: Arguments to tell ffmpeg how to convert the file to reach the wanted output.
// * inputMime: The mimetype of the input data.
//
// Returns: the converted data
func ConvertBytes(data []byte, outputExtension string, inputArgs []string, outputArgs []string, inputMime string) ([]byte, error) {
	tempdir, err := ioutil.TempDir("", "mautrix_ffmpeg_*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempdir)
	inputFileName := fmt.Sprintf("%s/input%s", tempdir, util.ExtensionFromMimetype(inputMime))

	inputFile, err := os.OpenFile(inputFileName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %w", err)
	}
	_, err = inputFile.Write(data)
	if err != nil {
		inputFile.Close()
		return nil, fmt.Errorf("failed to write data to input file: %w", err)
	}
	inputFile.Close()

	outputPath, err := ConvertPath(inputFileName, outputExtension, inputArgs, outputArgs, false)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(outputPath)
}
