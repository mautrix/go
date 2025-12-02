// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
	"fmt"
	"iter"
	"os"
	"reflect"
	"strconv"
	"strings"

	"go.mau.fi/util/random"
)

var randomParseFilePrefix = random.String(16) + "READFILE:"

func parseEnv(prefix string) iter.Seq2[[]string, string] {
	return func(yield func([]string, string) bool) {
		for _, s := range os.Environ() {
			if !strings.HasPrefix(s, prefix) {
				continue
			}
			kv := strings.SplitN(s, "=", 2)
			key := strings.TrimPrefix(kv[0], prefix)
			value := kv[1]
			if strings.HasSuffix(key, "_FILE") {
				key = strings.TrimSuffix(key, "_FILE")
				value = randomParseFilePrefix + value
			}
			key = strings.ToLower(key)
			if !strings.ContainsRune(key, '.') {
				key = strings.ReplaceAll(key, "__", ".")
			}
			if !yield(strings.Split(key, "."), value) {
				return
			}
		}
	}
}

func reflectYAMLFieldName(f *reflect.StructField) string {
	parts := strings.SplitN(f.Tag.Get("yaml"), ",", 2)
	fieldName := parts[0]
	if fieldName == "-" && len(parts) == 1 {
		return ""
	}
	if fieldName == "" {
		return strings.ToLower(f.Name)
	}
	return fieldName
}

type reflectGetResult struct {
	val           reflect.Value
	valKind       reflect.Kind
	remainingPath []string
}

func reflectGetYAML(rv reflect.Value, path []string) (*reflectGetResult, bool) {
	if len(path) == 0 {
		return &reflectGetResult{val: rv, valKind: rv.Kind()}, true
	}
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Map:
		return &reflectGetResult{val: rv, remainingPath: path, valKind: rv.Type().Elem().Kind()}, true
	case reflect.Struct:
		fields := reflect.VisibleFields(rv.Type())
		for _, field := range fields {
			fieldName := reflectYAMLFieldName(&field)
			if fieldName != "" && fieldName == path[0] {
				return reflectGetYAML(rv.FieldByIndex(field.Index), path[1:])
			}
		}
	default:
	}
	return nil, false
}

func reflectGetFromMainOrNetwork(main, network reflect.Value, path []string) (*reflectGetResult, bool) {
	if len(path) > 0 && path[0] == "network" {
		return reflectGetYAML(network, path[1:])
	}
	return reflectGetYAML(main, path)
}

func formatKeyString(key []string) string {
	return strings.Join(key, "->")
}

func UpdateConfigFromEnv(cfg, networkData any, prefix string) error {
	cfgVal := reflect.ValueOf(cfg)
	networkVal := reflect.ValueOf(networkData)
	for key, value := range parseEnv(prefix) {
		field, ok := reflectGetFromMainOrNetwork(cfgVal, networkVal, key)
		if !ok {
			return fmt.Errorf("%s not found", formatKeyString(key))
		}
		if strings.HasPrefix(value, randomParseFilePrefix) {
			filepath := strings.TrimPrefix(value, randomParseFilePrefix)
			fileData, err := os.ReadFile(filepath)
			if err != nil {
				return fmt.Errorf("failed to read file %s for %s: %w", filepath, formatKeyString(key), err)
			}
			value = strings.TrimSpace(string(fileData))
		}
		var parsedVal any
		var err error
		switch field.valKind {
		case reflect.String:
			parsedVal = value
		case reflect.Bool:
			parsedVal, err = strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("invalid value for %s: %w", formatKeyString(key), err)
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			parsedVal, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid value for %s: %w", formatKeyString(key), err)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			parsedVal, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid value for %s: %w", formatKeyString(key), err)
			}
		case reflect.Float32, reflect.Float64:
			parsedVal, err = strconv.ParseFloat(value, 64)
			if err != nil {
				return fmt.Errorf("invalid value for %s: %w", formatKeyString(key), err)
			}
		default:
			return fmt.Errorf("unsupported type %s in %s", field.valKind, formatKeyString(key))
		}
		if field.val.Kind() == reflect.Ptr {
			if field.val.IsNil() {
				field.val.Set(reflect.New(field.val.Type().Elem()))
			}
			field.val = field.val.Elem()
		}
		if field.val.Kind() == reflect.Map {
			key = key[:len(key)-len(field.remainingPath)]
			mapKeyStr := strings.Join(field.remainingPath, ".")
			key = append(key, mapKeyStr)
			if field.val.Type().Key().Kind() != reflect.String {
				return fmt.Errorf("unsupported map key type %s in %s", field.val.Type().Key().Kind(), formatKeyString(key))
			}
			field.val.SetMapIndex(reflect.ValueOf(mapKeyStr), reflect.ValueOf(parsedVal))
		} else {
			field.val.Set(reflect.ValueOf(parsedVal))
		}
	}
	return nil
}
