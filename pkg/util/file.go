/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Keio University.
Copyright 2022 Wide Project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

func FileUnmarshalAsYaml(in string, v interface{}) error {
	yamlFile, err := ioutil.ReadFile(in)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, v)
	if err != nil {
		return err
	}
	return nil
}

func WriteFile(filepath string, content []byte) error {
	words := strings.Split(filepath, "/")
	wordsDir := words[:len(words)-1]
	dir := ""
	for _, word := range wordsDir {
		dir = fmt.Sprintf("%s/%s", dir, word)
	}
	if err := os.MkdirAll(dir, 0777); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath, content, os.ModePerm); err != nil {
		return err
	}
	return nil
}
