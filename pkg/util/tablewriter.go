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
	"io"

	"github.com/olekukonko/tablewriter"
)

// EXAMPLE
// 01   table := util.NewTableWriter(os.Stdout)
// 02   table.SetHeader([]string{"A", "B", "C"})
// 03   table.Append([]string{"a1", "b1", "c1"})
// 04   table.Append([]string{"a2", "b2", "c2"})
// 05   table.Append([]string{"a3", "b3", "c3"})
// 06   table.Render()
func NewTableWriter(writer io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
	return table
}
