package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/pkg/errors"
)

type CodeGeneratorTarget struct {
	Name                string
	RenderName          string
	RenderKeyStructName string
	RenderValStructName string
	RawKeyStructName    string
	RawValStructName    string
	MapType             string
	PerCpuMap           bool
}

func parseEbpfMap(cg *ast.CommentGroup) (*CodeGeneratorTarget, error) {
	t := CodeGeneratorTarget{}

	// Parse CommentGroup
	//  ebpf:map:render
	//  ebpf:map:render:key
	//  ebpf:map:render:val
	//  ebpf:map:raw:key
	//  ebpf:map:raw:val
	//  ebpf:map:type
	for _, l := range cg.List {
		if regexp.MustCompile(
			`// *\+ebpf:map:name=[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(l.Text) {
			t.Name = strings.Split(l.Text, "=")[1]
		}
		if regexp.MustCompile(
			`// *\+ebpf:map:render=[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(l.Text) {
			t.RenderName = strings.Split(l.Text, "=")[1]
		}
		if regexp.MustCompile(
			`// *\+ebpf:map:render:key=[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(l.Text) {
			t.RenderKeyStructName = strings.Split(l.Text, "=")[1]
		}
		if regexp.MustCompile(
			`// *\+ebpf:map:render:val=[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(l.Text) {
			t.RenderValStructName = strings.Split(l.Text, "=")[1]
		}
		if regexp.MustCompile(
			`// *\+ebpf:map:raw:key=[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(l.Text) {
			t.RawKeyStructName = strings.Split(l.Text, "=")[1]
		}
		if regexp.MustCompile(
			`// *\+ebpf:map:raw:val=[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(l.Text) {
			t.RawValStructName = strings.Split(l.Text, "=")[1]
		}
		if regexp.MustCompile(
			`// *\+ebpf:map:type=[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(l.Text) {
			t.MapType = strings.Split(l.Text, "=")[1]
		}
		t.PerCpuMap = strings.Contains(t.MapType, "PERCPU")
	}

	// Return nil if some property is zero-value
	if t.RenderName == "" ||
		t.RenderKeyStructName == "" ||
		t.RenderValStructName == "" ||
		t.RawKeyStructName == "" ||
		t.RawValStructName == "" ||
		t.Name == "" ||
		t.MapType == "" {
		return nil, nil
	}
	return &t, nil
}

func f() error {
	files, err := os.ReadDir(".")
	if err != nil {
		return err
	}

	// Parse Generator seed info
	targets := []*CodeGeneratorTarget{}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".go") ||
			file.Name() == "zz_generated.go" {
			continue
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file.Name(), nil, parser.ParseComments)
		if err != nil {
			return errors.Wrap(err, "ERROR")
		}

		for _, cg := range f.Comments {
			target, err := parseEbpfMap(cg)
			if err != nil {
				return err
			}
			if target != nil {
				targets = append(targets, target)
			}
		}
	}

	// Sort targets by name
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Name < targets[j].Name
	})

	// Generate Code
	var buf bytes.Buffer
	fmt.Fprintf(&buf, codeHeader)
	tmpl1, err := template.New("").Parse(codeTemplate)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := tmpl1.Execute(&buf, target); err != nil {
			return err
		}
	}

	// Sort targets
	sort.Slice(targets, func(i, j int) bool {
		if len(targets[i].Name) != len(targets[j].Name) {
			return len(targets[i].Name) > len(targets[j].Name)
		} else {
			return targets[i].Name < targets[j].Name
		}
	})

	// Generate Code (2)
	if err := gen2(&buf, targets); err != nil {
		return err
	}

	// Write back to file
	if err := os.WriteFile("zz_generated.go", buf.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

const codeHeader = `// Code generated by mfplane/pkg/ebpf/gen, DO NOT EDIT.

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
	"github.com/pkg/errors"

	"github.com/slankdev/mfplane/pkg/util"
)
`

const codeTemplate = `
var (
	_ MapRender = &{{.RenderName}}{}
)

func (r *{{.RenderName}}) WriteImpl(mapfile string) error {
	for _, entry := range r.Items {
		key, err := entry.Key.ToRaw()
		if err != nil {
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.key.ToRaw")
		}
		val, err := entry.Val.ToRaw()
		if err != nil {
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.val.ToRaw")
		}

		// install to eBPF map
{{- if .PerCpuMap }}
		if err := BatchPinnedMapOperation(
			mapfile,
			func(m *ebpf.Map) error {
				return UpdatePerCPUArrayAll(m, key, val, ebpf.UpdateAny)
			}); err != nil {
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.percpumap")
		}
{{ else }}
		m, err := ebpf.LoadPinnedMap(mapfile, nil)
		if err != nil {
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.loadPinnedMap")
		}
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.update")
		}
{{ end }}
	}
	return nil
}

func (r *{{.RenderName}}) ReadImpl(mapfile string) error {
	m, err := ebpf.LoadPinnedMap(mapfile, nil)
	if err != nil {
		return errors.Wrap(err, "{{.RenderName}}.WriteImpl.loadPinnedMap")
	}

	// Parse
	iterate := m.Iterate()
	entries := []{{.RenderName}}Item{}
	key := {{.RawKeyStructName}}{}
{{- if .PerCpuMap }}
	percpuval := []{{.RawValStructName}}{}
	for iterate.Next(&key, &percpuval) {
		val := {{.RawValStructName}}{}
		val.Summarize(percpuval)
{{ else }}
	val := {{.RawValStructName}}{}
	for iterate.Next(&key, &val) {
{{ end }}
		kr, err := key.ToRender()
		if err != nil {
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.key.ToRender")
		}
		vr, err := val.ToRender()
		if err != nil {
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.val.ToRender")
		}
		k, ok1 := kr.(*{{.RenderKeyStructName}})
		v, ok2 := vr.(*{{.RenderValStructName}})
		if !ok1 || !ok2 {
			err := fmt.Errorf("cast error")
			return errors.Wrap(err, "{{.RenderName}}.WriteImpl.val.ToRender")
		}
		entries = append(entries, {{.RenderName}}Item{Key: *k, Val: *v})
	}

	r.Items = entries
	return nil
}

func NewCommandMapSet_{{.Name}}() *cobra.Command {
	var clioptFile string
	var clioptNamePrefix string
	cmd := &cobra.Command{
		Use: "{{.Name}}",
		RunE: func(cmd *cobra.Command, args []string) error {
			// name must be specified, then error
			// without that feature, it might broke the important data
			if clioptNamePrefix == "" {
				return fmt.Errorf("name must be specified")
			}

			// Read input file
			fileContent, err := os.ReadFile(clioptFile)
			if err != nil {
				return err
			}

			// Parse input file
			entries := {{.RenderName}}{}
			if err := util.YamlUnmarshalViaJson(fileContent, &entries); err != nil {
				return err
			}

			// Set maps
			mapfile := "/sys/fs/bpf/xdp/globals/" + clioptNamePrefix + "_{{.Name}}"
			if err := Write(mapfile, &entries); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptFile, "file", "f", "", "")
	cmd.Flags().StringVarP(&clioptNamePrefix, "name", "n", "l1", "")
	return cmd
}

func NewCommandMapInspect_{{.Name}}() *cobra.Command {
	var clioptNamePrefix string
	var clioptPinDir string
	cmd := &cobra.Command{
		Use: "{{.Name}}",
		RunE: func(cmd *cobra.Command, args []string) error {
			// name must be specified, then error
			// without that feature, it might broke the important data
			if clioptNamePrefix == "" {
				return fmt.Errorf("name must be specified")
			}

			mapfile := "/sys/fs/bpf/xdp/globals/" + clioptNamePrefix + "_{{.Name}}"
			entries := {{.RenderName}}{}
			if err := Read(mapfile, &entries); err != nil {
				return err
			}

			// Print
			util.Jprintln(entries)
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptNamePrefix, "name", "n", "l1", "")
	cmd.Flags().StringVarP(&clioptPinDir, "pin", "p",
		"/sys/fs/bpf/xdp/globals", "pinned map root dir")
	return cmd
}

func NewCommandMapFlush_{{.Name}}() *cobra.Command {
	var clioptNamePrefix string
	var clioptPinDir string
	cmd := &cobra.Command{
		Use: "{{.Name}}",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Flush(filepath.Join(clioptPinDir, clioptNamePrefix+"_{{.Name}}"))
		},
	}
	cmd.Flags().StringVarP(&clioptNamePrefix, "name", "n", "l1", "")
	cmd.Flags().StringVarP(&clioptPinDir, "pin", "p",
		"/sys/fs/bpf/xdp/globals", "pinned map root dir")
	return cmd
}

func NewCommandMapSize_{{.Name}}() *cobra.Command {
	var clioptNamePrefix string
	var clioptPinDir string
	cmd := &cobra.Command{
		Use: "{{.Name}}",
		RunE: func(cmd *cobra.Command, args []string) error {
			// name must be specified, then error
			// without that feature, it might broke the important data
			if clioptNamePrefix == "" {
				return fmt.Errorf("name must be specified")
			}
			mapfile := "/sys/fs/bpf/xdp/globals/" + clioptNamePrefix + "_{{.Name}}"
			size, err := Size(mapfile)
			if err != nil {
				return err
			}
			fmt.Println(size)
			return nil
		},
	}
	cmd.Flags().StringVarP(&clioptNamePrefix, "name", "n", "l1", "")
	cmd.Flags().StringVarP(&clioptPinDir, "pin", "p",
		"/sys/fs/bpf/xdp/globals", "pinned map root dir")
	return cmd
}

func init() {
	Drivers = append(Drivers, Driver{
		SetCommand:     NewCommandMapSet_{{.Name}}(),
		InspectCommand: NewCommandMapInspect_{{.Name}}(),
		FlushCommand:   NewCommandMapFlush_{{.Name}}(),
		SizeCommand:    NewCommandMapSize_{{.Name}}(),
	})
}
`

func main() {
	if err := f(); err != nil {
		log.Printf("%+v\n", err)
		os.Exit(1)
	}
}

func gen2(buf *bytes.Buffer, targets []*CodeGeneratorTarget) error {
	tmpl, err := template.New("").Parse(codeTemplate2)
	if err != nil {
		return err
	}
	if err := tmpl.Execute(buf, targets); err != nil {
		return err
	}
	return nil
}

const codeTemplate2 = `
type MapGenericItem struct {
	Mapfile string ` + "`" + `json:"mapfile"` + "`" + `
	Unknown bool   ` + "`" + `json:"unknown,omitempty"` + "`" + `
{{ range . }}
	{{ .RenderName }} *{{ .RenderName }} ` + "`" + `json:"{{ .Name }},omitempty"` + "`" + `
{{ end }}
}

func (i MapGenericItem) IsValid() error {
	setTypes := []string{}
{{ range . }}
	if i.{{.RenderName}} != nil {
		setTypes = append(setTypes, "{{.Name}}")
	}
{{ end }}
	if len(setTypes) != 1 {
		return fmt.Errorf("multiple-set or no-set (%v)", setTypes)
	}
	return nil
}

type MapGeneric struct {
	Items []MapGenericItem ` + "`" + `json:"items"` + "`" + `
}

func ReadAll(root string) (*MapGeneric, error) {
	files, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	m := MapGeneric{}
	for _, file := range files {
		if !file.IsDir() {
			mapfile := filepath.Join(root, file.Name())
			item := MapGenericItem{Mapfile: mapfile}
			switch {
{{ range . }}
			case strings.HasSuffix(file.Name(), "{{.Name}}"):
				{{.Name}} := {{.RenderName}}{}
				if err := Read(mapfile, &{{.Name}}); err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("read:%s", mapfile))
				}
				item.{{.RenderName}} = &{{.Name}}
{{ end }}
			default:
				item.Unknown = true
			}
			m.Items = append(m.Items, item)
		}
	}
	return &m, nil
}

func WriteAll(all *MapGeneric) error {
	for _, item := range all.Items {
		if err := item.IsValid(); err != nil {
			return err
		}

		switch {
{{ range . }}
		case strings.HasSuffix(item.Mapfile, "{{.Name}}"):
			if item.{{.RenderName}} == nil {
				return fmt.Errorf("type is {{.Name}} but property is not set")
			}
			if err := Write(item.Mapfile, item.{{.RenderName}}); err != nil {
				return errors.Wrap(err, fmt.Sprintf("write:%s", item.Mapfile))
			}
{{ end }}
		}
	}
	return nil
}

type ProgRunMapContext struct {
{{- range . }}
	{{ .RenderName }} {{ .RenderName }}
{{- end }}
}

func FlushProgRunMapContext(progName string) error {
	name := progName
	root := "/sys/fs/bpf/xdp/globals/"
	for _, mapName := range []string{
{{- range . }}
		"{{- .Name -}}",
{{- end }}
	} {
		if err := Flush(root + name + "_" + mapName); err != nil {
			return err
		}
	}
	return nil
}

func SetProgRunMapContext(mc *ProgRunMapContext, progName string) error {
	name := progName
	root := "/sys/fs/bpf/xdp/globals/"

{{- range . }}
	if len(mc.{{ .RenderName }}.Items) > 0 {
		if err := Write(
			root+name+"_{{ .Name }}",
			&mc.{{ .RenderName }}); err != nil {
			return errors.Wrap(err, "{{ .Name }}")
		}
	}
{{- end }}

	return nil
}

func DumpProgRunMapContext(progName string) (*ProgRunMapContext, error) {
	name := progName
	root := "/sys/fs/bpf/xdp/globals/"

{{- range . }}
	{{ .Name }} := {{ .RenderName }}{}
	if err := Read(
		root+name+"_{{ .Name }}",
		&{{ .Name }}); err != nil {
		return nil, errors.Wrap(err, "{{ .Name }}")
	}
{{- end }}

	return &ProgRunMapContext{
{{- range . }}
		{{ .RenderName }}: {{ .Name }},
{{- end }}
	}, nil
}
`
