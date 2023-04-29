/*
Copyright 2023.

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

package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NodeSpec defines the desired state of Node
type NodeSpec struct {
	Hostname  string         `json:"hostname"`
	Functions []FunctionSpec `json:"functions,omitempty"`
}

type FunctionSpec struct {
	Name               string                 `json:"name"`
	Netns              string                 `json:"netns,omitempty"`
	Device             string                 `json:"device"`
	Type               string                 `json:"type"`
	Mode               string                 `json:"mode"`
	ConfigFile         string                 `json:"configFile,omitempty"`
	Labels             map[string]string      `json:"labels,omitempty"`
	SegmentRoutingSrv6 SegmentRoutingSrv6Spec `json:"segmentRoutingSrv6,omitempty"`
}

type SegmentRoutingSrv6Spec struct {
	EncapSource string        `json:"encapSource"`
	Locators    []Srv6Locator `json:"locators"`
}

type Srv6Locator struct {
	Name    string `json:"name"`
	Prefix  string `json:"prefix"`
	Block   string `json:"block"`
	Anycast bool   `json:"anycast,omitempty"`
}

// NodeStatus defines the observed state of Node
type NodeStatus struct {
	Functions []FunctionStatus `json:"functions,omitempty"`
}

type FunctionStatus struct {
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels,omitempty"`
	Segments []Segment         `json:"segments"`
}

type Segment struct {
	NodeName  string       `json:"nodeName"`
	FuncName  string       `json:"funcName"`
	Locator   string       `json:"locator"`
	Sid       string       `json:"sid"`
	EndMfnNat *EndMfnNat   `json:"endMfnNat,omitempty"`
	EndMflNat *EndMflNat   `json:"endMflNat,omitempty"`
	Owner     SegmentOwner `json:"owner"`
}

type SegmentOwner struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type EndMfnNat struct {
	Vip                string   `json:"vip"`
	NatPortHashBitMaxk uint16   `json:"natPortHashBit"`
	UsidBlockLength    int      `json:"uSidBlockLength"`
	UsidFunctionLength int      `json:"uSidFunctionLength"`
	Sources            []string `json:"sources"`
}

type EndMflNat struct {
	Vip                   string              `json:"vip"`
	NatPortHashBitMaxk    uint16              `json:"natPortHashBit"`
	UsidBlockLength       int                 `json:"uSidBlockLength"`
	UsidFunctionLength    int                 `json:"uSidFunctionLength"`
	USidFunctionRevisions []EndMflNatRevision `json:"uSidFunctionRevisions"`
}

type EndMflNatRevision struct {
	Backends []string `json:"backends"`
}

type HEncaps struct {
	Mode string   `json:"mode"`
	Segs []string `json:"segs"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Node is the Schema for the nodes API
type Node struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeSpec   `json:"spec,omitempty"`
	Status NodeStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NodeList contains a list of Node
type NodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Node `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Node{}, &NodeList{})
}

func (n Node) GetFunctionSpec(name string, spec *FunctionSpec) error {
	for _, fn := range n.Spec.Functions {
		if fn.Name == name {
			*spec = fn
			return nil
		}
	}
	return fmt.Errorf("not found")
}

func (n Node) GetFunctionStatus(name string, spec *FunctionStatus) error {
	for _, fn := range n.Status.Functions {
		if fn.Name == name {
			*spec = fn
			return nil
		}
	}
	return fmt.Errorf("not found")
}
