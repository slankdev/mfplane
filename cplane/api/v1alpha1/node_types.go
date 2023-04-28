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
	Name        string      `json:"name"`
	Netns       string      `json:"netns,omitempty"`
	Device      string      `json:"device"`
	EncapSource string      `json:"encapSource"`
	Fib6        []Fib6Entry `json:"fib6,omitempty"`
	Fib4        []Fib4Entry `json:"fib4,omitempty"`
}

type Fib6Entry struct {
	Prefix          string     `json:"prefix"`
	ActionEndMfnNat *EndMfnNat `json:"endMfnNat,omitempty"`
}

type Fib4Entry struct {
	Prefix        string   `json:"prefix"`
	ActionHEncaps *HEncaps `json:"hencaps,omitempty"`
}

type EndMfnNat struct {
	Vip                string   `json:"vip"`
	NatPortHashBitMaxk uint16   `json:"natPortHashBit"`
	UsidBlockLength    int      `json:"uSidBlockLength"`
	UsidFunctionLength int      `json:"uSidFunctionLength"`
	Sources            []string `json:"source"`
}

type HEncaps struct {
	Mode string   `json:"mode"`
	Segs []string `json:"segs"`
}

// NodeStatus defines the observed state of Node
type NodeStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
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
