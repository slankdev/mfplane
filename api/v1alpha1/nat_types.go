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

// NatSpec defines the desired state of Nat
type NatSpec struct {
	Vip                string             `json:"vip"`
	Sources            []string           `json:"sources"`
	NatPortHashBit     uint16             `json:"natPortHashBit"`
	NatMapping         string             `json:"natMapping"`
	NatFiltering       string             `json:"natFiltering"`
	UsidBlockLength    int                `json:"uSidBlockLength"`
	UsidFunctionLength int                `json:"uSidFunctionLength"`
	LoadBalancer       MfpNodeSpecifySpec `json:"loadBalancer"`
	NetworkFunction    MfpNodeSpecifySpec `json:"networkFunction"`
}

type MfpNodeSpecifySpec struct {
	Replicas int                     `json:"replicas"`
	Selector *MfpNodeSpecifySelector `json:"selector,omitempty"`
}

type MfpNodeSpecifySelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// NatStatus defines the observed state of Nat
type NatStatus struct {
	Revisions []EndMflNatRevision `json:"revisions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name=LB,type=string,priority=1,JSONPath=.spec.loadBalancer.replicas
//+kubebuilder:printcolumn:name=NF,type=string,priority=1,JSONPath=.spec.networkFunction.replicas
//+kubebuilder:printcolumn:name=AGE,type=date,JSONPath=.metadata.creationTimestamp

// Nat is the Schema for the nats API
type Nat struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NatSpec   `json:"spec,omitempty"`
	Status NatStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NatList contains a list of Nat
type NatList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Nat `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Nat{}, &NatList{})
}
