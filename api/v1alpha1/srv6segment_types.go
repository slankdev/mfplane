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

// Srv6SegmentSpec defines the desired state of Srv6Segment
type Srv6SegmentSpec struct {
	NodeName  string       `json:"nodeName,omitempty"`
	FuncName  string       `json:"funcName,omitempty"`
	Locator   string       `json:"locator"`
	Sid       string       `json:"sid"`
	EndMfnNat *EndMfnNat   `json:"endMfnNat,omitempty"`
	EndMflNat *EndMflNat   `json:"endMflNat,omitempty"`
	Owner     SegmentOwner `json:"owner"`
}

// Srv6SegmentStatus defines the observed state of Srv6Segment
type Srv6SegmentStatus struct {
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Srv6Segment is the Schema for the srv6segments API
type Srv6Segment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   Srv6SegmentSpec   `json:"spec,omitempty"`
	Status Srv6SegmentStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// Srv6SegmentList contains a list of Srv6Segment
type Srv6SegmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Srv6Segment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Srv6Segment{}, &Srv6SegmentList{})
}
