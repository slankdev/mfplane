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
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Srv6SegmentSpec defines the desired state of Srv6Segment
type Srv6SegmentSpec struct {
	NodeName  string                 `json:"nodeName,omitempty"`
	FuncName  string                 `json:"funcName,omitempty"`
	Locator   string                 `json:"locator"`
	Sid       string                 `json:"sid,omitempty"`
	EndMfnNat *EndMfnNat             `json:"endMfnNat,omitempty"`
	EndMflNat *EndMflNat             `json:"endMflNat,omitempty"`
	Selector  MfpNodeSpecifySelector `json:"selector,omitempty"`
}

type EndMfnNat struct {
	Vip                string   `json:"vip"`
	NatPortHashBit     uint16   `json:"natPortHashBit"`
	UsidBlockLength    int      `json:"uSidBlockLength"`
	UsidFunctionLength int      `json:"uSidFunctionLength"`
	Sources            []string `json:"sources"`
}

type EndMflNat struct {
	Vip                   string              `json:"vip"`
	NatPortHashBit        uint16              `json:"natPortHashBit"`
	UsidBlockLength       int                 `json:"uSidBlockLength"`
	UsidFunctionLength    int                 `json:"uSidFunctionLength"`
	USidFunctionRevisions []EndMflNatRevision `json:"uSidFunctionRevisions,omitempty"`
}

type EndMflNatRevision struct {
	Backends []string `json:"backends"`
}

// Srv6SegmentStatus defines the observed state of Srv6Segment
type Srv6SegmentStatus struct {
	NodeName string `json:"nodeName,omitempty"`
	FuncName string `json:"funcName,omitempty"`
	// State indicates the current Segment state. The behavior of reconcile
	// changes accordingly.
	State Srv6SegmentState `json:"state"`
}

//+kubebuilder:validation:Enum=Terminating;Active;Configuring;Pending
type Srv6SegmentState string

const (
	Srv6SegmentStateTerminating = Srv6SegmentState("Terminating")
	Srv6SegmentStateActive      = Srv6SegmentState("Active")
	Srv6SegmentStateConfiguring = Srv6SegmentState("Configuring")
	Srv6SegmentStatePending     = Srv6SegmentState("Pending")
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName=seg
//+kubebuilder:printcolumn:name=SID,type=string,JSONPath=.spec.sid
//+kubebuilder:printcolumn:name=NODE,type=string,priority=1,JSONPath=.status.nodeName
//+kubebuilder:printcolumn:name=FUNC,type=string,priority=1,JSONPath=.status.funcName
//+kubebuilder:printcolumn:name=AGE,type=date,JSONPath=.metadata.creationTimestamp

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

func ListSegmentsNodeFunc(ctx context.Context, cli client.Client,
	nodeName, funcName string, list *Srv6SegmentList) error {
	segList := Srv6SegmentList{}
	if err := cli.List(ctx, &segList); err != nil {
		return err
	}
	for _, seg := range segList.Items {
		if seg.Status.NodeName == nodeName &&
			seg.Status.FuncName == funcName {
			list.Items = append(list.Items, seg)
		}
	}
	return nil
}
