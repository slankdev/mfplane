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

package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	mfplanev1alpha1 "github.com/slankdev/mfplane/api/v1alpha1"
	"github.com/slankdev/mfplane/pkg/util"
)

// Srv6SegmentReconciler reconciles a Srv6Segment object
type Srv6SegmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type ScheduleCandidate struct {
	NodeName string
	FuncName string
	Segments []mfplanev1alpha1.Srv6Segment
}

//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=srv6segments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=srv6segments/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=srv6segments/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Srv6Segment object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.4/pkg/reconcile
func (r *Srv6SegmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	seg := mfplanev1alpha1.Srv6Segment{}
	if err := r.Get(ctx, req.NamespacedName, &seg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if seg.Spec.Sid != "" {
		log.Info("ALREADY_ALLOCATED_SKIP")
		return ctrl.Result{}, nil
	}

	specUpdated := false
	statusUpdated := false
	log.Info("RECONCILE_START")

	if seg.Status.NodeName == "" || seg.Status.FuncName == "" {
		log.Info("SCHEDULING")
		funcType := "unknown"
		switch {
		case seg.Spec.EndMflNat != nil:
			funcType = "clb"
		case seg.Spec.EndMfnNat != nil:
			funcType = "nat"
		default:
			return ctrl.Result{}, fmt.Errorf("no sid activated")
		}

		// FILTERS
		c0, err := GetScheduleCandidates(ctx, r.Client, funcType)
		if err != nil {
			return ctrl.Result{}, err
		}
		c1, err := FilterAntiAffinity(ctx, r.Client, seg, c0)
		if err != nil {
			return ctrl.Result{}, err
		}

		// TODO(slankdev)
		// sort.Slice(c0, func(i, j int) bool {
		// 	return len(c0[i].Segments) < len(c0[j].Segments)
		// })

		// ELECT
		if len(c1) > 0 {
			c := c1[0]
			seg.Status.NodeName = c.NodeName
			seg.Status.FuncName = c.FuncName
			statusUpdated = true
		}
	}

	// Write back changes
	if statusUpdated {
		if err := r.Status().Update(ctx, &seg); err != nil {
			return ctrl.Result{}, err
		}
	}
	if specUpdated {
		if err := r.Update(ctx, &seg); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Srv6SegmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mfplanev1alpha1.Srv6Segment{}).
		Complete(r)
}

func GetScheduleCandidates(ctx context.Context, cli client.Client,
	funcType string) ([]ScheduleCandidate, error) {
	nodeList := mfplanev1alpha1.NodeList{}
	if err := cli.List(ctx, &nodeList); err != nil {
		return nil, err
	}
	segList := mfplanev1alpha1.Srv6SegmentList{}
	if err := cli.List(ctx, &segList); err != nil {
		return nil, err
	}

	candidates := []ScheduleCandidate{}
	for _, node := range nodeList.Items {
		for _, fn := range node.Spec.Functions {
			if fn.Type == funcType {
				segs := []mfplanev1alpha1.Srv6Segment{}
				for _, seg := range segList.Items {
					if seg.Status.NodeName == node.Name &&
						seg.Status.FuncName == fn.Name {
						segs = append(segs, seg)
					}
				}
				candidates = append(candidates, ScheduleCandidate{
					NodeName: node.Name,
					FuncName: fn.Name,
					Segments: segs,
				})
			}
		}
	}
	return candidates, nil
}

func FilterAntiAffinity(ctx context.Context, cli client.Client,
	seg mfplanev1alpha1.Srv6Segment,
	in []ScheduleCandidate) ([]ScheduleCandidate, error) {
	out := []ScheduleCandidate{}
	for _, item := range in {
		segList := mfplanev1alpha1.Srv6SegmentList{}
		if err := mfplanev1alpha1.ListSegmentsNodeFunc(ctx, cli,
			item.NodeName, item.FuncName, &segList); err != nil {
			return nil, err
		}
		drop := false
		for _, checkSeg := range segList.Items {
			if util.VerifyMatchLabels(checkSeg.Labels, seg.Spec.Selector.MatchLabels) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, item)
		}
	}
	return out, nil
}
