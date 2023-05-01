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
	"strconv"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/k0kubun/pp"
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
func (r *Srv6SegmentReconciler) Reconcile(ctx context.Context,
	req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	res := util.NewReconcileStatus()

	seg := mfplanev1alpha1.Srv6Segment{}
	if err := r.Get(ctx, req.NamespacedName, &seg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if seg.Status.NodeName == "" || seg.Status.FuncName == "" ||
		seg.Status.Sid == "" {
		seg.Status.State = mfplanev1alpha1.Srv6SegmentStatePending
		res.StatusUpdated = true
	}

	log.Info("START_RECONCILE", "state", seg.Status.State)
	switch seg.Status.State {
	case mfplanev1alpha1.Srv6SegmentStateActive:
		pp.Println("NOT IMPLEMENTED", seg.Status.State)
	case mfplanev1alpha1.Srv6SegmentStateTerminating:
		pp.Println("NOT IMPLEMENTED", seg.Status.State)
	case mfplanev1alpha1.Srv6SegmentStateConfiguring:
		if len(seg.ObjectMeta.Finalizers) > 0 {
			seg.Status.State = mfplanev1alpha1.Srv6SegmentStateActive
			res.StatusUpdated = true
		}
	case mfplanev1alpha1.Srv6SegmentStatePending:
		if err := r.reconcileNodeFuncSchedule(ctx, req, &seg, res); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		if err := r.reconcileSidAllocation(ctx, req, &seg, res); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		if seg.Status.NodeName != "" && seg.Status.FuncName != "" &&
			seg.Status.Sid != "" {
			pp.Println(seg.Spec, seg.Status)
			seg.Status.State = mfplanev1alpha1.Srv6SegmentStateConfiguring
			res.StatusUpdated = true
		}
	default:
		seg.Status.State = mfplanev1alpha1.Srv6SegmentStatePending
		res.StatusUpdated = true
	}
	log.Info("FINISH_RECONCILE", "state", seg.Status.State)

	r.reconcileCommonState(&seg, res)
	return res.ReconcileUpdate(ctx, r.Client, &seg)
}

func (r *Srv6SegmentReconciler) reconcileCommonState(
	seg *mfplanev1alpha1.Srv6Segment,
	res *util.ReconcileStatus) {
	updated := false
	seg.Labels, updated = util.MergeLabelsDiff(seg.Labels, map[string]string{
		"nodeName":     seg.Status.NodeName,
		"funcName":     seg.Status.FuncName,
		"sidAllocated": strconv.FormatBool(seg.Status.Sid != ""),
	})
	if updated {
		res.SpecUpdated = true
	}
}

func (r *Srv6SegmentReconciler) reconcileNodeFuncSchedule(ctx context.Context,
	req ctrl.Request, seg *mfplanev1alpha1.Srv6Segment,
	res *util.ReconcileStatus) error {
	log := log.FromContext(ctx)
	if seg.Status.NodeName == "" || seg.Status.FuncName == "" {
		log.Info("SCHEDULING")
		funcType := "unknown"
		switch {
		case seg.Spec.EndMflNat != nil:
			funcType = "clb"
		case seg.Spec.EndMfnNat != nil:
			funcType = "nat"
		default:
			return fmt.Errorf("no sid activated")
		}

		// FILTERS
		c0, err := GetScheduleCandidates(ctx, r.Client, funcType)
		if err != nil {
			return err
		}
		c1, err := FilterAntiAffinity(ctx, r.Client, seg, c0)
		if err != nil {
			return err
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
			res.StatusUpdated = true
		}
	}
	return nil
}

func (r *Srv6SegmentReconciler) reconcileSidAllocation(ctx context.Context,
	req ctrl.Request, seg *mfplanev1alpha1.Srv6Segment,
	res *util.ReconcileStatus) error {
	log := log.FromContext(ctx)

	// Skip for "not func scheduled" or "already sid allocated"
	if seg.Status.NodeName == "" || seg.Status.FuncName == "" ||
		seg.Status.Sid != "" {
		return nil
	}

	log.Info("SID_ALLOCATION")
	if seg.Spec.Locator == "anycast" {
		filter := seg.Spec.Selector.MatchLabels
		filter = util.MergeLabels(filter, map[string]string{
			"sidAllocated": strconv.FormatBool(true),
		})
		otherSegList := mfplanev1alpha1.Srv6SegmentList{}
		if err := r.List(ctx, &otherSegList, &client.ListOptions{
			Namespace:     seg.GetNamespace(),
			LabelSelector: labels.SelectorFromSet(filter),
		}); err != nil {
			return err
		}
		if len(otherSegList.Items) > 0 {
			log.Info("ANYCAST_SID", "value", seg.Status.Sid)
			seg.Status.Sid = otherSegList.Items[0].Status.Sid
			res.SpecUpdated = true
			return nil
		}
	}

	node := mfplanev1alpha1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: seg.Namespace,
		Name: seg.Status.NodeName}, &node); err != nil {
		return err
	}
	fnSpec := mfplanev1alpha1.FunctionSpec{}
	if err := node.GetFunctionSpec(seg.Status.FuncName, &fnSpec); err != nil {
		return err
	}
	loc := fnSpec.SegmentRoutingSrv6.GetLocator(seg.Spec.Locator)
	if loc == nil {
		return fmt.Errorf("locator '%s' not found", seg.Spec.Locator)
	}

	sids, err := util.GetSubnet(loc.Prefix, 32)
	if err != nil {
		return err
	}
	availableSids := []string{}
	segList := mfplanev1alpha1.Srv6SegmentList{}
	if err := r.List(ctx, &segList); err != nil {
		return err
	}
	for _, sid := range sids {
		exist := false
		for _, seg := range segList.Items {
			if seg.Status.Sid == sid {
				exist = true
				break
			}
		}
		if !exist {
			availableSids = append(availableSids, sid)
		}
	}

	if len(availableSids) == 0 {
		return fmt.Errorf("no available sid")
	}
	seg.Status.Sid = availableSids[0]
	res.StatusUpdated = true
	return nil
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
	seg *mfplanev1alpha1.Srv6Segment,
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
