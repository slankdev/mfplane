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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	mfplanev1alpha1 "github.com/slankdev/mfplane/api/v1alpha1"
)

// NatReconciler reconciles a Nat object
type NatReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=nats,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=nats/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=nats/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Nat object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.4/pkg/reconcile
func (r *NatReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	nat := mfplanev1alpha1.Nat{}
	if err := r.Get(ctx, req.NamespacedName, &nat); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info("RECONCILE_L_NODE")

	// TODO(slankdev): support scale-in. currently it doesn't support such case.
	// Need to consider using sub-resource/scale.

	// Schedule N-node Segments
	nbCreateNf := nat.Spec.NetworkFunction.Replicas
	nodeList1 := mfplanev1alpha1.NodeList{}
	if err := r.List(ctx, &nodeList1); err != nil {
		return ctrl.Result{}, err
	}
	for _, node := range nodeList1.Items {
		for _, fn := range node.Status.Functions {
			for _, seg := range fn.Segments {
				if seg.Owner.Kind == "Nat" && seg.Owner.Name == nat.Name &&
					seg.EndMfnNat != nil {
					nbCreateNf--
				}
			}
		}
	}
	nfSegments := []mfplanev1alpha1.Segment{}
	for i := 0; i < nbCreateNf; i++ {
		newSeg := mfplanev1alpha1.Segment{
			Locator: "default",
			Owner: mfplanev1alpha1.SegmentOwner{
				Kind: nat.Kind,
				Name: nat.Name,
			},
			EndMfnNat: &mfplanev1alpha1.EndMfnNat{
				Vip:                nat.Spec.Vip,
				NatPortHashBit:     nat.Spec.NatPortHashBit,
				UsidBlockLength:    nat.Spec.UsidBlockLength,
				UsidFunctionLength: nat.Spec.UsidFunctionLength,
				Sources:            nat.Spec.Sources,
			},
		}

		// XXX(slankdev)
		if i == 0 {
			newSeg.NodeName = "node-sample1"
			newSeg.FuncName = "N1"
			newSeg.Sid = "fc00:3101::/32"
		}
		if i == 1 {
			newSeg.NodeName = "node-sample1"
			newSeg.FuncName = "N2"
			newSeg.Sid = "fc00:3201::/32"
		}

		nfSegments = append(nfSegments, newSeg)
	}

	// Schedule L-node Segments
	nbCreateLb := nat.Spec.LoadBalancer.Replicas
	nodeList0 := mfplanev1alpha1.NodeList{}
	if err := r.List(ctx, &nodeList0); err != nil {
		return ctrl.Result{}, err
	}
	for _, node := range nodeList0.Items {
		for _, fn := range node.Status.Functions {
			for _, seg := range fn.Segments {
				if seg.Owner.Kind == "Nat" && seg.Owner.Name == nat.Name &&
					seg.EndMflNat != nil {
					nbCreateLb--
				}
			}
		}
	}
	lbSegments := []mfplanev1alpha1.Segment{}
	for i := 0; i < nbCreateLb; i++ {
		newSeg := mfplanev1alpha1.Segment{
			Locator: "anycast",
			Owner: mfplanev1alpha1.SegmentOwner{
				Kind: nat.Kind,
				Name: nat.Name,
			},
			EndMflNat: &mfplanev1alpha1.EndMflNat{
				Vip:                nat.Spec.Vip,
				NatPortHashBit:     nat.Spec.NatPortHashBit,
				UsidBlockLength:    nat.Spec.UsidBlockLength,
				UsidFunctionLength: nat.Spec.UsidFunctionLength,
			},
		}

		// XXX(slankdev)
		if i == 0 {
			newSeg.NodeName = "node-sample1"
			newSeg.FuncName = "L1"
			newSeg.Sid = "fc00:ff01::/32"
			newSeg.EndMflNat.USidFunctionRevisions = []mfplanev1alpha1.EndMflNatRevision{
				{
					Backends: []string{
						"fc00:3101::/32",
						"fc00:3201::/32",
					},
				},
			}
		}

		lbSegments = append(lbSegments, newSeg)
	}

	// Reconcile for Node resource
	nodeList := mfplanev1alpha1.NodeList{}
	if err := r.List(ctx, &nodeList); err != nil {
		return ctrl.Result{}, err
	}
	for _, node := range nodeList.Items {
		// Resource init
		if node.Status.Functions == nil {
			node.Status.Functions = []mfplanev1alpha1.FunctionStatus{}
		}
		for _, fn := range node.Spec.Functions {
			found := false
			for _, statusFn := range node.Status.Functions {
				if statusFn.Name == fn.Name {
					found = true
					break
				}
			}
			if !found {
				node.Status.Functions = append(node.Status.Functions,
					mfplanev1alpha1.FunctionStatus{
						Name:     fn.Name,
						Segments: []mfplanev1alpha1.Segment{},
					})
			}
		}

		// Fill allocated segment
		updated := false
		for fnIdx, fn := range node.Status.Functions {
			for _, seg := range lbSegments {
				if seg.NodeName == node.Name && seg.FuncName == fn.Name {
					fn.Segments = append(fn.Segments, seg)
					node.Status.Functions[fnIdx].Segments = fn.Segments
					updated = true
				}
			}
			for _, seg := range nfSegments {
				if seg.NodeName == node.Name && seg.FuncName == fn.Name {
					fn.Segments = append(fn.Segments, seg)
					node.Status.Functions[fnIdx].Segments = fn.Segments
					updated = true
				}
			}
		}

		// Update node resource
		if updated {
			if err := r.Status().Update(ctx, &node); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// Finish
	log.Info("RECONCILE_DONE")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NatReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mfplanev1alpha1.Nat{}).
		Complete(r)
}

func (r *NatReconciler) ScheduleFilter() error {
	return nil
}
