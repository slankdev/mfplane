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
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	mfplanev1alpha1 "github.com/slankdev/mfplane/api/v1alpha1"
	"github.com/slankdev/mfplane/pkg/util"
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
func (r *NatReconciler) Reconcile(ctx context.Context,
	req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	res := util.NewReconcileStatus()

	// Fetch Resource
	nat := mfplanev1alpha1.Nat{}
	if err := r.Get(ctx, req.NamespacedName, &nat); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Do Reconcile
	log.Info("RECONCILE_MAIN_ROUTINE_START")
	if err := r.reconcileChildNf(ctx, req, &nat, res); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileChildLb(ctx, req, &nat, res); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("RECONCILE_MAIN_ROUTINE_FINISH")

	return res.ReconcileUpdate(ctx, r.Client, &nat)
}

func (r *NatReconciler) reconcileChildNf(ctx context.Context,
	req ctrl.Request, nat *mfplanev1alpha1.Nat, res *util.ReconcileStatus) error {
	log := log.FromContext(ctx)

	segList := mfplanev1alpha1.Srv6SegmentList{}
	if err := r.List(ctx, &segList, &client.ListOptions{
		Namespace: nat.GetNamespace(),
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"srv6Action":        "endMfnNat",
			"ownerResourceKind": nat.Kind,
			"ownerResourceName": nat.GetName(),
		}),
	}); err != nil {
		return err
	}

	diff := nat.Spec.NetworkFunction.Replicas - len(segList.Items)
	if diff != 0 {
		seg := mfplanev1alpha1.Srv6Segment{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: nat.GetName() + "-nnode-",
				Namespace:    nat.GetNamespace(),
			},
			Spec: mfplanev1alpha1.Srv6SegmentSpec{
				Locator: "default",
				Selector: mfplanev1alpha1.MfpNodeSpecifySelector{
					MatchLabels: map[string]string{
						"nat": nat.Name,
					},
				},
				EndMfnNat: &mfplanev1alpha1.EndMfnNat{
					Vip:                nat.Spec.Vip,
					NatPortHashBit:     nat.Spec.NatPortHashBit,
					UsidBlockLength:    nat.Spec.UsidBlockLength,
					UsidFunctionLength: nat.Spec.UsidFunctionLength,
					Sources:            nat.Spec.Sources,
				},
			},
		}
		for i := 0; i < diff; i++ {
			seg.SetName("")
			op, err := ctrl.CreateOrUpdate(ctx, r.Client, &seg, func() error {
				seg.SetLabels(map[string]string{
					"nat":               nat.Name,
					"ownerResourceKind": nat.Kind,
					"ownerResourceName": nat.GetName(),
					"srv6Action":        "endMfnNat",
				})
				return ctrl.SetControllerReference(nat, &seg, r.Scheme)
			})
			if err != nil {
				log.Error(err, "ERROR")
				return err
			}
			log.Info("CreateOrUpdate", "op", op)
		}
	}
	return nil
}

func (r *NatReconciler) reconcileChildLb(ctx context.Context,
	req ctrl.Request, nat *mfplanev1alpha1.Nat, res *util.ReconcileStatus) error {
	log := log.FromContext(ctx)

	// Resolve SID
	nfSegList := mfplanev1alpha1.Srv6SegmentList{}
	if err := r.List(ctx, &nfSegList, &client.ListOptions{
		Namespace: nat.GetNamespace(),
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"srv6Action":        "endMfnNat",
			"sidAllocated":      strconv.FormatBool(true),
			"ownerResourceKind": nat.Kind,
			"ownerResourceName": nat.GetName(),
		}),
	}); err != nil {
		return err
	}
	sidList := []string{}
	for _, item := range nfSegList.Items {
		sidList = append(sidList, item.Spec.Sid)
	}

	// Create Desired additional segments
	lbSegList := mfplanev1alpha1.Srv6SegmentList{}
	if err := r.List(ctx, &lbSegList, &client.ListOptions{
		Namespace: nat.GetNamespace(),
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"srv6Action":        "endMflNat",
			"ownerResourceKind": nat.Kind,
			"ownerResourceName": nat.GetName(),
		}),
	}); err != nil {
		return err
	}

	diff := nat.Spec.LoadBalancer.Replicas - len(lbSegList.Items)
	if diff != 0 {
		for i := 0; i < diff; i++ {
			seg := mfplanev1alpha1.Srv6Segment{
				ObjectMeta: metav1.ObjectMeta{
					Name:         "",
					GenerateName: nat.GetName() + "-lnode-",
					Namespace:    nat.GetNamespace(),
				},
			}
			seg.SetLabels(map[string]string{
				"nat":               nat.Name,
				"ownerResourceKind": nat.Kind,
				"ownerResourceName": nat.GetName(),
				"srv6Action":        "endMflNat",
			})
			seg.Spec = mfplanev1alpha1.Srv6SegmentSpec{
				Locator: "anycast",
				Selector: mfplanev1alpha1.MfpNodeSpecifySelector{
					MatchLabels: map[string]string{
						"nat": nat.Name,
					},
				},
				EndMflNat: &mfplanev1alpha1.EndMflNat{
					Vip:                nat.Spec.Vip,
					NatPortHashBit:     nat.Spec.NatPortHashBit,
					UsidBlockLength:    nat.Spec.UsidBlockLength,
					UsidFunctionLength: nat.Spec.UsidFunctionLength,
					USidFunctionRevisions: []mfplanev1alpha1.EndMflNatRevision{
						{
							Backends: sidList,
						},
					},
				},
			}
			if err := r.Create(ctx, &seg); err != nil {
				log.Error(err, "r.Create")
				return err
			}
		}
	}

	lbSegList1 := mfplanev1alpha1.Srv6SegmentList{}
	if err := r.List(ctx, &lbSegList1, &client.ListOptions{
		Namespace: nat.GetNamespace(),
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"srv6Action":        "endMflNat",
			"sidAllocated":      strconv.FormatBool(true),
			"ownerResourceKind": nat.Kind,
			"ownerResourceName": nat.GetName(),
		}),
	}); err != nil {
		return err
	}
	for _, seg := range lbSegList1.Items {
		seg.Spec = mfplanev1alpha1.Srv6SegmentSpec{
			Locator: "anycast",
			Selector: mfplanev1alpha1.MfpNodeSpecifySelector{
				MatchLabels: map[string]string{
					"nat": nat.Name,
				},
			},
			EndMflNat: &mfplanev1alpha1.EndMflNat{
				Vip:                nat.Spec.Vip,
				NatPortHashBit:     nat.Spec.NatPortHashBit,
				UsidBlockLength:    nat.Spec.UsidBlockLength,
				UsidFunctionLength: nat.Spec.UsidFunctionLength,
				USidFunctionRevisions: []mfplanev1alpha1.EndMflNatRevision{
					{
						Backends: sidList,
					},
				},
			},
		}
		if err := r.Update(ctx, &seg); err != nil {
			return err
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NatReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mfplanev1alpha1.Nat{}).
		Owns(&mfplanev1alpha1.Srv6Segment{}).
		Complete(r)
}
