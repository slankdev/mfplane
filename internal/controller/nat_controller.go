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

	"github.com/k0kubun/pp"
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
		return ctrl.Result{}, err
	}

	// Schedule L-node Segments
	lbSegments := []mfplanev1alpha1.Segment{}
	for i := 0; i < nat.Spec.LoadBalancer.Replicas; i++ {
		lbSegments = append(lbSegments, mfplanev1alpha1.Segment{
			Owner: mfplanev1alpha1.SegmentOwner{
				Kind: nat.Kind,
				Name: nat.Name,
			},
			EndMflNat: &mfplanev1alpha1.EndMflNat{
				Vip:                nat.Spec.Vip,
				NatPortHashBitMaxk: nat.Spec.NatPortHashBit,
				UsidBlockLength:    nat.Spec.UsidBlockLength,
				UsidFunctionLength: nat.Spec.UsidFunctionLength,
			},
		})
	}
	// XXX(slankdev)
	lbSegments[0].NodeName = "node-sample1"
	lbSegments[0].FuncName = "L1"
	lbSegments[0].Locator = "anycast"
	lbSegments[0].Sid = "fc00:ff:1::/48"

	// Schedule N-node Segments
	nfSegments := []mfplanev1alpha1.Segment{}
	for i := 0; i < nat.Spec.NetworkFunction.Replicas; i++ {
		nfSegments = append(nfSegments, mfplanev1alpha1.Segment{
			Locator: "anycast",
			Sid:     "",
			Owner: mfplanev1alpha1.SegmentOwner{
				Kind: nat.Kind,
				Name: nat.Name,
			},
			EndMflNat: &mfplanev1alpha1.EndMflNat{
				Vip:                nat.Spec.Vip,
				NatPortHashBitMaxk: nat.Spec.NatPortHashBit,
				UsidBlockLength:    nat.Spec.UsidBlockLength,
				UsidFunctionLength: nat.Spec.UsidFunctionLength,
			},
		})
	}
	// XXX(slankdev)
	nfSegments[0].NodeName = "node-sample1"
	nfSegments[0].FuncName = "N1"
	nfSegments[0].Locator = "default"
	nfSegments[0].Sid = "fc00:3101::/32"
	nfSegments[1].NodeName = "node-sample1"
	nfSegments[1].FuncName = "N2"
	nfSegments[1].Locator = "default"
	nfSegments[1].Sid = "fc00:3201::/32"

	// Reconcile for L-node
	log.Info("RECONCILE_L_NODE")
	nodeList := mfplanev1alpha1.NodeList{}
	if err := r.List(ctx, &nodeList); err != nil {
		return ctrl.Result{}, err
	}
	for _, node := range nodeList.Items {
		for _, fn := range node.Spec.Functions {
			pp.Println(fn.Name)
		}
	}

	// Reconcile for N-node
	// TODO(slankdev): implement me
	// log.Info("RECONCILE_N_NODE")

	pp.Println("L-node", lbSegments)
	pp.Println("N-node", nfSegments)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NatReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mfplanev1alpha1.Nat{}).
		Complete(r)
}
