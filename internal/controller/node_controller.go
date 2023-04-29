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

// NodeReconciler reconciles a Node object
type NodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=nodes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=nodes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=mfplane.mfplane.io,resources=nodes/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Node object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.4/pkg/reconcile
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	node := mfplanev1alpha1.Node{}
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("RECONCILE")
	for _, fn := range node.Spec.Functions {
		util.SetLogger(log)
		// Attach XDP program
		if _, err := util.LocalExecutef("sudo ip netns exec %s "+
			"./bin/mikanectl bpf %s attach -i %s -f -n %s",
			fn.Netns, fn.Type, fn.Device, fn.Name); err != nil {
			return ctrl.Result{}, err
		}

		// Prepare config
		if err := util.WriteFile(fmt.Sprintf("/tmp/%s.config.yaml", fn.Name),
			[]byte(fn.ConfigFile)); err != nil {
			return ctrl.Result{}, err
		}
		if _, err := util.LocalExecutef("sudo ip netns exec %s "+
			"./bin/mikanectl map-load -f /tmp/%s.config.yaml",
			fn.Netns, fn.Name); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mfplanev1alpha1.Node{}).
		Complete(r)
}
