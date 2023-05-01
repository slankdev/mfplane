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

	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/k0kubun/pp"
	mfplanev1alpha1 "github.com/slankdev/mfplane/api/v1alpha1"
	"github.com/slankdev/mfplane/pkg/goroute2"
	"github.com/slankdev/mfplane/pkg/mikanectl"
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
	res := util.NewReconcileStatus()

	// Fetch Resource
	node := mfplanev1alpha1.Node{}
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Do Reconcile
	log.Info("RECONCILE_MAIN_ROUTINE_FINISH")
	if err := r.reconcileXdpAttach(ctx, req, &node, res); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileXdpMapLoad(ctx, req, &node, res); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("RECONCILE_MAIN_ROUTINE_FINISH")

	return res.ReconcileUpdate(ctx, r.Client, &node)
}

func (r *NodeReconciler) reconcileXdpAttach(ctx context.Context,
	req ctrl.Request, node *mfplanev1alpha1.Node,
	res *util.ReconcileStatus) error {
	log := log.FromContext(ctx)
	util.SetLogger(log)
	log.Info("RECONCILE_XDP_ATTACHING")
	for _, fn := range node.Spec.Functions {
		// Check XDP program
		linkDetail, err := goroute2.GetLinkDetail(fn.Netns, fn.Device)
		if err != nil {
			return err
		}
		if linkDetail == nil {
			return fmt.Errorf("link %s not found", fn.Device)
		}

		// Attach XDP program
		if linkDetail.Xdp == nil {
			if _, err := util.LocalExecutef("sudo ip netns exec %s "+
				"./bin/mikanectl bpf %s attach -i %s -n %s -m %s",
				fn.Netns, fn.Type, fn.Device, fn.Name, fn.Mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *NodeReconciler) reconcileXdpMapLoad(ctx context.Context,
	req ctrl.Request, node *mfplanev1alpha1.Node,
	res *util.ReconcileStatus) error {
	log := log.FromContext(ctx)
	log.Info("RECONCILE_XDP_MAP_LOAD")
	for _, fn := range node.Spec.Functions {

		segList := mfplanev1alpha1.Srv6SegmentList{}
		if err := r.List(ctx, &segList, &client.ListOptions{
			Namespace: node.GetNamespace(),
			LabelSelector: labels.SelectorFromSet(map[string]string{
				"nodeName":     node.Name,
				"funcName":     fn.Name,
				"sidAllocated": strconv.FormatBool(true),
			}),
		}); err != nil {
			return err
		}
		for _, seg := range segList.Items {
			pp.Println(node.Name, fn.Name, seg.Name)
		}
		print("\n")

		// KOKOKARA
		// Prepare config
		// configFile, err := craftConfig(fnSpec, fnStatus)
		// if err != nil {
		// 	return err
		// }
		// if err := util.WriteFile(fmt.Sprintf("/tmp/%s.config.yaml", fn.Name),
		// 	[]byte(configFile)); err != nil {
		// 	return err
		// }
		// if _, err := util.LocalExecutef("sudo ip netns exec %s "+
		// 	"./bin/mikanectl map-load -f /tmp/%s.config.yaml",
		// 	fn.Netns, fn.Name); err != nil {
		// 	return err
		// }
	}
	return nil
}

func craftConfig(fnSpec mfplanev1alpha1.FunctionSpec,
	fnStatus mfplanev1alpha1.FunctionStatus) (string, error) {
	c := mikanectl.Config{
		NamePrefix:  fnSpec.Name,
		MaxRules:    2,
		MaxBackends: 7,
		EncapSource: fnSpec.SegmentRoutingSrv6.EncapSource,
	}
	// for _, seg := range fnStatus.Segments {
	// 	sid := mikanectl.ConfigLocalSid{}
	// 	sid.Sid = seg.Sid
	// 	switch {
	// 	case seg.EndMflNat != nil:
	// 		sid.End_MFL = &mikanectl.ConfigLocalSid_End_MFL{
	// 			Vip:                seg.EndMflNat.Vip,
	// 			NatPortHashBit:     seg.EndMflNat.NatPortHashBit, // XXX: typo
	// 			USidBlock:          "fc00::0",                    // TODO(slankdev)
	// 			USidBlockLength:    seg.EndMflNat.UsidBlockLength,
	// 			USidFunctionLength: seg.EndMflNat.UsidFunctionLength,
	// 			NatMapping:         "endpointIndependentMapping",   // TODO(slankdev)
	// 			NatFiltering:       "endpointIndependentFiltering", // TODO(slankdev)
	// 		}
	// 		for _, rev := range seg.EndMflNat.USidFunctionRevisions {
	// 			backends := []string{}
	// 			for _, b := range rev.Backends {
	// 				_, ipnet, err := net.ParseCIDR(b)
	// 				if err != nil {
	// 					return "", err
	// 				}
	// 				u8 := [16]uint8{}
	// 				copy(u8[:], ipnet.IP)
	// 				u8 = util.BitShiftLeft8(u8)
	// 				u8 = util.BitShiftLeft8(u8)
	// 				newip := net.IP(u8[:])
	// 				backends = append(backends, newip.String())
	// 			}

	// 			sid.End_MFL.USidFunctionRevisions = append(
	// 				sid.End_MFL.USidFunctionRevisions,
	// 				mikanectl.FunctionRevision{
	// 					Backends: backends,
	// 				},
	// 			)
	// 		}
	// 	case seg.EndMfnNat != nil:
	// 		sid.End_MFN_NAT = &mikanectl.ConfigLocalSid_End_MFN_NAT{
	// 			Vip:                seg.EndMfnNat.Vip,
	// 			NatPortHashBit:     seg.EndMfnNat.NatPortHashBit, // XXX: typo
	// 			USidBlockLength:    seg.EndMfnNat.UsidBlockLength,
	// 			USidFunctionLength: seg.EndMfnNat.UsidFunctionLength,
	// 			Sources:            seg.EndMfnNat.Sources,
	// 		}
	// 	default:
	// 		return "", fmt.Errorf("no sid activated")
	// 	}
	// 	c.LocalSids = append(c.LocalSids, sid)
	// }
	out, err := yaml.Marshal(c)
	if err != nil {
		return "", err
	}
	sout := string(out) + "\n" + fnSpec.ConfigFile
	return sout, nil
}

func (r *NodeReconciler) findNodesFromSrv6Segment(
	seg0 client.Object) []reconcile.Request {
	seg := mfplanev1alpha1.Srv6Segment{}
	if err := r.Get(context.TODO(), types.NamespacedName{
		Namespace: seg0.GetNamespace(), Name: seg0.GetName()}, &seg); err != nil {
		return []reconcile.Request{}
	}
	if seg.Status.NodeName == "" || seg.Status.FuncName == "" {
		return []reconcile.Request{}
	}
	nodeList := mfplanev1alpha1.NodeList{}
	if err := r.List(context.TODO(), &nodeList); err != nil {
		return []reconcile.Request{}
	}
	requests := []reconcile.Request{}
	for _, node := range nodeList.Items {
		if seg.Status.NodeName == node.Name {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      node.GetName(),
					Namespace: node.GetNamespace(),
				},
			})
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mfplanev1alpha1.Node{}).
		Watches(
			&source.Kind{Type: &mfplanev1alpha1.Srv6Segment{}},
			handler.EnqueueRequestsFromMapFunc(r.findNodesFromSrv6Segment),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}
