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

	"k8s.io/apimachinery/pkg/labels"
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
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	//////////////////////
	// Reconcile N-Node //
	//////////////////////
	log.Info("RECONCILE_L_NODE")

	segList := mfplanev1alpha1.Srv6SegmentList{}
	if err := r.List(ctx, &segList, &client.ListOptions{
		Namespace: nat.GetNamespace(),
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"srv6Action":        "endMfnNat",
			"ownerResourceKind": nat.Kind,
			"ownerResourceName": nat.GetName(),
		}),
	}); err != nil {
		return ctrl.Result{}, err
	}

	diff := nat.Spec.NetworkFunction.Replicas - len(segList.Items)
	pp.Println("diff", diff)
	if diff != 0 {
		seg := mfplanev1alpha1.Srv6Segment{
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
			seg.SetNamespace(nat.GetNamespace())
			seg.SetGenerateName(nat.GetName() + "-")
			op, err := ctrl.CreateOrUpdate(ctx, r.Client, &seg, func() error {
				seg.SetLabels(map[string]string{
					"nat":               nat.Name,
					"ownerResourceKind": nat.Kind,
					"ownerResourceName": nat.GetName(),
					"srv6Action":        "endMfnNat",
				})
				return ctrl.SetControllerReference(&nat, &seg, r.Scheme)
			})
			if err != nil {
				log.Error(err, "ERROR")
				return ctrl.Result{}, err
			}
			log.Info("CreateOrUpdate", "op", op)
		}
	}

	// segments, err := GetAllSegments(ctx, r.Client, "nat",
	// 	mfplanev1alpha1.SegmentOwner{Name: nat.Name, Kind: nat.Kind})
	// if err != nil {
	// 	return ctrl.Result{}, err
	// }
	// diff := nat.Spec.NetworkFunction.Replicas - len(segments)
	// if diff != 0 {
	// 	if diff > 0 {
	// 		pp.Println("CREATE!!!")
	// 		c0, err := GetAllFunctions(ctx, r.Client, "nat")
	// 		if err != nil {
	// 			return ctrl.Result{}, err
	// 		}
	// 		pp.Println("c0", c0)
	// 		c1 := SortCandidates(c0)
	// 		pp.Println("c1", c1)
	// 		if len(c1) > 0 {
	// 			c := c1[0]
	// 			pp.Println("c2", c)
	// 			if err := AddSegment(ctx, r.Client, req.Namespace, c.NodeName,
	// 				c.FuncName,
	// 				mfplanev1alpha1.Segment{
	// 					NodeName: c.NodeName,
	// 					FuncName: c.FuncName,
	// 					Locator:  "default",
	// 					Sid:      "??",
	// 					EndMfnNat: &mfplanev1alpha1.EndMfnNat{
	// 						Vip:                nat.Spec.Vip,
	// 						NatPortHashBit:     nat.Spec.NatPortHashBit,
	// 						UsidBlockLength:    nat.Spec.UsidBlockLength,
	// 						UsidFunctionLength: nat.Spec.UsidFunctionLength,
	// 						Sources:            nat.Spec.Sources,
	// 					},
	// 				}); err != nil {
	// 				return ctrl.Result{}, err
	// 			}
	// 		}
	// 	}

	// UPDAETE
	// if updated {
	// 	if err := r.Status().Update(ctx, &node); err != nil {
	// 		return ctrl.Result{}, err
	// 	}
	// }
	// }

	// TODO(slankdev): support scale-in. currently it doesn't support such case.
	// Need to consider using sub-resource/scale.

	//////////////////////
	// Reconcile ??-Node //
	//////////////////////
	// nbCreateNf := nat.Spec.NetworkFunction.Replicas
	// nodeList1 := mfplanev1alpha1.NodeList{}
	// if err := r.List(ctx, &nodeList1); err != nil {
	// 	return ctrl.Result{}, err
	// }
	// for _, node := range nodeList1.Items {
	// 	for _, fn := range node.Status.Functions {
	// 		for _, seg := range fn.Segments {
	// 			if seg.Owner.Kind == "Nat" && seg.Owner.Name == nat.Name &&
	// 				seg.EndMfnNat != nil {
	// 				nbCreateNf--
	// 			}
	// 		}
	// 	}
	// }
	// nfSegments := []mfplanev1alpha1.Segment{}
	// for i := 0; i < nbCreateNf; i++ {
	// 	newSeg := mfplanev1alpha1.Segment{
	// 		Locator: "default",
	// 		Owner: mfplanev1alpha1.SegmentOwner{
	// 			Kind: nat.Kind,
	// 			Name: nat.Name,
	// 		},
	// 	}

	// 	// XXX(slankdev)
	// 	if i == 0 {
	// 		newSeg.NodeName = "node-sample1"
	// 		newSeg.FuncName = "N1"
	// 		newSeg.Sid = "fc00:3101::/32"
	// 	}
	// 	if i == 1 {
	// 		newSeg.NodeName = "node-sample1"
	// 		newSeg.FuncName = "N2"
	// 		newSeg.Sid = "fc00:3201::/32"
	// 	}

	// 	nfSegments = append(nfSegments, newSeg)
	// }

	// Schedule L-node Segments
	// nbCreateLb := nat.Spec.LoadBalancer.Replicas
	// nodeList0 := mfplanev1alpha1.NodeList{}
	// if err := r.List(ctx, &nodeList0); err != nil {
	// 	return ctrl.Result{}, err
	// }
	// for _, node := range nodeList0.Items {
	// 	for _, fn := range node.Status.Functions {
	// 		for _, seg := range fn.Segments {
	// 			if seg.Owner.Kind == "Nat" && seg.Owner.Name == nat.Name &&
	// 				seg.EndMflNat != nil {
	// 				nbCreateLb--
	// 			}
	// 		}
	// 	}
	// }
	// lbSegments := []mfplanev1alpha1.Segment{}
	// for i := 0; i < nbCreateLb; i++ {
	// 	newSeg := mfplanev1alpha1.Segment{
	// 		Locator: "anycast",
	// 		Owner: mfplanev1alpha1.SegmentOwner{
	// 			Kind: nat.Kind,
	// 			Name: nat.Name,
	// 		},
	// 		EndMflNat: &mfplanev1alpha1.EndMflNat{
	// 			Vip:                nat.Spec.Vip,
	// 			NatPortHashBit:     nat.Spec.NatPortHashBit,
	// 			UsidBlockLength:    nat.Spec.UsidBlockLength,
	// 			UsidFunctionLength: nat.Spec.UsidFunctionLength,
	// 		},
	// 	}

	// 	// XXX(slankdev)
	// 	if i == 0 {
	// 		newSeg.NodeName = "node-sample1"
	// 		newSeg.FuncName = "L1"
	// 		newSeg.Sid = "fc00:ff01::/32"
	// 		newSeg.EndMflNat.USidFunctionRevisions = []mfplanev1alpha1.EndMflNatRevision{
	// 			{
	// 				Backends: []string{
	// 					"fc00:3101::/32",
	// 					"fc00:3201::/32",
	// 				},
	// 			},
	// 		}
	// 	}

	// 	lbSegments = append(lbSegments, newSeg)
	// }

	// // Reconcile for Node resource
	// nodeList := mfplanev1alpha1.NodeList{}
	// if err := r.List(ctx, &nodeList); err != nil {
	// 	return ctrl.Result{}, err
	// }
	// for _, node := range nodeList.Items {
	// 	// Resource init
	// 	if node.Status.Functions == nil {
	// 		node.Status.Functions = []mfplanev1alpha1.FunctionStatus{}
	// 	}
	// 	for _, fn := range node.Spec.Functions {
	// 		found := false
	// 		for _, statusFn := range node.Status.Functions {
	// 			if statusFn.Name == fn.Name {
	// 				found = true
	// 				break
	// 			}
	// 		}
	// 		if !found {
	// 			node.Status.Functions = append(node.Status.Functions,
	// 				mfplanev1alpha1.FunctionStatus{
	// 					Name:     fn.Name,
	// 					Segments: []mfplanev1alpha1.Segment{},
	// 				})
	// 		}
	// 	}

	// 	// Fill allocated segment
	// 	updated := false
	// 	for fnIdx, fn := range node.Status.Functions {
	// 		for _, seg := range lbSegments {
	// 			if seg.NodeName == node.Name && seg.FuncName == fn.Name {
	// 				fn.Segments = append(fn.Segments, seg)
	// 				node.Status.Functions[fnIdx].Segments = fn.Segments
	// 				updated = true
	// 			}
	// 		}
	// 		for _, seg := range nfSegments {
	// 			if seg.NodeName == node.Name && seg.FuncName == fn.Name {
	// 				fn.Segments = append(fn.Segments, seg)
	// 				node.Status.Functions[fnIdx].Segments = fn.Segments
	// 				updated = true
	// 			}
	// 		}
	// 	}

	// 	// Update node resource
	// 	if updated {
	// 		if err := r.Status().Update(ctx, &node); err != nil {
	// 			return ctrl.Result{}, err
	// 		}
	// 	}
	// }

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

// func GetAllFunctions(ctx context.Context, cli client.Client,
// 	funcType string) ([]ScheduleCandidate, error) {
// 	nodeList := mfplanev1alpha1.NodeList{}
// 	if err := cli.List(ctx, &nodeList); err != nil {
// 		return nil, err
// 	}
// 	candidates := []ScheduleCandidate{}
// 	for _, node := range nodeList.Items {
// 		for _, fn := range node.Spec.Functions {
// 			if fn.Type == funcType {
// 				c := ScheduleCandidate{
// 					NodeName: node.Name,
// 					FuncName: fn.Name,
// 				}
// 				fnStatus := mfplanev1alpha1.FunctionStatus{}
// 				if err := node.GetFunctionStatus(fn.Name, &fnStatus); err == nil {
// 					c.Segments = fnStatus.Segments
// 				}
// 				candidates = append(candidates, c)
// 			}
// 		}
// 	}
// 	return candidates, nil
// }

// func GetAllSegments(ctx context.Context, cli client.Client, typeName string,
// 	owner mfplanev1alpha1.SegmentOwner) ([]mfplanev1alpha1.Segment, error) {
// 	nodeList := mfplanev1alpha1.NodeList{}
// 	if err := cli.List(ctx, &nodeList); err != nil {
// 		return nil, err
// 	}
// 	segments := []mfplanev1alpha1.Segment{}
// 	for _, node := range nodeList.Items {
// 		for _, fn := range node.Spec.Functions {
// 			fnStatus := mfplanev1alpha1.FunctionStatus{}
// 			if err := node.GetFunctionStatus(fn.Name, &fnStatus); err != nil {
// 				continue
// 			}
// 			for _, seg := range fnStatus.Segments {
// 				if seg.Owner.Kind == owner.Kind && seg.Owner.Name == owner.Name &&
// 					fn.Type == typeName {
// 					segments = append(segments, seg)
// 				}
// 			}
// 		}
// 	}
// 	return segments, nil
// }

// func SortCandidates(in []ScheduleCandidate) []ScheduleCandidate {
// 	sort.Slice(in, func(i, j int) bool {
// 		return len(in[i].Segments) < len(in[j].Segments)
// 	})
// 	return in
// }

// func SyncNodeFunction(node *mfplanev1alpha1.Node) {
// 	if node.Status.Functions == nil {
// 		node.Status.Functions = []mfplanev1alpha1.FunctionStatus{}
// 	}
// 	for _, fn := range node.Spec.Functions {
// 		fnStatus := mfplanev1alpha1.FunctionStatus{}
// 		if err := node.GetFunctionStatus(fn.Name, &fnStatus); err != nil {
// 			node.Status.Functions = append(node.Status.Functions,
// 				mfplanev1alpha1.FunctionStatus{
// 					Name: fn.Name,
// 					// Segments: []mfplanev1alpha1.Segment{},
// 				})
// 		}
// 	}
// }

// func AddSegment(ctx context.Context, cli client.Client,
// 	ns, nodeName, funcName string, seg mfplanev1alpha1.Segment) error {
// 	node := mfplanev1alpha1.Node{}
// 	if err := cli.Get(ctx, types.NamespacedName{Namespace: ns,
// 		Name: nodeName}, &node); err != nil {
// 		return err
// 	}
// 	SyncNodeFunction(&node)
// 	fnStatus := mfplanev1alpha1.FunctionStatus{}
// 	if err := node.GetFunctionStatus(funcName, &fnStatus); err != nil {
// 		return err
// 	}
// 	fnStatus.Segments = append(fnStatus.Segments, seg)
// 	if err := node.SetFunctionStatus(funcName, &fnStatus); err != nil {
// 		return err
// 	}
// 	pp.Println("UPDATE", node)
// 	if err := cli.Status().Update(ctx, &node); err != nil {
// 		return err
// 	}
// 	pp.Println("UPDATE DONE")
// 	return nil
// }
