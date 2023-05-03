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
	"net"
	"strconv"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	mfplanev1alpha1 "github.com/slankdev/mfplane/api/v1alpha1"
	"github.com/slankdev/mfplane/pkg/ebpf"
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
	if err := r.reconcileNatDaemon(ctx, req, &node, res); err != nil {
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
				"./bin/mikanectl bpf %s attach -i %s -n %s -m %s --define RING_SIZE=65537",
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
	util.SetLogger(log)
	log.Info("RECONCILE_XDP_MAP_LOAD")
	for _, fn := range node.Spec.Functions {
		// Fetch SID(s) which is allocated and bound on node:fn
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

		// Prepare config
		configFile, err := craftConfig(ctx, fn, segList)
		if err != nil {
			log.Error(err, "craftConfig")
			return err
		}
		if err := util.WriteFile(fmt.Sprintf("/tmp/%s.config.yaml", fn.Name),
			[]byte(configFile)); err != nil {
			log.Error(err, "util.WriteFile")
			return err
		}
		if _, err := util.LocalExecutef("sudo ip netns exec %s "+
			"./bin/mikanectl map-load -f /tmp/%s.config.yaml",
			fn.Netns, fn.Name); err != nil {
			log.Error(err, "map-load")
			return err
		}

		// Ensure Finalizer
		for _, item := range segList.Items {
			f := fmt.Sprintf("%s.%s.nodes.mfplane.io", fn.Name, node.Name)
			diff := false
			if item.DeletionTimestamp.IsZero() {
				diff = util.SetFinalizer(&item, f)
			} else {
				diff = util.UnsetFinalizer(&item, f)
			}
			if diff {
				if err := r.Update(ctx, &item); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (r *NodeReconciler) reconcileNatDaemon(ctx context.Context,
	req ctrl.Request, node *mfplanev1alpha1.Node,
	res *util.ReconcileStatus) error {
	log := log.FromContext(ctx)

	for _, fnSpec := range node.Spec.Functions {
		fnStatus := mfplanev1alpha1.FunctionStatus{}
		if err := node.GetFunctionStatus(fnSpec.Name, &fnStatus); err != nil {
			fnStatus.Name = fnSpec.Name
			fnStatus.Pidfile = fmt.Sprintf("/tmp/%s.%s.pid", node.Name, fnSpec.Name)
			fnStatus.Running = false
			node.Status.Functions = append(node.Status.Functions, fnStatus)
			res.StatusUpdated = true
			log.Info("NEW FUNCTION STATUS", "funcName", fnSpec.Name)
		}

		// Check Child process is running
		running, err := util.CheckProcess(fnStatus.Pidfile)
		if err != nil {
			log.Error(err, "util.CheckProcess")
			return err
		}

		// Start Daemon if not running
		if !running {
			pid, err := util.BackgroundLocalExecutef(
				"ip netns exec %s mikanectl daemon-nat -n %s",
				fnSpec.Netns, fnSpec.Name)
			if err != nil {
				return err
			}
			if err := util.WriteFile(fnStatus.Pidfile,
				[]byte(fmt.Sprintf("%d", pid))); err != nil {
				return err
			}
			log.Info("subprocess started", "funcName", fnSpec.Name, "pid", pid)
		}
	}
	return nil
}

func craftConfig(ctx context.Context,
	fnSpec mfplanev1alpha1.FunctionSpec,
	segList mfplanev1alpha1.Srv6SegmentList) (string, error) {
	log := log.FromContext(ctx)
	c := mikanectl.Config{
		NamePrefix:  fnSpec.Name,
		EncapSource: fnSpec.SegmentRoutingSrv6.EncapSource,
	}
	for _, seg := range segList.Items {
		if !seg.DeletionTimestamp.IsZero() {
			_, _ = util.LocalExecutef(
				"sudo ip netns exec %s ip -6 route del blackhole %s",
				fnSpec.Netns, seg.Status.Sid)
			switch {
			case seg.Spec.EndMflNat != nil:
				_, _ = util.LocalExecutef(
					"sudo ip netns exec %s ip -4 route del blackhole %s",
					fnSpec.Netns, seg.Spec.EndMflNat.Vip)
			case seg.Spec.EndMfnNat != nil:
				// Do nothing
			}
			continue
		} else {
			sid := mikanectl.ConfigLocalSid{}
			sid.Sid = seg.Status.Sid
			switch {
			case seg.Spec.EndMflNat != nil:
				sid.End_MFL = &mikanectl.ConfigLocalSid_End_MFL{
					Vip:                seg.Spec.EndMflNat.Vip,
					NatPortHashBit:     seg.Spec.EndMflNat.NatPortHashBit, // XXX: typo
					USidBlock:          "fc00::0",                         // TODO(slankdev)
					USidBlockLength:    seg.Spec.EndMflNat.UsidBlockLength,
					USidFunctionLength: seg.Spec.EndMflNat.UsidFunctionLength,
					NatMapping:         "endpointIndependentMapping",   // TODO(slankdev)
					NatFiltering:       "endpointIndependentFiltering", // TODO(slankdev)
				}

				for _, rev := range seg.Spec.EndMflNat.USidFunctionRevisions {
					backends := []string{}
					for _, b := range rev.Backends {
						_, ipnet, err := net.ParseCIDR(b)
						if err != nil {
							log.Error(err, "net.ParseCIDR")
							return "", err
						}
						u8 := [16]uint8{}
						copy(u8[:], ipnet.IP)
						u8 = util.BitShiftLeft8(u8)
						u8 = util.BitShiftLeft8(u8)
						newip := net.IP(u8[:])
						backends = append(backends, newip.String())
					}

					sid.End_MFL.USidFunctionRevisions = append(
						sid.End_MFL.USidFunctionRevisions,
						mikanectl.FunctionRevision{
							Backends: backends,
						},
					)
				}
				if _, err := util.LocalExecutef(
					"sudo ip netns exec %s ip -4 route replace blackhole %s",
					fnSpec.Netns, seg.Spec.EndMflNat.Vip); err != nil {
					return "", err
				}
			case seg.Spec.EndMfnNat != nil:
				sid.End_MFN_NAT = &mikanectl.ConfigLocalSid_End_MFN_NAT{
					Vip:                seg.Spec.EndMfnNat.Vip,
					NatPortHashBit:     seg.Spec.EndMfnNat.NatPortHashBit, // XXX: typo
					USidBlockLength:    seg.Spec.EndMfnNat.UsidBlockLength,
					USidFunctionLength: seg.Spec.EndMfnNat.UsidFunctionLength,
					Sources:            seg.Spec.EndMfnNat.Sources,
				}
			default:
				return "", fmt.Errorf("no sid activated")
			}
			c.LocalSids = append(c.LocalSids, sid)
			if _, err := util.LocalExecutef(
				"sudo ip netns exec %s ip -6 route replace blackhole %s",
				fnSpec.Netns, seg.Status.Sid); err != nil {
				return "", err
			}
		}
	}
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

var (
	receivePkts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "mfplane",
			Name:      "receive_pkts",
		},
		[]string{"node", "netns", "device", "sid", "action"},
	)
)

type Collector struct {
	client client.Client
}

func MustRegisterPromCollector(cli client.Client) {
	metrics.Registry.MustRegister(&Collector{client: cli})
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- receivePkts.WithLabelValues(
		"node", "netns", "device", "sid", "action").Desc()
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	nodeList := mfplanev1alpha1.NodeList{}
	if err := c.client.List(context.TODO(), &nodeList); err == nil {
		for _, node := range nodeList.Items {
			for _, fn := range node.Spec.Functions {
				if err := ebpf.BatchMapOperation(fn.Name+"_fib6",
					ciliumebpf.LPMTrie,
					func(m *ciliumebpf.Map) error {
						key := ebpf.Trie6Key{}
						val := ebpf.Trie6Val{}
						entries := m.Iterate()
						for entries.Next(&key, &val) {
							ch <- prometheus.MustNewConstMetric(
								receivePkts.WithLabelValues(
									"node", "netns", "device", "sid", "action").Desc(),
								prometheus.CounterValue, float64(val.StatsTotalPkts),
								node.Name, fn.Name, fn.Device,
								fmt.Sprintf("%s/%d", net.IP(key.Addr[:]), key.Prefixlen),
								val.Action.String(),
							)
						}
						return nil
					}); err != nil {
					continue
				}

			}
		}
	}
}

// XXX(slankdev): HARIBOTE
var cnt = 0

// XXX(slankdev): HARIBOTE
func init() {
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			cnt++
		}
	}()
}
