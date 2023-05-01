/*
Copyright 2023 Hiroki Shirokura.

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

package util

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type ReconcileStatus struct {
	SpecUpdated   bool
	StatusUpdated bool
	Requeue       bool
	RequeueAfter  time.Duration
}

func NewReconcileStatus() *ReconcileStatus {
	return &ReconcileStatus{}
}

func (res *ReconcileStatus) ReconcileUpdate(ctx context.Context,
	cli client.Client, obj client.Object) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	if res.StatusUpdated {
		log.Info("STATUS_UPDATE")
		if err := cli.Status().Update(ctx, obj); err != nil {
			log.Info("SKIPPABLE_ERROR", "error", err.Error())
			return ctrl.Result{}, err
		}
	}
	if res.SpecUpdated {
		log.Info("SPEC_UPDATE")
		if err := cli.Update(ctx, obj); err != nil {
			log.Info("SKIPPABLE_ERROR", "error", err.Error())
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}
