# 0x91_kubernetes-sigs

!!! quote "[Kubernetes SIGs](https://github.com/kubernetes-sigs/): Kubernetes SIG 相关项目"

## I. kubebuilder

<https://github.com/kubernetes-sigs/kubebuilder>

用来生成 CRD API 的 SDK

## I. controller-runtime

<https://github.com/kubernetes-sigs/controller-runtime>

kubebuilder 的子项目, 被 Operator SDK 使用

构建 Controller 使用的 Go 库

```go
package main

import (
    "context"
    "fmt"
    "os"

    logf "sigs.k8s.io/controller-runtime/pkg/log"

    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    "sigs.k8s.io/controller-runtime/pkg/builder"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/client/config"
    "sigs.k8s.io/controller-runtime/pkg/log/zap"
    "sigs.k8s.io/controller-runtime/pkg/manager"
    "sigs.k8s.io/controller-runtime/pkg/manager/signals"
    "sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// 示例: 通过 ReplicaSet 控制 Pod
func main() {
    logf.SetLogger(zap.New())

    var log = logf.Log.WithName("builder-examples")

    // 创建 manager
    mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{})
    if err != nil {
        log.Error(err, "could not create manager")
        os.Exit(1)
    }

    // 创建 ControllerManagedBy
    err = builder.
        ControllerManagedBy(mgr).  // Create the ControllerManagedBy
        For(&appsv1.ReplicaSet{}). // ReplicaSet is the Application API
        Owns(&corev1.Pod{}).       // ReplicaSet owns Pods created by it
        Complete(&ReplicaSetReconciler{})
    if err != nil {
        log.Error(err, "could not create controller")
        os.Exit(1)
    }

    // 启动 manager
    if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
        log.Error(err, "could not start manager")
        os.Exit(1)
    }
}

// ReplicaSetReconciler 实现了 ControllerManagedBy
type ReplicaSetReconciler struct {
    client.Client
}

// Implement the business logic:
// This function will be called when there is a change to a ReplicaSet or a Pod with an OwnerReference
// to a ReplicaSet.
//
// * Read the ReplicaSet
// * Read the Pods
// * Set a Label on the ReplicaSet with the Pod count
func (a *ReplicaSetReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
    // Read the ReplicaSet
    rs := &appsv1.ReplicaSet{}
    err := a.Get(ctx, req.NamespacedName, rs)
    if err != nil {
        return reconcile.Result{}, err
    }

    // List the Pods matching the PodTemplate Labels
    pods := &corev1.PodList{}
    err = a.List(ctx, pods, client.InNamespace(req.Namespace), client.MatchingLabels(rs.Spec.Template.Labels))
    if err != nil {
        return reconcile.Result{}, err
    }

    // Update the ReplicaSet
    rs.Labels["pod-count"] = fmt.Sprintf("%v", len(pods.Items))
    err = a.Update(ctx, rs)
    if err != nil {
        return reconcile.Result{}, err
    }

    return reconcile.Result{}, nil
}

func (a *ReplicaSetReconciler) InjectClient(c client.Client) error {
    a.Client = c
    return nil
}
```
