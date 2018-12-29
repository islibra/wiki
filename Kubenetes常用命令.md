```bash
kubectl get namespace/ns  #查看namespace
kubectl get node -nmynamespace  #查看指定namespace节点状态
kubectl get node --all-namespaces  #查看所有namespace节点状态
kubectl create -f xxx.yaml [-nkube-system]  #根据yaml创建资源
kubectl get ingress xxx  #查看ingress信息
kubectl describe ingress xxx-ingress [-nkube-system]  #查看详细ingress信息
#更新ingress
kubectl edit ingress xxx
kubectl replace -f xxx.yaml
kubectl get deployment [-nxxx]  #查看deployment信息
#查看deployment的yaml文件
kubectl get deployment xxx -nxxx -oyaml
kubectl edit deployment xxx -nxxx
kubectl get pod -nxxx -owide | grep aaa  #查看POD
kubectl get pod -nxxx -owide -oyaml aaa | grep hostIP   #获取POD所在节点IP
kubectl get svc -nxxx  #查看service信息
```
