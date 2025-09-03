
# About

This is a project that is to demostrate how EVPN HA works without multihomed, using frr or gobgp. 
1. terraform IaC for fast POC.
2. It uses alicloud.

Check this on my blog: [SDN&网络：EVPN高可用实践](https://solofox.github.io/2025/08/29/evpn-ha-over-multiple-tunnels.html).

# Usage
- install terraform, get a alicloud acount and openapi key 
- export your alicloud ak/sk
export ALICLOUD_ACCESS_KEY='xxxxxxxx'
export ALICLOUD_SECRET_KEY='yyyyyyyy'
- cd frr or gobgp
- terraform init
- terraform apply
Now login to ecs to check everything.

## Note
for gobgp part, you probably need to change the region to US by edit gobgp/main.tf:
```hcl
provider "alicloud" {
  region = "cn-beijing"  # 请根据实际需求修改区域
}
```
or download these three files and put it in a reachable site, and modify gobgp/main.tf accordingly (6 lines to changed):
```
wget 'https://raw.githubusercontent.com/solofox/evpn-ha/refs/heads/main/gobgp/gobgp_3.37.0_linux_amd64.tar.gz'
wget 'https://raw.githubusercontent.com/solofox/evpn-ha/refs/heads/main/gobgp/gobgp-api-proto.tar.gz'
wget 'https://raw.githubusercontent.com/solofox/evpn-ha/refs/heads/main/gobgp/vxlan.py'
```

