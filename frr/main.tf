# main.tf - 阿里云高可用VXLAN网络架构

provider "alicloud" {
  region = "cn-beijing"  # 请根据实际需求修改区域
}

# 变量定义
variable "instance_type" {
  default = "ecs.c7.large"
}

variable "disk_type" {
  default = "cloud_essd"
}

variable "image_id" {
  default = "ubuntu_24_04_x64_20G_alibase_20250722.vhd"  # 请根据实际需求选择镜像
}

variable "vni" {
  default = 100  # VXLAN Network Identifier
}

variable "bgp_asn" {
  default = 65001  # BGP自治系统号
}

# 数据源：获取可用区
data "alicloud_zones" "default" {
  available_resource_creation = "VSwitch"
  available_instance_type     = "${var.instance_type}"
  available_disk_category     = "${var.disk_type}"
}

resource "alicloud_ecs_key_pair" "frr_evpn_ha_key_pair" {
  key_pair_name = "frr-evpn-ha-key-pair"
  public_key    = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCjY7eOVWfQji8YauBwzIW7iTmsnkvGuYZck/qJJbqY7XAbYUK1dCAbJDuICEzG6Nk25jcJETDty+h4kC9cGYW9hzv8/ZCUTyaNVCY8eFfLeDEUBDF56sqtyqAh8Z2L+ZlksnIu/PGAH4GwZ2wPwRdfCS9qGiyu0U+FT5Or61hnsSNWKrCbQ5T5QPJLXQLuE0Ihn7KfFWQa3LsBCLvFaMO0WH1oS2+HW2miWZgJLe502CYTcVTbBEiCoa1e5jNyQ8jS6pnLY6B7ycm5SGU2Dl0L9QpmK1faZxP6jugFxz+UXHot7A5oX9/WoYi4tY9jBftyUs1gDCfGnzbWrlFyyiXivZbAk2eSm75Ra5ew/wiIEAuU5lrlr7oYPVNIDnxknuo4aKR12NG655bk9EbDWBDEumLTtTXH1j/6r2f6welx895VK5Q6VtyLCYpGnRT758+eoLl24QuVEi4nNDcY0YQ7p7nS3HxkAvCo1B6QE+wjy8W9vVyDTYRt/BFs4w+vbAc= solofox"
}

# VPC和网络配置
resource "alicloud_vpc" "main" {
  vpc_name   = "vxlan-high-availability-vpc"
  cidr_block = "192.168.0.0/16"
}

resource "alicloud_vswitch" "network1" {
  vpc_id            = alicloud_vpc.main.id
  cidr_block        = "192.168.1.0/24"
  zone_id           = data.alicloud_zones.default.zones[0].id
  vswitch_name      = "network1"
}

resource "alicloud_vswitch" "network2" {
  vpc_id            = alicloud_vpc.main.id
  cidr_block        = "192.168.2.0/24"
  zone_id           = data.alicloud_zones.default.zones[0].id
  vswitch_name      = "network2"
}

# 安全组配置
resource "alicloud_security_group" "server_sg1" {
  name   = "server-security-group"
  vpc_id = alicloud_vpc.main.id
}

# 规则1: 允许192.168.1.0/24的所有协议互通
resource "alicloud_security_group_rule" "sg1rule1" {
  type              = "ingress"
  ip_protocol       = "all"
  security_group_id = alicloud_security_group.server_sg1.id
  cidr_ip           = "192.168.1.0/24"
  policy            = "accept"
  nic_type          = "intranet"
}

# 规则2: 允许0.0.0.0/0的SSH (TCP 22) 和远程桌面(RDP, TCP 3389) 协议互通
resource "alicloud_security_group_rule" "sg1rule2_ssh" {
  type              = "ingress"
  ip_protocol       = "tcp"
  security_group_id = alicloud_security_group.server_sg1.id
  port_range        = "22/22"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
  priority          = 1
  nic_type          = "intranet"
}

resource "alicloud_security_group_rule" "sg1rule2_rdp" {
  type              = "ingress"
  ip_protocol       = "tcp"
  security_group_id = alicloud_security_group.server_sg1.id
  port_range        = "3389/3389"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
  priority          = 1
  nic_type          = "intranet"
}

resource "alicloud_security_group" "server_sg2" {
  name   = "server-security-group"
  vpc_id = alicloud_vpc.main.id
}

# 规则1: 允许192.168.2.0/24的所有协议互通
resource "alicloud_security_group_rule" "sg2rule1" {
  type              = "ingress"
  ip_protocol       = "all"
  security_group_id = alicloud_security_group.server_sg2.id
  cidr_ip           = "192.168.2.0/24"
  policy            = "accept"
  nic_type          = "intranet"
}

# 规则2: 允许0.0.0.0/0的SSH (TCP 22) 和远程桌面(RDP, TCP 3389) 协议互通
resource "alicloud_security_group_rule" "sg2rule2_ssh" {
  type              = "ingress"
  ip_protocol       = "tcp"
  security_group_id = alicloud_security_group.server_sg2.id
  port_range        = "22/22"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
  priority          = 1
  nic_type          = "intranet"
}

resource "alicloud_security_group_rule" "sg2rule2_rdp" {
  type              = "ingress"
  ip_protocol       = "tcp"
  security_group_id = alicloud_security_group.server_sg2.id
  port_range        = "3389/3389"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
  priority          = 1
  nic_type          = "intranet"
}


# 路由反射器实例
resource "alicloud_instance" "rr_net1" {
  instance_name        = "RR-net1"
  host_name            = "RR-net1"
  private_ip           = "192.168.1.2"
  image_id             = var.image_id
  instance_type        = var.instance_type
  system_disk_category = "${var.disk_type}"
  system_disk_size     = "40"
  security_groups      = [alicloud_security_group.server_sg1.id]
  vswitch_id           = alicloud_vswitch.network1.id
  key_name             = alicloud_ecs_key_pair.frr_evpn_ha_key_pair.id
  internet_max_bandwidth_out = 0
  
  user_data = <<EOF
#!/bin/bash
set -e
# 安装FRR
apt update -y
apt install -y frr frr-pythontools

# 配置FRR
cat >> /etc/frr/daemons << 'EOL'
bgpd=yes
EOL

cat >> /etc/frr/frr.conf << 'EOL'
router bgp ${var.bgp_asn}
 bgp router-id 192.168.1.2
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 bgp cluster-id 192.168.1.2
 neighbor VTEPs peer-group
 neighbor VTEPs remote-as ${var.bgp_asn}
 neighbor VTEPs capability extend-nexthop
 ! clients
 bgp listen range 192.168.1.0/24 peer-group VTEPs
 ! 
 address-family l2vpn evpn
  neighbor VTEPs activate
  neighbor VTEPs route-reflector-client
 exit-address-family
exit
EOL

systemctl enable frr
systemctl restart frr
EOF
}

resource "alicloud_instance" "rr_net2" {
  instance_name        = "RR-net2"
  host_name            = "RR-net2"
  private_ip           = "192.168.2.2"
  image_id             = var.image_id
  instance_type        = var.instance_type
  system_disk_category = "${var.disk_type}"
  system_disk_size     = "40"
  security_groups      = [alicloud_security_group.server_sg2.id]
  vswitch_id           = alicloud_vswitch.network2.id
  key_name             = alicloud_ecs_key_pair.frr_evpn_ha_key_pair.id
  internet_max_bandwidth_out = 0
  
  user_data = <<EOF
#!/bin/bash
set -e
# 安装FRR
apt update -y
apt install -y frr frr-pythontools

# 配置FRR
cat >> /etc/frr/daemons << 'EOL'
bgpd=yes
EOL

cat >> /etc/frr/frr.conf << 'EOL'
router bgp ${var.bgp_asn}
 bgp router-id 192.168.2.2
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 bgp cluster-id 192.168.2.2
 neighbor VTEPs peer-group
 neighbor VTEPs remote-as ${var.bgp_asn}
 neighbor VTEPs capability extend-nexthop
 ! clients
 bgp listen range 192.168.2.0/24 peer-group VTEPs
 ! 
 address-family l2vpn evpn
  neighbor VTEPs activate
  neighbor VTEPs route-reflector-client
 exit-address-family
exit
EOL

systemctl enable frr
systemctl restart frr
EOF
}

# 服务器实例
resource "alicloud_instance" "server-l" {
  instance_name        = "server-l"
  host_name            = "server-l"
  private_ip           = "192.168.1.65"
  image_id             = var.image_id
  instance_type        = var.instance_type
  system_disk_category = "${var.disk_type}"
  system_disk_size     = "40"
  security_groups      = [alicloud_security_group.server_sg1.id]
  vswitch_id           = alicloud_vswitch.network1.id
  key_name             = alicloud_ecs_key_pair.frr_evpn_ha_key_pair.id
  internet_max_bandwidth_out = 0
  
  user_data = <<EOF
#!/bin/bash
set -e
# 安装必要软件
apt update -y
apt install -y frr frr-pythontools

echo "waiting for eth1"
while ! (ip link show eth1); do 
  echo "eth1 is not ready yet."
  sleep 2
done

# 创建Bridge
ip link add br-vxlan type bridge
ip addr add 192.168.0.65/24 dev br-vxlan
ip link set br-vxlan up

# 创建VTEP接口
ip link add vxlan0 type vxlan id ${var.vni} dstport 4789 nolearning
ip link set vxlan0 master br-vxlan
ip link set vxlan0 up

# 配置FRR
cat >> /etc/frr/daemons << 'EOL'
bgpd=yes
zebra=yes
EOL

cat >> /etc/frr/frr.conf << 'EOL'
! 禁用type3路由。这个VXLAN网络中无未知/隐藏的服务器，无需BUM处理。
route-map NO_TYPE3 deny 10
 match evpn route-type 3
route-map NO_TYPE3 permit 20
! 主备，实际上不work
route-map PRIMARY-LINK permit 10
 set local-preference 200
route-map BACKUP-LINK permit 10
 set local-prefernce 100
router bgp ${var.bgp_asn}
 bgp router-id 192.168.1.65
 ! bgp listen disable
 no bgp default ipv4-unicast
 neighbor RR peer-group
 neighbor RR remote-as ${var.bgp_asn}
 neighbor RR capability extend-nexthop
 neighbor RR timers 3 9
 ! neighbors
 neighbor 192.168.1.2 peer-group RR
 neighbor 192.168.2.2 peer-group RR
 address-family l2vpn evpn
  neighbor RR route-map NO_TYPE3 out
  neighbor 192.168.1.2 route-map PRIMARY-LINK in
  neighbor 192.168.2.2 route-map BACKUP-LINK in
  neighbor RR next-hop-self
  neighbor RR activate
  advertise-all-vni
  advertise-svi-ip
 exit-address-family
exit
EOL

systemctl enable frr
systemctl restart frr
EOF
}

resource "alicloud_instance" "server-r" {
  instance_name        = "server-r"
  host_name            = "server-r"
  private_ip           = "192.168.1.87"
  image_id             = var.image_id
  instance_type        = var.instance_type
  system_disk_category = "${var.disk_type}"
  system_disk_size     = "40"
  security_groups      = [alicloud_security_group.server_sg1.id]
  vswitch_id           = alicloud_vswitch.network1.id
  key_name             = alicloud_ecs_key_pair.frr_evpn_ha_key_pair.id
  internet_max_bandwidth_out = 0
  
  user_data = <<EOF
#!/bin/bash
set -e
# 安装必要软件
apt update -y
apt install -y frr frr-pythontools

echo "waiting for eth1"
while ! (ip link show eth1); do 
  echo "eth1 is not ready yet."
  sleep 2
done

# 创建Bridge
ip link add br-vxlan type bridge
ip addr add 192.168.0.87/24 dev br-vxlan
ip link set br-vxlan up

# 创建VTEP接口
ip link add vxlan0 type vxlan id ${var.vni} dstport 4789 nolearning
ip link set vxlan0 master br-vxlan
ip link set vxlan0 up

# 配置FRR
cat >> /etc/frr/daemons << 'EOL'
bgpd=yes
zebra=yes
EOL

cat >> /etc/frr/frr.conf << 'EOL'
! 禁用type3路由。这个VXLAN网络中无未知/隐藏的服务器，无需BUM处理。
route-map NO_TYPE3 deny 10
 match evpn route-type 3
route-map NO_TYPE3 permit 20
! 主备，实际上不work
route-map PRIMARY-LINK permit 10
 set local-preference 200
route-map BACKUP-LINK permit 10
 set local-prefernce 100
router bgp ${var.bgp_asn}
 bgp router-id 192.168.1.87
 ! bgp listen disable
 no bgp default ipv4-unicast
 neighbor RR peer-group
 neighbor RR remote-as ${var.bgp_asn}
 neighbor RR capability extend-nexthop
 neighbor RR timers 3 9
 ! neighbors
 neighbor 192.168.1.2 peer-group RR
 neighbor 192.168.2.2 peer-group RR
 address-family l2vpn evpn
  neighbor RR route-map NO_TYPE3 out
  neighbor 192.168.1.2 route-map PRIMARY-LINK in
  neighbor 192.168.2.2 route-map BACKUP-LINK in
  neighbor RR next-hop-self
  neighbor RR activate
  advertise-all-vni
  advertise-svi-ip
 exit-address-family
exit
EOL

systemctl enable frr
systemctl restart frr
EOF
}

# server-l的eth1
resource "alicloud_network_interface" "server-l-eth1" {
  vswitch_id      = alicloud_vswitch.network2.id
  security_groups = [alicloud_security_group.server_sg2.id]
  private_ip      = "192.168.2.65"
  name            = "server-l-eth1"
}

resource "alicloud_network_interface_attachment" "server-l-eth1-attachment" {
  instance_id          = alicloud_instance.server-l.id
  network_interface_id = alicloud_network_interface.server-l-eth1.id
}

# server-r的eth1
resource "alicloud_network_interface" "server-r-eth1" {
  vswitch_id      = alicloud_vswitch.network2.id
  security_groups = [alicloud_security_group.server_sg2.id]
  private_ip      = "192.168.2.87"
  name            = "server-r-eth1"
}

resource "alicloud_network_interface_attachment" "server-r-eth1-attachment" {
  instance_id          = alicloud_instance.server-r.id
  network_interface_id = alicloud_network_interface.server-r-eth1.id
}

