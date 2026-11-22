#cloud-config
hostname: __HOSTNAME__
fqdn: __HOSTNAME__
manage_etc_hosts: true
preserve_hostname: false
timezone: Etc/UTC
users:
  - name: penguinbox
    gecos: PenguinBox sandbox
    groups: [adm, sudo]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - __SSH_PUBLIC_KEY__
ssh_pwauth: false
disable_root: true
write_files:
  - path: /opt/penguinbox/provision.sh
    owner: root:root
    permissions: '0755'
    encoding: b64
    content: __PROVISION_B64__
runcmd:
  - [ bash, /opt/penguinbox/provision.sh ]
final_message: "PenguinBox is provisioned; tools are installed"
