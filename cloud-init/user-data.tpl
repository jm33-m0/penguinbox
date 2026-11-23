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
    lock_passwd: false
    ssh_authorized_keys:
      - __SSH_PUBLIC_KEY__
# Console (VNC and serial) password login. cloud-init hashes the plaintext.
# SSH password authentication stays disabled, so this only unlocks the local
# console for debugging a guest whose API or provisioning failed.
chpasswd:
  expire: false
  list: |
    penguinbox:__CONSOLE_PASSWORD__
ssh_pwauth: false
ssh_deletekeys: false
disable_root: true
write_files:
  - path: /opt/penguinbox/provision.sh
    owner: root:root
    permissions: '0755'
    encoding: b64
    content: __PROVISION_B64__
  # Cloud-init runcmd is one-shot per instance-id, so an interrupted first boot
  # would never install penguinboxd. The unit retries on every boot (and every
  # RestartSec while failing) until provision.sh writes the completion marker.
  - path: /etc/systemd/system/penguinbox-provision.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=PenguinBox guest provisioning
      After=network-online.target
      Wants=network-online.target
      ConditionPathExists=!/var/lib/penguinbox-provisioned

      [Service]
      Type=simple
      ExecStart=/bin/bash /opt/penguinbox/provision.sh
      Restart=on-failure
      RestartSec=60s

      [Install]
      WantedBy=multi-user.target
runcmd:
  - [ install, -d, -m, '0700', -o, penguinbox, -g, penguinbox, /home/penguinbox/.ssh ]
  - [ bash, -c, 'printf "%s\n" "$1" >/home/penguinbox/.ssh/authorized_keys && chown penguinbox:penguinbox /home/penguinbox/.ssh/authorized_keys && chmod 0600 /home/penguinbox/.ssh/authorized_keys', --, __SSH_PUBLIC_KEY__ ]
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, --now, penguinbox-provision.service ]
final_message: "PenguinBox boot complete; provisioning state: systemctl status penguinbox-provision.service"
