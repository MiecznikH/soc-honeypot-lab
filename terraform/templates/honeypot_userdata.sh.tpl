#!/bin/bash
################################################################################
# Bootstrap honeypota: Cowrie + agent Wazuh
################################################################################
set -euxo pipefail
exec > >(tee /var/log/user-data.log) 2>&1

export DEBIAN_FRONTEND=noninteractive

########################################
sed -i "s/^#\?Port .*/Port ${admin_ssh_port}/" /etc/ssh/sshd_config
systemctl restart ssh

########################################
# 2. Zależności + Cowrie jako dedykowany użytkownik
########################################
apt-get update
apt-get install -y git python3-venv python3-pip python3-dev libssl-dev \
                   libffi-dev build-essential iptables-persistent curl

adduser --disabled-password --gecos "" cowrie

sudo -u cowrie bash <<EOSU
set -eux
cd /home/cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie
git checkout ${cowrie_ref}
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp src/cowrie/data/etc/cowrie.cfg.dist etc/cowrie.cfg
# Cowrie nasłuchuje na 2222 (domyślnie) — nie wymaga uprawnień roota.
EOSU

# Przekierowanie 22 -> 2222.
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
netfilter-persistent save

# Cowrie jako usługa systemd (przeżyje reboot).
cat > /etc/systemd/system/cowrie.service <<'EOF'
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
ExecStart=/home/cowrie/cowrie/bin/cowrie start
ExecStop=/home/cowrie/cowrie/bin/cowrie stop
PIDFile=/home/cowrie/cowrie/var/run/cowrie.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cowrie

########################################
# 3. Agent Wazuh — przypięta wersja
########################################
curl -fsSLO "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${wazuh_agent_version}_amd64.deb"
WAZUH_MANAGER="${manager_ip}" WAZUH_AGENT_NAME="${agent_name}" \
  dpkg -i "./wazuh-agent_${wazuh_agent_version}_amd64.deb"

# blok auto-update, żeby restart nie rozłożył agenta.
apt-mark hold wazuh-agent

########################################
# 4. Przekierowanie agentowi, żeby czytał log Cowrie.
#    Bez tego blok honeypota nie istnieje i srcip nigdy nie trafia do indeksu.
########################################
sed -i "s|</ossec_config>||" /var/ossec/etc/ossec.conf
cat >> /var/ossec/etc/ossec.conf <<'EOF'
  <localfile>
    <log_format>json</log_format>
    <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>
  </localfile>
</ossec_config>
EOF

# Odczyt logu dla agenta.
chmod o+rx /home/cowrie/cowrie /home/cowrie/cowrie/var \
           /home/cowrie/cowrie/var/log /home/cowrie/cowrie/var/log/cowrie || true

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "BOOTSTRAP OK: cowrie + wazuh-agent skonfigurowane."
