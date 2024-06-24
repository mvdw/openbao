#!/bin/bash

echo "This script requires root privileges."
if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Not running as root"
    exit 1
else
    echo "Installation continues"
fi

create_user_and_setup() {
    # Step 0: Create openbao user and group if not exists
    if id "openbao" &>/dev/null; then
        echo "User 'openbao' already exists"
    else
        sudo useradd --system --home /var/lib/openbao --shell /bin/bash --user-group openbao
    fi

    # Check if /var/lib/openbao directory exists, if not, create it
    if [ ! -d /var/lib/openbao ]; then
        sudo mkdir -p /var/lib/openbao
        sudo chown openbao:openbao /var/lib/openbao
    fi

    # Ensure .bashrc and .profile are copied from /etc/skel
    for file in .bashrc .profile; do
        if [ ! -f /var/lib/openbao/$file ]; then
            sudo cp /etc/skel/$file /var/lib/openbao/$file
            sudo chown openbao:openbao /var/lib/openbao/$file
        fi
    done
}

install_go() {
    # Step 1: Install Go
    wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
    echo "export PATH=\$PATH:/usr/local/go/bin" | sudo tee -a /var/lib/openbao/.profile
    sudo chown -R openbao:openbao /var/lib/openbao
}

install_dependencies() {
    # Step 2: Install OpenBao dependencies
    sudo mkdir -p /var/lib/openbao/.nvm
    sudo chown -R openbao:openbao /var/lib/openbao
    sudo apt install -y git make curl gnupg2
}

install_nvm_node_yarn() {
    # Step 3: Install NVM and Node.js for the openbao user
    sudo -u openbao -H bash -c 'cd /var/lib/openbao && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash'
    sudo -u openbao -H bash -c 'export NVM_DIR="/var/lib/openbao/.nvm" && cd /var/lib/openbao && source $NVM_DIR/nvm.sh && nvm install 22'

    # Step 4: Install yarn for the openbao user in /var/lib/openbao
    sudo -u openbao -H bash -c 'export NVM_DIR="/var/lib/openbao/.nvm" && cd /var/lib/openbao && source $NVM_DIR/nvm.sh && npm config set prefix /var/lib/openbao/.npm-global && npm install -g yarn'
    sudo -u openbao -H bash -c 'echo "export PATH=/var/lib/openbao/.npm-global/bin:\$PATH" >> /var/lib/openbao/.profile'
}

clone_and_build_openbao() {
    # Step 5: Clone and build OpenBao
    sudo mkdir -p /var/lib/openbao/src/github.com/openbao
    sudo chown -R openbao:openbao /var/lib/openbao/src/github.com
    cd /var/lib/openbao/src/github.com/openbao
    if [ ! -d "openbao" ]; then
        sudo -u openbao git clone https://github.com/openbao/openbao.git
    fi
    cd openbao
    sudo chown -R openbao:openbao /var/lib/openbao/src/github.com/openbao/openbao

    # Step 6: Ensure proper environment variables are set
    # Remove conflicting settings from .npmrc
    sudo -u openbao -H bash -c 'echo "" > /var/lib/openbao/.npmrc'

    sudo -u openbao -H bash -c 'source /var/lib/openbao/.profile && cd /var/lib/openbao/src/github.com/openbao/openbao && export NVM_DIR="/var/lib/openbao/.nvm" && source $NVM_DIR/nvm.sh && nvm use --delete-prefix v22.3.0 --silent && export NODE_OPTIONS="--max_old_space_size=4096" && make bootstrap > make_bootstrap.log 2>&1'

    # Step 7: Build static assets
    sudo -u openbao -H bash -c 'source /var/lib/openbao/.profile && cd /var/lib/openbao/src/github.com/openbao/openbao && export NVM_DIR="/var/lib/openbao/.nvm" && source $NVM_DIR/nvm.sh && nvm use --delete-prefix v22.3.0 --silent && make static-dist dev-ui > make_static_dist.log 2>&1'

    # Step 8: Move the binary to the system path
    if [ -f /var/lib/openbao/src/github.com/openbao/openbao/bin/bao ]; then
        sudo mv /var/lib/openbao/src/github.com/openbao/openbao/bin/bao /usr/local/bin/openbao
    else
        echo "openbao binary not found. Compilation may have failed. Check make_bootstrap.log and make_static_dist.log for details."
        exit 1
    fi

    # Step 9: Verify OpenBao installation
    if ! command -v openbao &> /dev/null
    then
        echo "openbao could not be found"
        exit 1
    fi
}

configure_openbao() {
    # Step 10: Configure OpenBao
    sudo mkdir -p /var/lib/openbao/config
    cat << 'EOF' | sudo tee /var/lib/openbao/config/config.hcl
ui = true
cluster_addr  = "https://10.10.0.126:8201"
api_addr      = "https://10.10.0.126:8200"
disable_mlock = true
storage "file" {
  path = "/var/lib/openbao/data"
}
listener "tcp" {
  address       = "10.10.0.126:8200"
  tls_cert_file = "/var/lib/openbao/tls/tls.crt"
  tls_key_file  = "/var/lib/openbao/tls/tls.key"
}
EOF

    sudo mkdir -p /var/lib/openbao/data
    sudo chown -R openbao:openbao /var/lib/openbao/data
    sudo chmod -R 755 /var/lib/openbao/data
}

create_openssl_config() {
    # Step 11: Create OpenSSL Configuration File
    cat << 'EOF' | sudo tee /var/lib/openbao/openssl.cnf
[req]
default_bits       = 2048
default_md         = sha256
prompt             = no
encrypt_key        = no
distinguished_name = dn
req_extensions     = req_ext
x509_extensions    = v3_ca

[dn]
C  = US
ST = State
L  = City
O  = Organization
OU = Organizational Unit
CN = 10.10.0.126

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names
basicConstraints = critical, CA:true

[alt_names]
IP.1 = 10.10.0.126
EOF
}

generate_private_key_and_certificate() {
    # Step 12: Generate new private key and certificate
    sudo openssl genpkey -algorithm RSA -out /var/lib/openbao/tls.key
    sudo openssl req -new -x509 -days 365 -key /var/lib/openbao/tls.key -out /var/lib/openbao/tls.crt -config /var/lib/openbao/openssl.cnf

    sudo mkdir -p /var/lib/openbao/tls
    sudo mv /var/lib/openbao/tls.crt /var/lib/openbao/tls/
    sudo mv /var/lib/openbao/tls.key /var/lib/openbao/tls/
    sudo chown -R openbao:openbao /var/lib/openbao/tls/

    sudo cp /var/lib/openbao/tls/tls.crt /usr/local/share/ca-certificates/openbao.crt
    sudo update-ca-certificates

    # Step 13: Ensure proper ownership of all files
    sudo chown -R openbao:openbao /var/lib/openbao
}

initialize_and_unseal_openbao() {
    # Step 14: Initialize and unseal OpenBao
    # Create .bashrc for openbao user with VAULT_ADDR
    sudo -u openbao -H bash -c 'echo "export VAULT_ADDR=\"https://10.10.0.126:8200\"" >> /var/lib/openbao/.bashrc && source /var/lib/openbao/.bashrc'

    # Step 15: Start OpenBao with the Configuration File
    sudo -u openbao -H bash -c 'source /var/lib/openbao/.bashrc && openbao server -config /var/lib/openbao/config/config.hcl &'
    sleep 30  # Ensure the server has time to start
    echo "Wait 30 seconds to make sure that the openbao server has time to start "

    # Check if OpenBao server is running
    if ! curl -k https://10.10.0.126:8200/v1/sys/seal-status; then
        echo "OpenBao server is not responding. Please check the logs."
        exit 1
    fi

    sudo -u openbao -H bash -c 'source /var/lib/openbao/.bashrc && openbao operator init  > /tmp/init_output.txt'

    #cat /tmp/init_output.txt

    # Display the initialization output
    INIT_OUTPUT=$(cat /tmp/init_output.txt)
    UNSEAL_KEYS=$(echo "$INIT_OUTPUT" | grep "Unseal Key" | awk "{print \$NF}")
    echo "$UNSEAL_KEYS" > /tmp/unseal_keys.txt

    # Prepare unseal keys for encryption as adrian user
    UNSEAL_KEY_1=$(echo "$UNSEAL_KEYS" | sed -n '1p')
    UNSEAL_KEY_2=$(echo "$UNSEAL_KEYS" | sed -n '2p')
    UNSEAL_KEY_3=$(echo "$UNSEAL_KEYS" | sed -n '3p')
    UNSEAL_KEY_4=$(echo "$UNSEAL_KEYS" | sed -n '4p')
    UNSEAL_KEY_5=$(echo "$UNSEAL_KEYS" | sed -n '5p')    

    # Encrypt the unseal keys
    apt -y install gnupg
    echo "your-passphrase" > /root/.gpg_passphrase
    echo -e "$UNSEAL_KEY_1\n$UNSEAL_KEY_2\n$UNSEAL_KEY_3\n$UNSEAL_KEY_4\n$UNSEAL_KEY_5" | gpg --batch --yes --passphrase-file /root/.gpg_passphrase --symmetric --cipher-algo AES256 -o /root/.vault_unseal_keys.gpg
    chmod 400 /root/.vault_unseal_keys.gpg

    # Optional: Clean up temporary files
    rm /tmp/init_output.txt /tmp/unseal_keys.txt

    echo "OpenBao setup completed successfully."
}

create_unseal_script() {
    cat << 'EOF' > /usr/local/bin/unseal_openbao.sh
#!/bin/bash

export VAULT_ADDR='https://10.10.0.126:8200'

# Create log file if it doesn't exist
LOGFILE=/var/log/unseal_openbao.log
if [ ! -f "$LOGFILE" ]; then
    touch "$LOGFILE"
    chown openbao:openbao "$LOGFILE"
else
    echo "$LOGFILE exists"
fi

# Log the start time
echo "Starting unseal at $(date)" >> $LOGFILE

# Wait for OpenBao to be ready
while ! curl -k https://10.10.0.126:8200/v1/sys/seal-status | grep -q '"sealed":true'; do
  echo "Waiting for OpenBao to be sealed and ready..." >> $LOGFILE
  sleep 5
done

echo "OpenBao is sealed and ready at $(date)" >> $LOGFILE

# Load the GPG passphrase
GPG_PASSPHRASE=$(cat /root/.gpg_passphrase)

# Decrypt the unseal keys
UNSEAL_KEYS=$(gpg --quiet --batch --yes --decrypt --passphrase "$GPG_PASSPHRASE" /root/.vault_unseal_keys.gpg)
if [ $? -ne 0 ]; then
  echo "Failed to decrypt unseal keys at $(date)" >> $LOGFILE
  exit 1
fi

echo "Unseal keys decrypted successfully at $(date)" >> $LOGFILE

# Convert decrypted keys to an array
UNSEAL_KEYS_ARRAY=($(echo "$UNSEAL_KEYS"))

# Unseal OpenBao
for key in "${UNSEAL_KEYS_ARRAY[@]}"; do
  curl -k --request POST --data "{\"key\": \"$key\"}" https://10.10.0.126:8200/v1/sys/unseal # >> $LOGFILE 2>&1
  #if [ $? -ne 0 ]; then
  #  echo "Failed to unseal with key $key at $(date)" >> $LOGFILE
  #  exit 1
  #fi
  #echo "Successfully used unseal key $key at $(date)" >> $LOGFILE
done

echo "OpenBao unsealed successfully at $(date)" >> $LOGFILE
EOF
chmod +x /usr/local/bin/unseal_openbao.sh
}

create_env_file() {
# Create environment file for OpenBao
sudo mkdir -p /etc/openbao.d
cat << 'EOF' | sudo tee /etc/openbao.d/openbao.env
VAULT_ADDR=https://10.10.0.126:8200
DBUS_SESSION_BUS_ADDRESS=$XDG_RUNTIME_DIR/bus
EOF
}

create_systemd_services() {
# Create openbao.service
cat << 'EOF' | sudo tee /etc/systemd/system/openbao.service
[Unit]
Description=OpenBao
Documentation=https://github.com/openbao/openbao
Requires=network-online.target
After=network-online.target
Requires=openbao-unseal.service

[Service]
User=openbao
Group=openbao
EnvironmentFile=/etc/openbao.d/openbao.env
ExecStart=/usr/local/bin/openbao server -config=/var/lib/openbao/config/config.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Create openbao-unseal.service
cat << 'EOF' | sudo tee /etc/systemd/system/openbao-unseal.service
[Unit]
Description=Unseal OpenBao
After=openbao.service
Requires=openbao.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/unseal_openbao.sh
Environment=VAULT_ADDR=https://10.10.0.126:8200
Environment=DBUS_SESSION_BUS_ADDRESS=$XDG_RUNTIME_DIR/bus

[Install]
WantedBy=multi-user.target
EOF
}

kill_openbao() {
    # Find and kill running OpenBao instances gracefully
    pkill -f openbao
    # Wait for a few seconds to ensure processes are terminated
    sleep 5
}


system_services() {
    # Reload systemd and enable services
    echo "Reloading systemd daemon..."
    sudo systemctl daemon-reload
    if [ $? -ne 0 ]; then
        echo "Failed to reload systemd daemon"
        exit 1
    fi

    echo "Enabling openbao-unseal.service..."
    sudo systemctl enable openbao-unseal.service
    if [ $? -ne 0 ]; then
        echo "Failed to enable openbao-unseal.service"
        exit 1
    fi

    echo "Enabling openbao.service..."
    sudo systemctl enable openbao.service
    if [ $? -ne 0 ]; then
        echo "Failed to enable openbao.service"
        exit 1
    fi

    echo "Starting openbao.service..."
    sudo systemctl start openbao.service
    if [ $? -ne 0 ]; then
        echo "Failed to start openbao.service"
        exit 1
    fi
}

main() {
    create_user_and_setup
    install_go
    install_dependencies
    install_nvm_node_yarn
    clone_and_build_openbao
    configure_openbao
    create_openssl_config
    generate_private_key_and_certificate
    initialize_and_unseal_openbao
    create_unseal_script
    create_env_file
    create_systemd_services
    kill_openbao
    system_services
}

main "$@"
