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
    sudo -u openbao -H bash -c '
        export NVM_DIR="/var/lib/openbao/.nvm"
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash
        source $NVM_DIR/nvm.sh
        latest_node=$(nvm ls-remote | grep -Eo "v[0-9]+\.[0-9]+\.[0-9]+" | tail -1)
        nvm install "$latest_node"
    '

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

    sudo -u openbao -H bash -c '
        source /var/lib/openbao/.profile
        cd /var/lib/openbao/src/github.com/openbao/openbao
        export NVM_DIR="/var/lib/openbao/.nvm"
        source $NVM_DIR/nvm.sh
        nvm use --delete-prefix $(nvm ls-remote | grep -Eo "v[0-9]+\.[0-9]+\.[0-9]+" | tail -1) --silent
        export NODE_OPTIONS="--max_old_space_size=4096"
        make bootstrap > make_bootstrap.log 2>&1
    '

    # Step 7: Build static assets
    sudo -u openbao -H bash -c '
        source /var/lib/openbao/.profile
        cd /var/lib/openbao/src/github.com/openbao/openbao
        export NVM_DIR="/var/lib/openbao/.nvm"
        source $NVM_DIR/nvm.sh
        nvm use --delete-prefix $(nvm ls-remote | grep -Eo "v[0-9]+\.[0-9]+\.[0-9]+" | tail -1) --silent
        make static-dist dev-ui > make_static_dist.log 2>&1
    '

    # Step 8: Move the binary to the system path
    if [ -f /var/lib/openbao/src/github.com/openbao/openbao/bin/bao ]; then
        sudo mv /var/lib/openbao/src/github.com/openbao/openbao/bin/bao /usr/local/bin/openbao
    else
        echo "openbao binary not found. Compilation may have failed. Check make_bootstrap.log and make_static_dist.log for details."
        exit 1
    fi

    # Step 9: Verify OpenBao installation
    if ! command -v openbao &> /dev/null; then
        echo "openbao could not be found"
        exit 1
    fi
}

configure_openbao() {
    # Step 10: Configure OpenBao
    sudo mkdir -p /var/lib/openbao/config
    cat << 'EOF' | sudo tee /var/lib/openbao/config/config.hcl
ui = true
cluster_addr  = "https://<IP address or URL>:8201"
api_addr      = "https://<IP address or URL>:8200"
disable_mlock = true
storage "file" {
  path = "/var/lib/openbao/data"
}
listener "tcp" {
  address       = "<IP address or URL>:8200"
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
CN = <IP address or URL>

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names
basicConstraints = critical, CA:true

[alt_names]
IP.1 = <IP address or URL>
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
    echo "Exporting VAULT_ADDR..."
    export VAULT_ADDR="https://<IP address or URL>:8200"
    echo "VAULT_ADDR is set to $VAULT_ADDR"

    # Step 15: Start OpenBao with the Configuration File
    echo "Starting OpenBao server..."
    sudo -u openbao -H bash -c 'nohup openbao server -config /var/lib/openbao/config/config.hcl > /var/lib/openbao/openbao.log 2>&1 &'

    sleep 10  # Ensure the server has time to start

    echo