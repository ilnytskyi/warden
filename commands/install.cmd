#!/usr/bin/env bash
[[ ! ${WARDEN_DIR} ]] && >&2 echo -e "\033[31mThis script is not intended to be run directly!\033[0m" && exit 1

source "${WARDEN_DIR}/utils/install.sh"

if [[ ! -d "${WARDEN_SSL_DIR}/rootca" ]]; then
    mkdir -p "${WARDEN_SSL_DIR}/rootca"/{certs,crl,newcerts,private}

    touch "${WARDEN_SSL_DIR}/rootca/index.txt"
    echo 1000 > "${WARDEN_SSL_DIR}/rootca/serial"
    echo 1000 > "${WARDEN_SSL_DIR}/rootca/crlnumber"
fi

# create CA root certificate if none present
if [[ ! -f "${WARDEN_SSL_DIR}/rootca/private/ca.key.pem" ]]; then
  echo "==> Generating private key for local root certificate"
  openssl genrsa -out "${WARDEN_SSL_DIR}/rootca/private/ca.key.pem" 2048
fi

if [[ ! -f "${WARDEN_SSL_DIR}/rootca/certs/ca.cert.pem" ]]; then
  echo "==> Signing root certificate 'Warden Proxy Local CA ($(hostname -s))'"
  openssl req -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -config "${WARDEN_DIR}/config/openssl/rootca.conf"        \
    -key "${WARDEN_SSL_DIR}/rootca/private/ca.key.pem"        \
    -out "${WARDEN_SSL_DIR}/rootca/certs/ca.cert.pem"         \
    -subj "/C=US/O=Warden.dev/CN=Warden Proxy Local CA ($(hostname -s))"
fi

if [[ ! -f "${WARDEN_SSL_DIR}/rootca/crlnumber" ]]; then
  echo 1000 > "${WARDEN_SSL_DIR}/rootca/crlnumber"
fi

if [[ ! -f "${WARDEN_SSL_DIR}/rootca/crl/ca.crl.pem" ]]; then
  echo "==> Generating certificate revocation list for local root certificate"
  openssl ca -gencrl -config "${WARDEN_DIR}/config/openssl/rootca.conf" \
    -out "${WARDEN_SSL_DIR}/rootca/crl/ca.crl.pem"
fi

## trust root ca differently on Fedora, Ubuntu and macOS
if [[ "$OSTYPE" =~ ^linux ]] \
  && [[ -d /etc/pki/ca-trust/source/anchors ]] \
  && [[ ! -f /etc/pki/ca-trust/source/anchors/warden-proxy-local-ca.cert.pem ]] \
  ## Fedora/CentOS
then
  echo "==> Trusting root certificate (requires sudo privileges)"  
  sudo cp "${WARDEN_SSL_DIR}/rootca/certs/ca.cert.pem" /etc/pki/ca-trust/source/anchors/warden-proxy-local-ca.cert.pem
  sudo update-ca-trust
elif [[ "$OSTYPE" =~ ^linux ]] \
  && [[ -d /usr/local/share/ca-certificates ]] \
  && [[ ! -f /usr/local/share/ca-certificates/warden-proxy-local-ca.crt ]] \
  ## Ubuntu/Debian
then
  echo "==> Trusting root certificate (requires sudo privileges)"
  sudo cp "${WARDEN_SSL_DIR}/rootca/certs/ca.cert.pem" /usr/local/share/ca-certificates/warden-proxy-local-ca.crt
  sudo update-ca-certificates
elif [[ "$OSTYPE" == "darwin"* ]] \
  && ! security dump-trust-settings -d | grep 'Warden Proxy Local CA' >/dev/null \
  ## Apple macOS
then
  echo "==> Trusting root certificate (requires sudo privileges)"
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain "${WARDEN_SSL_DIR}/rootca/certs/ca.cert.pem"
fi

if hasWindowsCertificateBridge; then
  echo "==> Trusting root certificate in Windows Root store"
  if ! windows_trust_status="$(trustRootCaInWindows "${WARDEN_SSL_DIR}/rootca/certs/ca.cert.pem")"; then
    warning "Unable to trust the Warden root certificate in Windows. Windows browsers may continue to warn until it is imported manually."
    sendWindowsNotification "Warden Certificate" "Unable to trust the Warden root certificate in Windows. Manual import may still be required." "Error"
  elif [[ "${windows_trust_status}" == "localmachine_present" ]]; then
    echo "==> Root certificate already present in Windows LocalMachine Root store"
  elif [[ "${windows_trust_status}" == "localmachine_imported" ]]; then
    echo "==> Root certificate imported into Windows LocalMachine Root store"
    sendWindowsNotification "Warden Certificate" "Warden root certificate installed in Windows LocalMachine Root." "Info"
  elif [[ "${windows_trust_status}" == "localmachine_replaced" ]]; then
    echo "==> Root certificate replaced in Windows LocalMachine Root store"
    sendWindowsNotification "Warden Certificate" "Warden root certificate was rotated in Windows LocalMachine Root." "Info"
  elif [[ "${windows_trust_status}" == "localmachine_imported_via_elevation" ]]; then
    echo "==> Root certificate imported into Windows LocalMachine Root store after administrator approval"
    sendWindowsNotification "Warden Certificate" "Warden root certificate installed in Windows LocalMachine Root after administrator approval." "Info"
  elif [[ "${windows_trust_status}" == "localmachine_policy_blocked_present" ]]; then
    warning "Windows policy may be preventing installation of the Warden root certificate into Windows LocalMachine Root. The certificate is already present in Windows CurrentUser Root store. Contact your administrator if Windows system services still reject the certificate."
    sendWindowsNotification "Warden Certificate" "Windows policy may be preventing LocalMachine Root installation. The certificate is present in CurrentUser Root." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_policy_blocked_imported" ]]; then
    warning "Windows policy may be preventing installation of the Warden root certificate into Windows LocalMachine Root. Imported into Windows CurrentUser Root store instead. Contact your administrator if Windows system services still reject the certificate."
    sendWindowsNotification "Warden Certificate" "Windows policy may be preventing LocalMachine Root installation. The certificate was imported into CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_policy_blocked_replaced" ]]; then
    warning "Windows policy may be preventing installation of the Warden root certificate into Windows LocalMachine Root. Replaced in Windows CurrentUser Root store instead. Contact your administrator if Windows system services still reject the certificate."
    sendWindowsNotification "Warden Certificate" "Windows policy may be preventing LocalMachine Root installation. The certificate was rotated in CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_store_error_present" ]]; then
    warning "Windows rejected installation of the Warden root certificate into Windows LocalMachine Root for a reason other than access denial. The certificate is already present in Windows CurrentUser Root store. Windows policy or endpoint security may be blocking this operation."
    sendWindowsNotification "Warden Certificate" "Windows rejected LocalMachine Root installation. The certificate is present in CurrentUser Root." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_store_error_imported" ]]; then
    warning "Windows rejected installation of the Warden root certificate into Windows LocalMachine Root for a reason other than access denial. Imported into Windows CurrentUser Root store instead. Windows policy or endpoint security may be blocking this operation."
    sendWindowsNotification "Warden Certificate" "Windows rejected LocalMachine Root installation. The certificate was imported into CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_store_error_replaced" ]]; then
    warning "Windows rejected installation of the Warden root certificate into Windows LocalMachine Root for a reason other than access denial. Replaced in Windows CurrentUser Root store instead. Windows policy or endpoint security may be blocking this operation."
    sendWindowsNotification "Warden Certificate" "Windows rejected LocalMachine Root installation. The certificate was rotated in CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_elevation_cancelled_present" ]]; then
    warning "Administrator approval was canceled while importing the Warden root certificate into Windows LocalMachine Root. The certificate is already present in Windows CurrentUser Root store."
    sendWindowsNotification "Warden Certificate" "Administrator approval was canceled. The certificate is already present in Windows CurrentUser Root." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_elevation_cancelled_imported" ]]; then
    warning "Administrator approval was canceled while importing the Warden root certificate into Windows LocalMachine Root. Imported into Windows CurrentUser Root store instead."
    sendWindowsNotification "Warden Certificate" "Administrator approval was canceled. The certificate was imported into Windows CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_elevation_cancelled_replaced" ]]; then
    warning "Administrator approval was canceled while importing the Warden root certificate into Windows LocalMachine Root. Replaced in Windows CurrentUser Root store instead."
    sendWindowsNotification "Warden Certificate" "Administrator approval was canceled. The certificate was rotated in Windows CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_elevation_failed_present" ]]; then
    warning "Administrator-approved import into Windows LocalMachine Root did not complete successfully. The certificate is already present in Windows CurrentUser Root store."
    sendWindowsNotification "Warden Certificate" "Administrator-approved import into Windows LocalMachine Root did not complete. The certificate is already present in Windows CurrentUser Root." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_elevation_failed_imported" ]]; then
    warning "Administrator-approved import into Windows LocalMachine Root did not complete successfully. Imported into Windows CurrentUser Root store instead."
    sendWindowsNotification "Warden Certificate" "Administrator-approved import into Windows LocalMachine Root did not complete. The certificate was imported into Windows CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_elevation_failed_replaced" ]]; then
    warning "Administrator-approved import into Windows LocalMachine Root did not complete successfully. Replaced in Windows CurrentUser Root store instead."
    sendWindowsNotification "Warden Certificate" "Administrator-approved import into Windows LocalMachine Root did not complete. The certificate was rotated in Windows CurrentUser Root instead." "Warning"
  elif [[ "${windows_trust_status}" == "localmachine_policy_blocked_unreadable" ]] || [[ "${windows_trust_status}" == "localmachine_store_error_unreadable" ]]; then
    warning "Windows policy or endpoint security may be preventing Warden from checking or updating Windows CurrentUser Root after the LocalMachine Root install was blocked."
  fi
fi

## configure resolver for .test domains on Mac OS only as Linux lacks support
## for BSD like per-TLD configuration as is done at /etc/resolver/test on Mac
if [[ "$OSTYPE" == "darwin"* ]]; then
  if [[ ! -f /etc/resolver/test ]]; then
    echo "==> Configuring resolver for .test domains (requires sudo privileges)"
    if [[ ! -d /etc/resolver ]]; then
        sudo mkdir /etc/resolver
    fi
    echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/test >/dev/null
  fi
else
  warning "Manual configuration required for Automatic DNS resolution: https://docs.warden.dev/configuration/dns-resolver.html"
fi

## generate rsa keypair for authenticating to warden sshd service
if [[ ! -f "${WARDEN_HOME_DIR}/tunnel/ssh_key" ]]; then
  echo "==> Generating rsa key pair for tunnel into sshd service"
  mkdir -p "${WARDEN_HOME_DIR}/tunnel"
  ssh-keygen -b 2048 -t rsa -f "${WARDEN_HOME_DIR}/tunnel/ssh_key" -N "" -C "user@tunnel.warden.test"
fi

## if host machine does not have composer installed, this directory will otherwise be created by docker with root:root
## causing problems so it's created as current user to avoid composer issues inside environments given it is mounted
if [[ ! -d ~/.composer ]]; then
  mkdir ~/.composer
fi

## since bind mounts are native on linux to use .pub file as authorized_keys file in tunnel it must have proper perms
if [[ "$OSTYPE" =~ ^linux ]] && [[ "$(stat -c '%U' "${WARDEN_HOME_DIR}/tunnel/ssh_key.pub")" != "root" ]]; then
  sudo chown root:root "${WARDEN_HOME_DIR}/tunnel/ssh_key.pub"
fi

## append settings for tunnel.warden.test in /etc/ssh/ssh_config
installSshConfig

## Add optional Warden configuration file
if [[ ! -f "${WARDEN_HOME_DIR}/.env" ]]; then
	cat >> "${WARDEN_HOME_DIR}/.env" <<-EOT
		# Set to "1" to enable global Portainer service
		WARDEN_PORTAINER_ENABLE=0
		# Set to "0" to disable DNSMasq
		WARDEN_DNSMASQ_ENABLE=1
		# Set to "1" to enable experimental DNS-over-HTTPS at https://doh.\${WARDEN_SERVICE_DOMAIN:-warden.test}/dns-query
		WARDEN_DNS_OVER_HTTPS_ENABLE=0
		# Set to "0" to disable phpMyAdmin
		WARDEN_PHPMYADMIN_ENABLE=1
		# Set to "0" to disabled Mutagen.  Keep commented out to use System default (Darwin defaults to 1)
		# WARDEN_MUTAGEN_ENABLE=0
	EOT
fi
