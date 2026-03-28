#!/usr/bin/env bash
[[ ! ${WARDEN_DIR} ]] && >&2 echo -e "\033[31mThis script is not intended to be run directly!\033[0m" && exit 1

source "${WARDEN_DIR}/utils/core.sh"

function isWsl () {
  [[ -n "${WSL_DISTRO_NAME:-}" ]] && return 0
  [[ -r /proc/sys/kernel/osrelease ]] && grep -qiE '(microsoft|wsl)' /proc/sys/kernel/osrelease && return 0
  [[ -r /proc/version ]] && grep -qiE '(microsoft|wsl)' /proc/version && return 0
  return 1
}

function hasWindowsCertificateBridge () {
  isWsl && command -v powershell.exe >/dev/null 2>&1
}

function runWindowsPowerShellScript () {
  local script_path="${1}"
  shift

  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${script_path}" "$@" | tr -d '\r'
}

function toWindowsPath () {
  wslpath -w "$(realpath "${1}")"
}

function sendWindowsNotification () {
  local title="${1}"
  local message="${2}"
  local level="${3:-Info}"

  hasWindowsCertificateBridge || return 0

  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden \
    -File "$(toWindowsPath "${WARDEN_DIR}/utils/windows/show-notification.ps1")" \
    -Title "${title}" \
    -Message "${message}" \
    -Level "${level}" >/dev/null 2>&1 || true
}

function getWindowsCertificateThumbprint () {
  local cert_path="${1}"
  local windows_cert_path thumbprint

  [[ -f "${cert_path}" ]] || return 1

  windows_cert_path="$(wslpath -w "${cert_path}")" || return 1
  thumbprint="$(runWindowsPowerShellScript "$(toWindowsPath "${WARDEN_DIR}/utils/windows/get-certificate-thumbprint.ps1")" -CertificatePath "${windows_cert_path}")" || return 1
  [[ -n "${thumbprint}" ]] || return 1

  echo "${thumbprint}"
}

function getWindowsRootCaStoreState () {
  local cert_path="${1}"
  local windows_cert_path store_state

  [[ -f "${cert_path}" ]] || return 1

  windows_cert_path="$(wslpath -w "${cert_path}")" || return 1
  store_state="$(runWindowsPowerShellScript "$(toWindowsPath "${WARDEN_DIR}/utils/windows/get-root-store-state.ps1")" -CertificatePath "${windows_cert_path}")" || return 1
  [[ -n "${store_state}" ]] || return 1

  echo "${store_state}"
}

function trustRootCaInWindowsStore () {
  local cert_path="${1}"
  local store_location="${2}"
  local windows_cert_path trust_status

  [[ -f "${cert_path}" ]] || return 1
  [[ "${store_location}" =~ ^(CurrentUser|LocalMachine)$ ]] || return 1

  windows_cert_path="$(wslpath -w "${cert_path}")" || return 1
  trust_status="$(runWindowsPowerShellScript "$(toWindowsPath "${WARDEN_DIR}/utils/windows/trust-root-store.ps1")" -CertificatePath "${windows_cert_path}" -StoreLocation "${store_location}")" || return 1
  [[ "${trust_status}" =~ ^(present|imported|replaced|access_denied|policy_blocked|store_error)$ ]] || return 1

  echo "${trust_status}"
}

function trustRootCaInWindowsLocalMachineElevated () {
  local cert_path="${1}"
  local windows_cert_path cert_thumbprint powershell_script elevate_status
  local import_script_path

  [[ -f "${cert_path}" ]] || return 1

  windows_cert_path="$(wslpath -w "${cert_path}")" || return 1
  cert_thumbprint="$(getWindowsCertificateThumbprint "${cert_path}")" || return 1
  import_script_path="$(toWindowsPath "${WARDEN_DIR}/utils/windows/import-root-localmachine.ps1")" || return 1

  read -r -d '' powershell_script <<-EOT || true
		& {
		  \$certPath = '${windows_cert_path}'
		  \$thumbprint = '${cert_thumbprint}'
		  \$scriptPath = [System.IO.Path]::Combine(\$env:TEMP, 'Warden-Import-Root-Certificate-' + [guid]::NewGuid().ToString() + '.ps1')
		  \$statusPath = [System.IO.Path]::Combine(\$env:TEMP, 'warden-rootca-import-' + [guid]::NewGuid().ToString() + '.txt')
		  \$tempCertPath = [System.IO.Path]::Combine(\$env:TEMP, 'warden-rootca-' + [guid]::NewGuid().ToString() + '.pem')
		  Copy-Item \$certPath \$tempCertPath -Force
		  Copy-Item '${import_script_path}' \$scriptPath -Force

		  try {
		    try {
		      \$process = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @(
		        '-NoProfile',
		        '-ExecutionPolicy',
		        'Bypass',
		        '-File',
		        \$scriptPath,
		        '-CertificatePath',
		        \$tempCertPath,
		        '-Thumbprint',
		        \$thumbprint,
		        '-StatusPath',
		        \$statusPath
		      )
		    } catch {
		      if (\$_.Exception.Message -match 'cancelled by the user') {
		        Write-Output 'elevation_cancelled'
		        return
		      }
		      Write-Output 'elevation_failed'
		      return
		    }

		    if (\$process.ExitCode -ne 0) {
		      Write-Output 'elevation_failed'
		      return
		    }

		    if (-not (Test-Path \$statusPath)) {
		      Write-Output 'elevation_failed'
		      return
		    }

		    \$status = Get-Content -Path \$statusPath -Raw
		    if (\$status -eq 'policy_blocked') {
		      Write-Output 'policy_blocked'
		      return
		    }

		    if (\$status -ne 'imported') {
		      Write-Output 'elevation_failed'
		      return
		    }

		    \$verifyStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
		    \$verifyStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
		    try {
		      \$verified = \$verifyStore.Certificates | Where-Object { \$_.Thumbprint -eq \$thumbprint }
		      if (\$verified) {
		        Write-Output 'imported'
		      } else {
		        Write-Output 'elevation_failed'
		      }
		    } finally {
		      \$verifyStore.Close()
		    }
		  } finally {
		    Remove-Item -Path \$scriptPath -ErrorAction SilentlyContinue
		    Remove-Item -Path \$statusPath -ErrorAction SilentlyContinue
		    Remove-Item -Path \$tempCertPath -ErrorAction SilentlyContinue
		  }
		}
	EOT

  elevate_status="$(powershell.exe -NoProfile -NonInteractive -Command "${powershell_script}" | tr -d '\r')" || return 1
  [[ "${elevate_status}" =~ ^(imported|elevation_cancelled|elevation_failed|policy_blocked)$ ]] || return 1

  echo "${elevate_status}"
}

function trustRootCaInWindows () {
  local cert_path="${1}"
  local local_machine_status elevated_status current_user_status

  local_machine_status="$(trustRootCaInWindowsStore "${cert_path}" "LocalMachine")" || return 1

  if [[ "${local_machine_status}" == "policy_blocked" ]] || [[ "${local_machine_status}" == "store_error" ]]; then
    current_user_status="$(trustRootCaInWindowsStore "${cert_path}" "CurrentUser")" || return 1
    echo "localmachine_${local_machine_status}_${current_user_status}"
  elif [[ "${local_machine_status}" == "access_denied" ]]; then
    elevated_status="$(trustRootCaInWindowsLocalMachineElevated "${cert_path}")" || return 1
    if [[ "${elevated_status}" == "imported" ]]; then
      echo "localmachine_imported_via_elevation"
      return 0
    fi

    current_user_status="$(trustRootCaInWindowsStore "${cert_path}" "CurrentUser")" || return 1
    echo "localmachine_${elevated_status}_${current_user_status}"
  else
    echo "localmachine_${local_machine_status}"
  fi
}

function installSshConfig () {
  if ! grep '## WARDEN START ##' /etc/ssh/ssh_config >/dev/null; then
    echo "==> Configuring sshd tunnel in host ssh_config (requires sudo privileges)"
    echo "    Note: This addition to the ssh_config file can sometimes be erased by a system"
    echo "    upgrade requiring reconfiguring the SSH config for tunnel.warden.test."
    cat <<-EOT | sudo tee -a /etc/ssh/ssh_config >/dev/null

			## WARDEN START ##
			Host tunnel.warden.test
			HostName 127.0.0.1
			User user
			Port 2222
			IdentityFile ~/.warden/tunnel/ssh_key
			## WARDEN END ##
			EOT
  fi
}

function assertWardenInstall {
  if [[ ! -f "${WARDEN_HOME_DIR}/.installed" ]] \
    || [[ "${WARDEN_HOME_DIR}/.installed" -ot "${WARDEN_DIR}/bin/warden" ]]
  then
    [[ -f "${WARDEN_HOME_DIR}/.installed" ]] && echo "==> Updating warden" || echo "==> Starting initialization"

    "${WARDEN_DIR}/bin/warden" install

    [[ -f "${WARDEN_HOME_DIR}/.installed" ]] && echo "==> Update complete" || echo "==> Initialization complete"
    date > "${WARDEN_HOME_DIR}/.installed"
  fi

  ## append settings for tunnel.warden.test in /etc/ssh/ssh_config
  #
  # NOTE: This function is called on every invocation of this assertion in an attempt to ensure
  # the ssh configuration for the tunnel is present following it's removal following a system
  # upgrade (macOS Catalina has been found to reset the global SSH configuration file)
  #

  installSshConfig
}
