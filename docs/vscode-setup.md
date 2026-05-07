# VSCode Setup

This guide sets up VSCode for local development of `mini-soc-siem-lab` on
Windows.

## 1. Install Required Tools

Run PowerShell as Administrator:

```powershell
winget install --id Microsoft.VisualStudioCode -e
winget install --id Git.Git -e
winget install --id Python.Python.3.11 -e
winget install --id OpenJS.NodeJS.LTS -e
winget install --id Docker.DockerDesktop -e
```

If Docker Desktop asks for WSL, install it and reboot if prompted:

```powershell
wsl --install
```

Open a new PowerShell window and verify:

```powershell
code --version
git --version
python --version
node --version
npm --version
docker --version
docker compose version
```

## 2. Open the Project

```powershell
cd "C:\Users\nekow\develop\mini-soc-siem-lab"
code mini-soc-siem-lab.code-workspace
```

If `code` is not found, open VSCode manually, press `Ctrl+Shift+P`, run
`Shell Command: Install 'code' command in PATH`, then open a new PowerShell
window.

## 3. Install Recommended Extensions

VSCode should prompt you to install recommended extensions. You can also run:

```powershell
code --install-extension ms-python.python
code --install-extension ms-python.debugpy
code --install-extension charliermarsh.ruff
code --install-extension ms-azuretools.vscode-docker
code --install-extension redhat.vscode-yaml
code --install-extension github.vscode-github-actions
code --install-extension dbaeumer.vscode-eslint
code --install-extension esbenp.prettier-vscode
```

## 4. Create Python Environment

From the VSCode terminal:

```powershell
cd "C:\Users\nekow\develop\mini-soc-siem-lab"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

Then choose the interpreter:

1. Press `Ctrl+Shift+P`.
2. Select `Python: Select Interpreter`.
3. Choose `.venv\Scripts\python.exe`.

### Troubleshooting: `python` Only Prints `Python`

If `python -m venv .venv` only prints `Python` and does not create
`.venv\Scripts\python.exe`, Windows is probably using the Microsoft Store app
execution alias instead of a real Python installation.

Check it:

```powershell
where.exe python
python --version
```

If the path contains `WindowsApps`, install Python and open a new PowerShell:

```powershell
winget install --id Python.Python.3.11 -e
```

If it still resolves to `WindowsApps`, disable the aliases:

1. Open Windows Settings.
2. Go to `Apps > Advanced app settings > App execution aliases`.
3. Turn off `python.exe` and `python3.exe`.
4. Open a new PowerShell and run `python --version` again.

Then recreate the virtual environment from the project directory:

```powershell
cd "C:\Users\nekow\develop\mini-soc-siem-lab"
Remove-Item -Recurse -Force .venv -ErrorAction SilentlyContinue
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

## 5. Install Frontend Dependencies

```powershell
cd dashboard
npm install
cd ..
```

### Troubleshooting: `npm` Is Not Recognized

If PowerShell says `npm` is not recognized, install Node.js LTS:

```powershell
winget install --id OpenJS.NodeJS.LTS -e
```

Close all PowerShell and VSCode terminals, open a new PowerShell, then verify:

```powershell
node --version
npm --version
where.exe node
where.exe npm
```

Expected paths usually look like:

```text
C:\Program Files\nodejs\node.exe
C:\Program Files\nodejs\npm.cmd
```

If Node.js is already installed but `npm` is still missing, repair the PATH for
the current terminal:

```powershell
$env:Path += ";C:\Program Files\nodejs"
node --version
npm --version
```

Then run the dashboard install again:

```powershell
cd "C:\Users\nekow\develop\mini-soc-siem-lab\dashboard"
npm install
```

## 6. Run Tests and Checks

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check backend scripts vulnerable-web-app
cd dashboard
npm run build
cd ..
docker compose config
```

The same commands are available in VSCode through `Terminal > Run Task`.

## 7. Run the Full Docker Lab

```powershell
copy .env.example .env
docker compose up --build
```

Open:

- Web app: http://localhost:8080
- Detector API docs: http://localhost:8001/docs
- Dashboard: http://localhost:3000

### Troubleshooting: Docker API / `docker_engine` Not Found

If `docker compose up --build` shows an error like:

```text
failed to connect to the docker API at npipe:////./pipe/docker_engine
```

Docker Desktop is installed but the Docker engine is not running, or Docker
Desktop has not finished starting.

Check Docker:

```powershell
docker --version
docker compose version
docker info
```

If `docker info` fails, start Docker Desktop from the Start menu and wait until
it says Docker is running. Then try:

```powershell
docker info
docker compose up --build
```

### Troubleshooting: Virtualization Support Not Detected

If Docker Desktop shows `Virtualization support not detected`, Docker cannot
start its Linux engine. This is a Windows/BIOS setting issue, not an application
code issue.

First check Windows:

```powershell
systeminfo | Select-String "Virtualization|Hyper-V"
```

Also open Task Manager, go to `Performance > CPU`, and check whether
`Virtualization` is `Enabled`.

Enable required Windows features from an Administrator PowerShell:

```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
dism.exe /online /enable-feature /featurename:HypervisorPlatform /all /norestart
wsl --install
wsl --update
wsl --set-default-version 2
bcdedit /set hypervisorlaunchtype auto
```

Then reboot Windows and start Docker Desktop again.

If virtualization is still disabled, enable it in BIOS/UEFI:

- Intel: enable `Intel Virtualization Technology`, `VT-x`, or `VT-d`
- AMD: enable `SVM Mode` or `AMD-V`

After saving BIOS/UEFI settings and rebooting, confirm:

```powershell
docker info
```

If Task Manager already shows virtualization as enabled but Docker Desktop still
shows the same error, verify the Windows virtualization features and boot
configuration:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
bcdedit /enum | findstr /i hypervisorlaunchtype
wsl --status
wsl -l -v
```

Enable the common WSL 2 backend requirements from an Administrator PowerShell:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart
bcdedit /set hypervisorlaunchtype auto
wsl --update
wsl --set-default-version 2
```

Then reboot Windows. After rebooting:

```powershell
wsl --status
docker info
```

If `WSL2 is not supported with your current machine configuration` appears even
when Task Manager shows virtualization is enabled, run these commands from an
Administrator PowerShell and reboot:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart
bcdedit /set hypervisorlaunchtype auto
wsl --install --no-distribution
wsl --update
shutdown /r /t 0
```

After Windows starts again, check:

```powershell
wsl --status
wsl -l -v
docker info
```

If Docker Desktop asks for WSL 2 support, install or update WSL:

```powershell
wsl --install
wsl --update
```

Then reboot Windows, start Docker Desktop again, and rerun:

```powershell
cd "C:\Users\nekow\develop\mini-soc-siem-lab"
docker compose up --build
```

## 8. Generate Demo Alerts

In a second terminal:

```powershell
.\.venv\Scripts\python.exe scripts\generate_sample_logs.py --send
curl.exe -X POST http://localhost:8001/detect/run
curl.exe http://localhost:8001/alerts
```

You can also use VSCode tasks:

- `Demo: ingest sample logs`
- `Demo: run detection`

## 9. Debug Without Docker

Use the VSCode Run and Debug panel:

- `Detector API: local SQLite`
- `Vulnerable Web App: local`

The detector debug profile uses SQLite at `backend/local-dev.db`, which is useful
for quick API debugging without starting PostgreSQL.
