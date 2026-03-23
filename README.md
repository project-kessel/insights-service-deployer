# insights-service-deployer

Note: Services used here are only available to Red Hat employees

## Prerequisite

- `oc` CLI needs to be installed [Can be downloaded from here](https://console-openshift-console.apps.crc-eph.r9lp.p1.openshiftapps.com/command-line-tools)
- `bonfire` CLI needs to be installed [See installation guide](https://github.com/redhatinsights/bonfire)
- Have access to the ephemeral environment (requires VPN)


## Deploy rbac, HBI service and the Kessel stack with dedicated kafka connect stack (debezium included)

EPHEMERAL_SERVER is typically https://api.crc-eph.r9lp.p1.openshiftapps.com:6443
EPHEMERAL_TOKEN can be obtained from https://oauth-openshift.apps.crc-eph.r9lp.p1.openshiftapps.com/oauth/token/request

```
git clone git@github.com:project-kessel/insights-service-deployer.git
export EPHEMERAL_TOKEN=<> # get token from ephemeral cluster
export EPHEMERAL_SERVER=<> # get server from ephemeral cluster
./deploy.sh deploy
```

Once deployed, the script will return the URL to use to access the console (`Gateway route`) and credentials to use (`Default user login`).

Note: Since this won't deploy all the services, the frontpage has no content beside the menu, this is expected. 

### Customising the deployment

`./deploy.sh deploy` (and `./deploy.sh deploy_with_hbi_demo`) accept additional arguments: 1) a custom bonfire deploy
template from a git ref (e.g. branch) in the insights-host-inventory repo, 2) a custom host-inventory image and 3) a
custom image tag.

Usage:
```shell
/deploy.sh deploy [host-inventory-deploy-branch [custom-image [custom-image-tag]]]
```
e.g.
```shell
./deploy.sh deploy add-kessel-client quay.io/wscalf/host-inventory experiment-and-payload
```

### Debugging

If the deploy looks like it's hanging, check with `oc get pods` to ensure that
no pod is crash looping. A common source of error is that pods are stuck in `ImagePullBackOff`
due to Konflux referencing an image that doesn't exist yet. (The script tries to
tackle this to some degree by requesting `latest` image tags and soon by checking if tags exist.)

## Deploy Compliance

Deploy the compliance service along with rbac (including debezium for replication). Both the compliance and rbac commit SHAs are resolved automatically from their respective GitHub repositories (`compliance-backend` and `insights-rbac`), but the compliance commit can optionally be overridden.

```shell
# Deploy compliance with the latest commits from both repos
./deploy.sh compliance

# Deploy compliance with a specific commit
./deploy.sh compliance <full-compliance-commit-sha>
```

The command will:
1. Fetch the latest commit from [compliance-backend](https://github.com/RedHatInsights/compliance-backend) (or use the provided one)
2. Fetch the latest commit from [insights-rbac](https://github.com/RedHatInsights/insights-rbac)
3. Deploy compliance with the resolved image tags and template refs
4. Apply the SpiceDB schema
5. Set up rbac debezium connectors

## Demo steps for HBI & rbac end-to-end flow with kessel from console

These are the additional steps to get an end-to-end flow from the HBI 
and rbac consoles such that workspaces and hosts can be created and 
access managed with rbac and queried with kessel.

### Deploy and add test data in one command

```shell
./deploy.sh deploy_with_hbi_demo
```
This deploys the components and adds test user and host data

### Deploy and add data in separate steps

1. Ensure the deploy.sh script has run correctly, above.
2. Create test hosts in HBI:
```shell
./deploy.sh add_hosts_to_hbi # adds 10 hosts with org_id 12345 by default
```
or
```shell
./deploy.sh add_hosts_to_hbi 12345 # adds 10 hosts by default with org_id 12345
```
or
```shell
./deploy.sh add_hosts_to_hbi 12345 10 # adds 10 hosts with org_id 12345
```
3. Create test users:
```shell
./deploy.sh add_users # adds users defined in data/rbac_users_data.json to Keycloak and seeds them in RBAC
```
4. Run some checks. e.g. create a workspace in the HBI and check that it replicates into spicedb.

### Notes

#### Unleash Feature Flags Script

1. The script sets Unleash feature flags based on `unleash/unleash_project.json`.  
   It then builds and deploys an image with these feature flags and applies them using **bonfire**.

#### Possible scenarios

#### A. Not Logged into Podman 
(recommended if you don't need to set up your own feature flags)

- The script will use the image from `quay.io/mmclaugh/kessel-unleash-import`, which already contains the feature flags.

#### B. Logged into Podman

- The script will create a repository named `kessel-unleash-import` in **your quay account**.
- **Note:** This may fail the first time — you need to **make the repository public** manually.


### Checks
To check unleash feature flags manually:
```shell
Log in to Unleash at `localhost:4242` with the creds:

  -   user: admin
  -   pass: unleash4all
e.g. check that the `hbi.api.kessel-workspace-migration` in Unleash is on.
```

## Local Development Environment

After deployment, you can develop services locally using Okteto for fast code-reload cycles:

### Prerequisites
- [Okteto CLI](https://www.okteto.com/docs/get-started/install-okteto-cli/) installed
- Local clone of [insights-host-inventory](https://github.com/RedHatInsights/insights-host-inventory)

### Setup
**Important**: You must set the `INSIGHTS_HOST_INVENTORY_REPO_PATH` environment variable to your local insights-host-inventory repository path before using the development environment.

```bash
# Set your local repo path (REQUIRED)
export INSIGHTS_HOST_INVENTORY_REPO_PATH=/path/to/your/insights-host-inventory
```

### Usage
```bash
# Start development mode - interactive service selection
./okteto-dev.sh up

# Or start development mode for a specific service
./okteto-dev.sh up host-inventory-service-reads

# Check status
./okteto-dev.sh check

# Stop development mode
./okteto-dev.sh down

# Daemon mode - start service in background
./okteto-dev.sh up -d host-inventory-service-reads

# Daemon mode with wait - start in background and wait until ready
./okteto-dev.sh up -d -w host-inventory-service-reads

# Start multiple services - background mode, quiet output
./okteto-dev.sh group-up host-inventory-service-reads host-inventory-service-writes
./okteto-dev.sh group-up --all -w # Start all services in the okteto template and wait until ready

# View logs from daemon mode services
./okteto-dev.sh logs host-inventory-service-reads
```

Development containers sync your local code changes and reload automatically (~13 seconds). You can either let okteto provide interactive service selection, or specify one service to start directly. The script handles ClowdApp reconciliation and deployment scaling automatically.

### Available Services

The deployment includes 7 debuggable Python services:

**Message Queue Services** (Process Kafka messages):
- `host-inventory-mq-p1` - Priority 1 message processing
- `host-inventory-mq-pmin` - Minimum priority message processing  
- `host-inventory-mq-sp` - System profile message processing
- `host-inventory-mq-workspaces` - Workspace message processing

**API Services** (Handle HTTP requests):
- `host-inventory-service-reads` - Read-only API operations
- `host-inventory-service-secondary-reads` - Secondary read operations
- `host-inventory-service-writes` - Write API operations

### VS Code/Cursor Debugging Setup

After starting development with `./okteto-dev.sh up [service]`, you can debug the Python services:

1. Copy the debug configuration to your local insights-host-inventory repo:
   ```bash
   cp okteto/vscode/launch.json /path/to/insights-host-inventory/.vscode/
   ```

2. Open your insights-host-inventory repo in VS Code/Cursor

3. Set breakpoints and start debugging using:
   - **Individual services**: Select specific service (e.g., "🔍 Debug: MQ Priority 1", "🔍 Debug: API Reads")
   - **Service groups**: "🔍 Debug: All Message Queue Services" or "🔍 Debug: All API Services"
   - **All services**: "🔍 Debug: All Host Inventory Services"

### Debug Port Mappings

**Message Queue Services**:
- Port 9006 → MQ Priority 1 (`host-inventory-mq-p1`)
- Port 9007 → MQ Priority Min (`host-inventory-mq-pmin`)
- Port 9008 → MQ System Profile (`host-inventory-mq-sp`)
- Port 9009 → MQ Workspaces (`host-inventory-mq-workspaces`)

**API Services**:
- Port 9010 → API Reads (`host-inventory-service-reads`)
- Port 9011 → API Secondary Reads (`host-inventory-service-secondary-reads`)
- Port 9012 → API Writes (`host-inventory-service-writes`)

**Health Check Ports** (MQ services only):
- Port 9000 → MQ Priority 1 health
- Port 9001 → MQ Priority Min health  
- Port 9002 → MQ System Profile health
- Port 9003 → MQ Workspaces health

### Testing Your Setup

For API services, you can test with curl commands like:
```bash
# Test API reads service 
curl -H "x-rh-identity: eyJpZGVudGl0eSI6eyJhY2NvdW50X251bWJlciI6IjEyMzQ1IiwiaW50ZXJuYWwiOnsib3JnX2lkIjoiMTIzNDUifSwidHlwZSI6IlVzZXIiLCJ1c2VyIjp7InVzZXJfaWQiOiJzYXJhIiwiaXNfb3JnX2FkbWluIjp0cnVlfX19" \
     localhost:8002/api/inventory/v1/hosts
```

For MQ services, set breakpoints in `inv_mq_service.py` and related message processing code.

### Debugging Behavior

**MQ Services**: Start immediately and accept debugger connections at any time. You can attach VS Code after the service is running - no waiting required.

**Note**: Ensure the Python extension is installed in VS Code/Cursor for `debugpy` support.