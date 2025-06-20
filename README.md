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
# log into ephemeral cluster
oc login --token="${EPHEMERAL_TOKEN}" --server="${EPHEMERAL_SERVER}" 
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