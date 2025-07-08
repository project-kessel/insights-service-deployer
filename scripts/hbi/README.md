# HBI Demo User and Workspace Management Scripts

This directory contains scripts for setting up and tearing down demo users (e.g., Luke, Leia) and their associated workspaces in the Host-Based Inventory (HBI) system. These scripts are designed to demonstrate Role-Based Access Control (RBAC) by creating users with limited permissions restricted to their own dedicated workspaces.

## Primary Scripts

For most use cases, you should not need to run the scripts in this directory directly. Instead, you should use the main entry point scripts located in the parent `scripts/` directory:

-   `scripts/setup_demo_users.sh`: Orchestrates the setup of all demo users. It calls the individual `setup_*.sh` scripts in this directory to create each user, their workspace, and their specific RBAC permissions.

-   `scripts/teardown_demo_users.sh`: Cleans up the entire demo environment by calling the individual `teardown_*.sh` scripts in this directory to remove all demo users, their workspaces, and all associated RBAC configurations.

### How to Run the Demo Setup

To set up the complete demo environment, run the main script from the `insights-service-deployer` root directory:

```shell
./scripts/setup_demo_users.sh
```

To tear down the demo environment:

```shell
./scripts/teardown_demo_users.sh
```

## Individual User Scripts

The scripts in this directory manage the lifecycle of individual demo users. They are called by the main setup and teardown scripts but can also be run individually for debugging or testing purposes.

-   `setup_luke.sh`: Sets up the "Luke" demo user with a workspace containing 4 hosts and configures RBAC to restrict his access to only those hosts.
-   `setup_leia.sh`: Sets up the "Leia" demo user with a workspace containing 2 hosts from the "Ungrouped Hosts" pool and configures her permissions accordingly.
-   `create_luke_group.sh`, `create_leia_group.sh`: These scripts are responsible for creating the RBAC group, policy, and resource definitions for each user. They are called by the main setup scripts.
-   `teardown_luke.sh`, `teardown_leia.sh`: These scripts remove all RBAC configurations and workspaces associated with each user, effectively cleaning up their environments. 