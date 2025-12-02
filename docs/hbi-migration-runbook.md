This document describes how to test the HBI migration in the ephemeral environment.

## Prerequisites

- `oc` is installed
- `jq` is installed
- `psql` is installed
- the latest `bonfire` installed
- You have access to the ephemeral environment.
- You have cloned the [insights service deployer repository](https://github.com/project-kessel/insights-service-deployer)

## Steps

### Base Environment Setup

Login to the ephemeral environment.
```bash
oc login --token=<token> --server=<ephemeral-environment-api-url>
```

Via `insights-service-deployer`, deploy the components to the ephemeral environment.
```bash
./deploy.sh deploy.sh
```

> [!IMPORTANT]
> When the deployer script completes, it provides some URL's and auth information for testing purposes. Make sure to capture this info if you intend to test host deletion with the outbox as you'll need it to access the Console UI.

Once completed, next is to setup some users, and add some hosts to HBI. Its important that the hosts are added **before** the migration or outbox Debezium connectors are to ensure these host are treated like existing hosts from the connectors perspective.

```bash
# Add test users and ensure correct permissions are set
./deploy.sh add_users

# Add 10 hosts to HBI in default org
./deploy.sh add_hosts_to_hbi
```


Now, deploy the Kessel Kafka infra including both the migration and outbox connectors:
```bash
./deploy.sh host-replication-kafka
```

### Generate & Insert HBI records

The `add_hosts_to_hbi`step during setup created 10 hosts in the the default org '12345'. This is sufficient enough for basic migration testing, but may not be suitable for larger host migration tests. You can use the same command to add more hosts with some extra params: `./deploy.sh add_hosts_to_hbi 12345 100` for example would add 100 hosts to the org 12345

For more substantial tests, it may be best to leverage HBI's IQE Test Process which can be provided by HBI team on request.

### Start the Migration

To start the HBI migration, you just need to set the host migration connector to `running`

```bash
oc patch kafkaconnector "hbi-migration-connector" --type='merge' -p='{"spec":{"state":"running"}}'
```

### Validating the Migration

To validate the migration, you can check the `kessel-inventory-consumer` and `kessel-inventory-api` pod logs to see the last offset the consumer processed. Below is an examlpe log from the `kessel-inventory-consumer`, the logs for Kessel Inventory will be similar when its done:
```bash
INFO ts=2025-08-06T18:10:20Z caller=log/log.go:30 service.name=inventory-consumer service.version=0.1.0 trace.id= span.id= subsystem=inventoryConsumer msg=consumed event from topic host-inventory.hbi.hosts, partition 0 at offset 9
```

You can also check the replication status by using the `scripts/check-replication-counts.sh` script. This will check both the Host and Kessel databases and capture:
1. The number of hosts in HBI DB
2. The number of resources in Kessel Inventory DB
3. The number of resources in Kessel Inventory DB with a consistency token (ktn) set

When all hosts are fully replicated, these numbers should all match.

### Outbox Replication

> [!WARNING]
> The migration connector and the outbox connector should not both be running at the same time. This will lead to duplicate records created for the same hosts. While there are idempotency checks in place, it can lead to misleading results and errors. Always disable or remove the migration connector before turning on the outbox connector and adding new hosts.

To validate outbox replication, you can do the same process with a couple of minor changes:
1. Disable the migration connector by setting it to `stopped`
```bash
oc patch kafkaconnector "hbi-migration-connector" --type='merge' -p='{"spec":{"state":"stopped"}}'
```

2. Set the outbox connector to `running`
```bash
oc patch kafkaconnector "hbi-outbox-connector" --type='merge' -p='{"spec":{"state":"running"}}'
```

3. Generate outbox records by creating new hosts with `add_hosts_to_hbi` flag

When the hosts are added, you should see the same consumer logs in `kessel-inventory-consumer` and `kessel-inventory-api` which will confirm outbox processing

> [!Note]
> When reviewing logs for kessel inventory consumer, the partitions might be confusing as they'll start over from zero again. This is because a different topic is used which you'll see in the log outbox
>
> `msg=consumed event from topic outbox.event.hbi.hosts, partition 0 at offset 9`

### Testing Host Deletion Replication

To test that deleting a host in HBI properly replicates to Kessel, the easiest method is to access the Development Console UI provided by the deployer and delete in browser

To Delete a Host via UI:
1. Access the dev Console using the `Gateway route` URL provided by the deployer script
2. Login using the `jdoe` user and the provided credentials from the deployer script
3. Click the Services Drop down menu (button says Red Hat Hybrid Cloud Console) and select **Inventories** --> **Inventory** --> **Systems**
4. Click on the host to delete
5. Capture the UUID of the host for validation
6. Click the **Delete** button to delete the host

This will trigger an outbox write which will be captured by the Inventory Consumer and replicated down to Inventory API.

To validate the removal of the host in Inventory, query the Inventory DB for the host

elect * from reporter_resources where local_resource_id = '45e70917-eb1b-46a5-a4af-d693f726498e';

`psql -h localhost -p <local_port> -U <user> -d kessel-inventory -c "select * from reporter_resources where local_resource_id = '<UUID_FROM_CONSOLE_UI>'" -x`

### Resetting the Migration

The easiest way to reset your environment is to `bonfire namespace release` and redeploy from the beginning.

If you are feeling adventurous you can use the `scripts/migration-cleanup.sh` via `insights-service-deployer` to clean up the database and kafka infra. But you will need to redeploy the deleted components manually.

### Troubleshooting

#### Debezium Connector Logs

You can inspect the Debezium connector logs to see if there are any errors snapshotting the HBI table. You will see a Java stack trace if there are any errors. Typically searching by the "Snapshot" keyword will help you find the relevant logs.

```bash
oc logs -f kessel-kafka-connect-connect-0
```

#### Consumer Errors

Consumer errors can happen in two places: The Kessel Inventory Consumer (KIC) and the Kessel Inventory API (KIA).

KIC is responsible for replicating new hosts from HBI into KIA. KIA is responsible for ensuring relations are created in Kessel Relations API and then the consistency token is added to the resource in KIA's DB.

Each consumers logs are pretty verbose on why the consumer is unable to process a message. Review the logs and see what may be causing the issue. The most common issue is the consumer receives a record with missing data that doesnt pass schema validation as defined by HBI [HERE](https://github.com/project-kessel/inventory-api/tree/main/data/schema/resources/host) but missing data may also cause API validation failures as well. The logs will provide data on what issue occured, but if you would like to see the actual event itself, you can do so by accessing Kafka and consuming from the topic using the provided tools:

1. Access the Kessel Kafka Connect pod

```bash
oc rsh kessel-kafka-connect-0
```

2. Determine what offset contains the bad message by looking at current offsets for the topic

```bash
# Note: KAFKA_CONNECT_BOOTSTRAP_SERVERS should already be set in the container -- no extra steps
./bin/kafka-consumer-groups.sh --describe --group kic --bootstrap-server $KAFKA_CONNECT_BOOTSTRAP_SERVERS

# Example Output
GROUP    TOPIC                    PARTITION  CURRENT-OFFSET  LOG-END-OFFSET
kic      outbox.event.hbi.hosts   0          1014            1441
```

In the above output, `CURRENT-OFFSET` indicates the last message offset processed, `LOG-END-OFFSET` captures that last offset that exists in the topic. Based on the current offset, the likely culprit is offset `1015`, we can look at that message by consuming from the topic and searching for that offset

```bash
./bin/kafka-console-consumer.sh --topic <TOPIC-FROM-OUTPUT> --bootstrap-server $KAFKA_CONNECT_BOOTSTRAP_SERVERS --from-beginning --property print.key=true --property print.headers=true --property print.offset=true | grep Offset:<OFFSET-NUMBER>
```

This will print out the event Key, any headers, the offset number and the entire message including message schema. Review the `payload` section of the message for what was captured from the database to determine what data may be missing.

#### Connector Errors

If there are issues with the connectors and nothing is being sent to the consumers, check the state of the connectors (`oc get kafkaconnectors`). If any show "False" in the `READY` column, check the connectors' Kafka Connect pod logs (indicated by the `CLUSTER` column) for any errors.
