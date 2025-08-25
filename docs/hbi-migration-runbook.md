This document describes how to test the HBI migration in the ephemeral environment.

## Prerequisites

- `oc` is installed
- `jq` is installed
- `psql` is installed
- You have access to the ephemeral environment.
- You have cloned the [insights service deployer repository](https://github.com/project-kessel/insights-service-deployer)
- You have cloned the [db-generator repository](https://github.com/tonytheleg/db-generator) - this repo is private and **requires access**
    - This repo generates host and outbox HBI records for insertion into the ephemeral environment database

## Steps

### Base Environment Setup

Login to the ephemeral environment.
```bash
oc login --token=<token> --server=<ephemeral-environment-api-url>
```

Via `insights-service-deployer`, deploy the components to the ephemeral environment.
```bash
./deploy.sh deploy
```

Via `insights-service-deployer`, deploy the HBI replication tables and kafka infra to the ephemeral environment.
```bash
# Add tables to HBI db
./deploy.sh host-replication-tables
```
```
# Add kessel kafka infra
./deploy.sh host-replication-kafka
```

### Generate & Insert HBI records
If you don't have host data already generated, generate it from the `db-generator` repository.

The following generates 10 host files with 1000 host records each (hosts are counted in hundreds and multiplied by the number of files). This means the following command will generate 10,000 host records total.
```bash
go run main.go --num-hosts 10 --num-files 10 --type hosts 
```

Grab the host-inventory-db database `user` secret from the ephemeral environment.
```bash
oc get secrets host-inventory-db -o json | jq '.data["db.user"]' -r | base64 -d
```

Now port forward to the host-inventory database, host-inventory-db is the svc name
```bash
oc port-forward service/host-inventory-db 5433:5432
```

Next, insert the HBI records into the ephemeral environment database.
```bash
psql -h localhost -p 5433 -U <user> -d host-inventory -f <path-to-generated-host-file>
```

You can validate the records are inserted by checking the `host-inventory` database:
```bash
psql -h localhost -p 5433 -U <user> -d host-inventory -c "select count(*) from hbi.hosts" -x
```

### Start the Migration

To start the HBI migration, you just need to set the host migration connector to `running`

```bash
oc patch kafkaconnector "hbi-migration-connector" --type='merge' -p='{"spec":{"state":"running"}}'
```

### Validating the Migration

To validate the migration, you can check the `kessel-inventory-consumer` pod logs for the following message:
```bash
INFO ts=2025-08-06T18:10:20Z caller=log/log.go:30 service.name=inventory-consumer service.version=0.1.0 trace.id= span.id= subsystem=inventoryConsumer msg=consumed event from topic host-inventory.hbi.hosts, partition 0 at offset 999
```

To validate database records, you can port-forward and check the `kessel-inventory` database for the following records:

**Get the number of resources in the kessel-inventory database**
```bash
psql -h localhost -p <local_port> -U <user> -d kessel-inventory -c "select count(*) from resources" -x
```

**Check for resources in the kessel-inventory database that do not have a consistency token (should be 0 when migration is complete)**
```bash
psql -h localhost -p <local_port> -U <user> -d kessel-inventory -c "select count(*) from resources where consistency_token != ''" -x
```

### Outbox Replication

To validate outbox replication, you can do the same process with a couple of changes
1. Set the outbox connector to `running` first
```bash
oc patch kafkaconnector "hbi-outbox-connector" --type='merge' -p='{"spec":{"state":"running"}}'
```
2. Generate outbox records via the `db-generator` repository using the `--type outbox` flag

Once you make those changes, you can insert and validate the outbox records are flowing through the same means as the host migration.

### Resetting the Migration

The easiest way to reset your environment is to `bonfire namespace release` and redeploy from the beginning. 

If you are feeling adventurous you can use the `scripts/migration-cleanup.sh` via `insights-service-deployer` to clean up the database and kafka infra. But you will need to redeploy the deleted components manually.

### Troubleshooting

#### Debezium Connector Logs

You can inspect the Debezium connector logs to see if there are any errors snapshotting the HBI table. You will see a Java stack trace if there are any errors. Typically searching by the "Snapshot" keyword will help you find the relevant logs.

```bash
oc logs -f kessel-kafka-connect-connect-0
```

#### Kafka Messages
If you'd like to inspect kafka messages, you can use the following commands...

Note: `KAFKA_CONNECT_BOOTSTRAP_SERVERS` is already set inside the connect pod.

```bash
> oc rsh kessel-kafka-connect-connect-0

# Host migration events
> ./bin/kafka-console/consumer.sh --bootstrap-server $KAFKA_CONNECT_BOOTSTRAP_SERVERS --topic host-inventory.hbi.hosts --property print.key=true --property print.headers=true --from-beginning
 
 OR

# Outbox events
> ./bin/kafka-console/consumer.sh --bootstrap-server $KAFKA_CONNECT_BOOTSTRAP_SERVERS --topic outbox.event.hbi.hosts --property print.key=true --property print.headers=true --from-beginning
```

