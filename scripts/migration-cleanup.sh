#!/bin/bash

# Remove connectors
echo "Removing connectors..."
oc delete kctr hbi-migration-connector hbi-outbox-connector

# clean up KIC and Connect
echo "Removing Connect and KIC..."
oc delete app kessel-inventory-consumer
oc delete kc kessel-kafka-connect

# remove connect and migration/outbox topics
echo "Removing topics..."
NAMESPACE=env-$(oc project -q)
BOOTSTRAP_SERVERS=${NAMESPACE}-kafka-bootstrap:9092
for i in kessel-kafka-connect-cluster-configs kessel-kafka-connect-cluster-offsets kessel-kafka-connect-cluster-status host-inventory.hbi.hosts outbox.event.hbi.hosts; do oc rsh $NAMESPACE-kafka-0 /opt/kafka/bin/kafka-topics.sh --delete --bootstrap-server $BOOTSTRAP_SERVERS --topic $i; done

# remove any test hosts from HBI DB
echo "Removing any host records..."
HOST_DB_POD=$(oc get pod --no-headers -o name -l app=host-inventory,service=db,sub=local_db)
oc rsh $HOST_DB_POD psql -d host-inventory -c "delete from hbi.hosts;"

echo "Removing replication slots..."
oc rsh $HOST_DB_POD psql -d host-inventory -c "select pg_drop_replication_slot('debezium_hosts'); select pg_drop_replication_slot('debezium_outbox');"

oc rsh $HOST_DB_POD psql -d host-inventory -c "drop table hbi.outbox; drop table hbi.signal"
echo "Done!"
