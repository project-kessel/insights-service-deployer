#!/bin/bash


echo "HBI Host Count from HBI DB:"
oc rsh $(oc get pods -l app=host-inventory,service=db -o name) psql -h localhost -d host-inventory -c "select count(*) from hbi.hosts"

echo "Resource Count from Kessel DB:"
oc rsh $(oc get pods -l app=kessel-inventory,service=db -o name) psql -h localhost -d kessel-inventory -c "select count(*) from reporter_resources"

echo "Resource Count where Consistencty Token has Updated:"
oc rsh $(oc get pods -l app=kessel-inventory,service=db -o name) psql -h localhost -d kessel-inventory -c "select count(*) from resource where ktn IS NOT NULL"

echo "In general, all above counts should match when replication is complete"
