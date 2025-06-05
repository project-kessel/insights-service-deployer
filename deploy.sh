#!/bin/bash

set -e

login() {
  if [[ -z "${EPHEMERAL_TOKEN}" || -z "${EPHEMERAL_SERVER}" ]]; then
    [[ -z "${EPHEMERAL_TOKEN}" ]] && echo " - EPHEMERAL_TOKEN is not set"
    [[ -z "${EPHEMERAL_SERVER}" ]] && echo " - EPHEMERAL_SERVER is not set"
    exit 1
  fi

  echo "Login.."
  oc login --token="${EPHEMERAL_TOKEN}" --server=${EPHEMERAL_SERVER}
}

release_current_namespace() {
  echo "Releasing current environment.."
  login
  bonfire namespace release `oc project -q`
}

deploy() {
  login
  echo "Deploying..."
  HOST_GIT_COMMIT=$(echo $(git ls-remote https://github.com/RedHatInsights/insights-host-inventory HEAD) | cut -d ' ' -f1)
  HOST_FRONTEND_GIT_COMMIT=$(echo $(git ls-remote https://github.com/RedHatInsights/insights-inventory-frontend HEAD) | cut -d ' ' -f1 | cut -c1-7)
  bonfire deploy host-inventory -F true -p host-inventory/RBAC_V2_FORCE_ORG_ADMIN=true \
  -p host-inventory/URLLIB3_LOG_LEVEL=WARN \
  --ref-env insights-stage \
  -p host-inventory/CONSUMER_MQ_BROKER=rbac-kafka-kafka-bootstrap:9092  \
  --set-template-ref host-inventory="${HOST_GIT_COMMIT}"  \
  -p rbac/V2_APIS_ENABLED=True -p rbac/V2_READ_ONLY_API_MODE=False -p rbac/V2_BOOTSTRAP_TENANT=True \
  -p rbac/REPLICATION_TO_RELATION_ENABLED=True -p rbac/BYPASS_BOP_VERIFICATION=True \
  -p rbac/KAFKA_ENABLED=False -p rbac/NOTIFICATONS_ENABLED=False \
  -p rbac/NOTIFICATIONS_RH_ENABLED=False \
  -p rbac/ROLE_CREATE_ALLOW_LIST="remediations,\
inventory,\
policies,\
advisor,\
vulnerability,\
compliance,\
automation-analytics,\
notifications,\
patch,\
integrations,\
ros,\
staleness,\
config-manager,\
idmsvc" \
  -p rbac/V2_MIGRATION_APP_EXCLUDE_LIST="approval" \
  --set-image-tag quay.io/cloudservices/insights-inventory=latest \
  --set-image-tag quay.io/cloudservices/insights-inventory-frontend="${HOST_FRONTEND_GIT_COMMIT}" \
  --set-image-tag quay.io/redhat-services-prod/hcc-platex-services/chrome-service=latest \
  --set-image-tag quay.io/redhat-services-prod/hcc-accessmanagement-tenant/insights-rbac=latest \
  -p host-inventory/BYPASS_RBAC=false \
  --set-image-tag quay.io/redhat-services-prod/rh-platform-experien-tenant/insights-rbac-ui=latest

  setup_debezium
}

setup_debezium() {
  echo "Debezium is setting up.."
  download_debezium_configuration
  cd scripts
  chmod 0700 kafka.sh
  ./kafka.sh -n `oc project -q`
  cd ..

  RBAC_KAFKA_POD=rbac-kafka-kafka-0
  until oc get pod $RBAC_KAFKA_POD  > /dev/null 2>&1; do
    echo "Waiting for pod ${RBAC_KAFKA_POD} to be created..."
    sleep 5
  done

  oc wait pod $RBAC_KAFKA_POD --for=condition=Ready --timeout=60s

  oc rsh $RBAC_KAFKA_POD /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server=rbac-kafka-kafka-bootstrap:9092 \
  --create --if-not-exists --topic outbox.event.workspace --partitions 3 --replication-factor 1

  # Force re-seed of permissions, roles and groups when we are sure the replication slot has been created in rbac db
  force_seed_rbac_acl_data_in_relations
}

# workaround for the case where seeding attempted before replication slot has been created for debezium and events are lost
force_seed_rbac_acl_data_in_relations() {
  echo "Force (re-)seeding of rbac acl data in kessel..."
  echo "Wait for rbac debezium connector to be ready to ensure replication slot has been created..."
  oc wait kafkaconnector/rbac-connector --for=condition=Ready --timeout=300s
  echo "Run seeding script..."
  RBAC_SERVICE_POD=$(oc get pods -l pod=rbac-service --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
  oc exec -it "$RBAC_SERVICE_POD" --container=rbac-service -- /bin/bash -c "./rbac/manage.py seeds --force-create-relationships" | grep -F 'INFO: ***'

  setup_kessel
}

setup_kessel() {
  echo "Kessel inventory is setting up.."
  bonfire deploy kessel -C kessel-inventory --set-image-tag quay.io/redhat-services-prod/project-kessel-tenant/kessel-inventory/inventory-api=latest

  setup_sink_connector
}

setup_sink_connector() {
  echo "Relations sink connector is setting up.."
  NAMESPACE=`oc project -q`
  BOOTSTRAP_SERVERS=$(oc get svc -n $NAMESPACE -o json | jq -r '.items[] | select(.metadata.name | test("^rbac-kafka.*-kafka-bootstrap")) | "\(.metadata.name).\(.metadata.namespace).svc"')
  RELATIONS_SINK_IMAGE=quay.io/cloudservices/kafka-relations-sink
  IMAGE_TAG=latest
  bonfire deploy kessel -C relations-sink-ephemeral \
   -p relations-sink-ephemeral/NAMESPACE=$NAMESPACE \
   -p relations-sink-ephemeral/RELATIONS_SINK_IMAGE=$RELATIONS_SINK_IMAGE \
   -p relations-sink-ephemeral/BOOTSTRAP_SERVERS=$BOOTSTRAP_SERVERS \
   -p relations-sink-ephemeral/IMAGE_TAG=$IMAGE_TAG

   deploy_unleash_importer_image
}

download_debezium_configuration() {
  RAW_BASE_URL="https://raw.githubusercontent.com/RedHatInsights/insights-rbac/master"
  FILES=(
    "deploy/kafka-connect.yml"
    "deploy/debezium-connector.yml"
    "scripts/kafka.sh"
    "scripts/connector-params.env"
  )

  RAW_BASE_URL="https://raw.githubusercontent.com/RedHatInsights/insights-rbac/master"

  # --- DOWNLOAD ---
  for FILE in "${FILES[@]}"; do
    TARGET="./$FILE"
    DIR_PATH=$(dirname "$TARGET")
    FILE_NAME=$(basename "$FILE")
    URL="$RAW_BASE_URL/$FILE"

    mkdir -p "$DIR_PATH"

    if [[ -f "$TARGET" ]]; then
      echo "Skipping $FILE_NAME (already exists)"
      continue
    fi

    echo "Downloading $FILE_NAME to $DIR_PATH"
    curl -sSL -o "$TARGET" "$URL"
    echo "Saved to $TARGET"
  done
}

clean_download_debezium_configuration() {
  rm -rf deploy
  rm -rf scripts
}

build_unleash_importer_image() {
  # This function can probably be split out of the main deploy in the future, since, if the feature flags rarely change,
  # there will be no need to rebuild the image. By attempting to run it every time for now, we at least test this part
  # of the script. (The build part is pretty quick anyway.)
  echo "Attempting to build and push custom unleash image to set feature flags..."

  if ! hash podman 2>/dev/null; then
    echo "Podman is not installed (and user is also not logged onto quay with podman) -- but don't worry! -- defaulting to pre-built image (quay.io/mmclaugh/kessel-unleash-import:latest) in deployment."
  else
    quay_user=$(podman login --get-login quay.io 2>/dev/null || true)
    if [[ -z "${quay_user}" ]]; then
      echo "Current user is not logged into quay with podman -- but don't worry! -- defaulting to pre-built image (quay.io/mmclaugh/kessel-unleash-import:latest) in deployment."
    else
      IMAGE="quay.io/$quay_user/kessel-unleash-import"
      TAG="latest"
      IMAGE_TAG="$IMAGE:$TAG"
      podman build --platform linux/amd64 . -f docker/Dockerfile.UnleashImporter -t "$IMAGE_TAG"
      podman push "$IMAGE_TAG"
      podman rmi "$IMAGE_TAG"
      echo "Image built, pushed to $IMAGE_TAG and deleted locally."
      echo "Note: Your quay.io repo needs to be public for the image to be pulled for ephemeral deployments!"
      UNLEASH_IMAGE="$IMAGE"
      UNLEASH_TAG="$TAG"
    fi
  fi
}

deploy_unleash_importer_image() {
  echo "Deploy kessel unleash importer image with feature flags..."
  build_unleash_importer_image

  if [[ -z "${UNLEASH_IMAGE}" || -z "${UNLEASH_TAG}" ]]; then
    UNLEASH_IMAGE=quay.io/mmclaugh/kessel-unleash-import
    UNLEASH_TAG=latest
  fi

  # Ensure clowdjobinvocations from a prior run are deleted, so that new bonfire run resets flags
  oc delete --ignore-not-found=true --wait=true clowdjobinvocation/swatch-unleash-import-1

  # Starts the job that runs the unleash feature flag import
  bonfire deploy rhsm --timeout=1800 --optional-deps-method none  \
    --frontends false --no-remove-resources app:rhsm \
    -C rhsm -p rhsm/SWATCH_UNLEASH_IMPORT_IMAGE="$UNLEASH_IMAGE" \
    -p rhsm/SWATCH_UNLEASH_IMPORT_IMAGE_TAG="$UNLEASH_TAG"
}

add_hosts_to_hbi() {
  # Optional arguments: $1: org_id, $2: number of hosts to add
  ORG_ID=12345
  NUM_HOSTS=10

  if [ -n "$1" ]; then
    ORG_ID="$1"
    if [ -n "$2" ]; then
      NUM_HOSTS="$2"
    fi
  fi

  HOST_INVENTORY_READ_POD=$(oc get pods -l pod=host-inventory-service-reads --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
  HOST_INVENTORY_DB_POD=$(oc get pods -l app=host-inventory,service=db,sub=local_db --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
  HBI_BOOTSTRAP_SERVERS=$(oc get svc -o json | jq -r '.items[] | select(.metadata.name | test("^env-ephemeral.*-kafka-bootstrap")) | "\(.metadata.name).\(.metadata.namespace).svc"')
  BEFORE_COUNT=$(oc exec -it "$HOST_INVENTORY_DB_POD" -- /bin/bash -c "psql -d host-inventory -c \"select count(*) from hbi.hosts;\"" | head -3 | tail -1 | tr -d '[:space:]')
  TARGET_COUNT=$((BEFORE_COUNT + NUM_HOSTS))
  AFTER_COUNT=$BEFORE_COUNT

  echo "Sending ${NUM_HOSTS} hosts to hbi using kafka producer..."
  oc exec -it -c host-inventory-service-reads "$HOST_INVENTORY_READ_POD" -- /bin/bash -c 'NUM_HOSTS="$1" KAFKA_BOOTSTRAP_SERVERS="$2" python3 utils/kafka_producer.py' _ "$NUM_HOSTS" "$HBI_BOOTSTRAP_SERVERS"

  until [ "$AFTER_COUNT" == "$TARGET_COUNT" ]; do
    echo "Waiting for ${NUM_HOSTS} hosts added via kafka to sync to the hbi db... [AFTER_COUNT: ${AFTER_COUNT}, TARGET_COUNT: ${TARGET_COUNT}]"
    sleep 3
    AFTER_COUNT=$(oc exec -it "$HOST_INVENTORY_DB_POD" -- /bin/bash -c "psql -d host-inventory -c \"select count(*) from hbi.hosts;\"" | head -3 | tail -1 | tr -d '[:space:]')
  done

  echo "Setting org_id=${ORG_ID} for ${AFTER_COUNT} hosts..."
  oc exec -it "$HOST_INVENTORY_DB_POD" -- /bin/bash -c "psql -d host-inventory -c \"UPDATE hbi.hosts SET org_id='${ORG_ID}';\""
}

add_users_to_hbi() {
  echo "Importing users from data/rbac_users_data.json into hbi..."
  scripts/rbac_load_users.sh
}

wait_for_sink_connector_ready() {
  echo "Waiting for kessel sink connector to be ready..."
  # For some reason, bonfire waits on kafkaconnect/inventory-kafka-connect during kessel-inventory deployment, but not
  # on kafkaconnect/relations-sink during the sink connector deployment.
  oc wait kafkaconnector/relations-sink-connector --for=condition=Ready --timeout=300s
}

show_bonfire_namespace() {
  bonfire namespace describe
}

add_group_role_to_rbac() {
  echo "Creating Group and Role in RBAC from data/rbac_group_role.json"

  echo "Loading users into Keycloak"
  scripts/rbac_load_users.sh

  echo "Creating group, role and principals"
  scripts/rbac_add_group_role.sh
}

usage() {
  echo "Usage: $SCRIPT_NAME {release_current_namespace|deploy|deploy_with_hbi_demo|clean_download_debezium_configuration|deploy_unleash_importer_image|add_hosts_to_hbi|add_users_to_hbi|add_group_role_to_rbac}"
  exit 1
}

case "$1" in
  release_current_namespace)
    release_current_namespace
    ;;
  deploy)
    deploy
    wait_for_sink_connector_ready
    show_bonfire_namespace
    ;;
  deploy_with_hbi_demo)
    deploy
    add_hosts_to_hbi
    add_users_to_hbi
    wait_for_sink_connector_ready
    show_bonfire_namespace
    ;;
  clean_download_debezium_configuration)
    clean_download_debezium_configuration
    ;;
  setup_debezium)
    setup_debezium
    ;;
  add_hosts_to_hbi)
    # $2 is ORG_ID, $3 is the number of hosts to add
    add_hosts_to_hbi "$2" "$3"
    ;;
  add_users_to_hbi)
    add_users_to_hbi
    ;;
  add_group_role_to_rbac)
    add_group_role_to_rbac
    ;;
  *)
    usage
    ;;
esac
