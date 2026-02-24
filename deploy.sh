#!/bin/bash

set -e

EPHEMERAL_TOKEN=$(oc whoami --show-token)
EPHEMERAL_SERVER=$(oc whoami --show-server)

login() {
  user="$(oc whoami < /dev/null)"
  [[ $? -eq 0 ]] && echo "Skipping login. Already logged in as user: $user" && return 0

  if [[ -z "${EPHEMERAL_TOKEN}" || -z "${EPHEMERAL_SERVER}" ]]; then
    [[ -z "${EPHEMERAL_TOKEN}" ]] && echo " - EPHEMERAL_TOKEN is not set"
    [[ -z "${EPHEMERAL_SERVER}" ]] && echo " - EPHEMERAL_SERVER is not set"
    exit 1
  fi

  echo "Login.."
  oc login --token="${EPHEMERAL_TOKEN}" --server=${EPHEMERAL_SERVER}
}

check_bonfire_namespace() {
  NAMESPACE=`oc project -q 2>/dev/null || true`
  if [[ -z $NAMESPACE || "${NAMESPACE}" == "default" ]]; then
    echo "No bonfire namespace set or using 'default', reserving a namespace for you now (duration 10hr)..."
    bonfire namespace reserve --duration 10h
  fi
}

release_current_namespace() {
  echo "Releasing current environment.."
  login
  bonfire namespace release `oc project -q`
}

# parameters $1: deploy template branch; $2: custom image; $3: custom image tag; $4: local schema file path
deploy() {
  echo "Deploying..."

  NAMESPACE=`oc project -q`

  HBI_CUSTOM_IMAGE="quay.io/cloudservices/insights-inventory"
  HBI_CUSTOM_IMAGE_TAG=latest
  HBI_CUSTOM_IMAGE_PARAMETER=""
  LOCAL_SCHEMA_FILE=""

  if [ -n "$1" ]; then
    HBI_DEPLOYMENT_TEMPLATE_REF="$1"
  else
    HOST_GIT_COMMIT=$(echo $(git ls-remote https://github.com/RedHatInsights/insights-host-inventory HEAD) | cut -d ' ' -f1)
    HBI_DEPLOYMENT_TEMPLATE_REF="$HOST_GIT_COMMIT"
  fi
  if [ -n "$2" ]; then
    HBI_CUSTOM_IMAGE="$2"
    HBI_CUSTOM_IMAGE_PARAMETER="-p host-inventory/IMAGE=${HBI_CUSTOM_IMAGE}"
  fi
  if [ -n "$3" ]; then
    HBI_CUSTOM_IMAGE_TAG="$3"
  fi
  if [ -n "$4" ]; then
    LOCAL_SCHEMA_FILE="$4"
  fi

  HOST_FRONTEND_GIT_COMMIT=$(echo $(git ls-remote https://github.com/RedHatInsights/insights-inventory-frontend HEAD) | cut -d ' ' -f1 | cut -c1-7)
  bonfire deploy host-inventory -F true -p host-inventory/RBAC_V2_FORCE_ORG_ADMIN=true \
  -p host-inventory/URLLIB3_LOG_LEVEL=WARN \
  --ref-env insights-stage \
  --set-template-ref host-inventory="$HBI_DEPLOYMENT_TEMPLATE_REF"  \
  -p rbac/MEMORY_LIMIT=512Mi \
  -p rbac/MEMORY_REQUEST=256Mi \
  -p rbac/RBAC_KAFKA_CONSUMER_REPLICAS=0 \
  -p rbac/V2_APIS_ENABLED=True -p rbac/V2_READ_ONLY_API_MODE=False -p rbac/V2_BOOTSTRAP_TENANT=True \
  -p rbac/REPLICATION_TO_RELATION_ENABLED=True \
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
  ${HBI_CUSTOM_IMAGE_PARAMETER} -p rbac/V2_MIGRATION_APP_EXCLUDE_LIST="approval" \
  -p rbac/V2_MIGRATION_RESOURCE_EXCLUDE_LIST="empty-exclude-list" \
  -p host-inventory/KESSEL_TARGET_URL=kessel-inventory-api.$NAMESPACE.svc.cluster.local:9000 \
  --set-image-tag "${HBI_CUSTOM_IMAGE}=${HBI_CUSTOM_IMAGE_TAG}" \
  --set-image-tag quay.io/redhat-services-prod/rh-platform-experien-tenant/service-accounts="e187df2" \
  --set-image-tag quay.io/cloudservices/insights-inventory-frontend="${HOST_FRONTEND_GIT_COMMIT}" \
  --set-image-tag quay.io/redhat-services-prod/hcc-platex-services/chrome-service=latest \
  --set-image-tag quay.io/redhat-services-prod/hcc-accessmanagement-tenant/insights-rbac=latest \
  -p host-inventory/BYPASS_RBAC=false \
  -p host-inventory/BYPASS_KESSEL=false \
  --set-image-tag quay.io/cloudservices/unleash-proxy=latest \
  --set-image-tag quay.io/redhat-services-prod/rh-platform-experien-tenant/insights-rbac-ui=latest

  setup_rbac_debezium
  apply_schema "$LOCAL_SCHEMA_FILE"
}


setup_rbac_debezium() {
  echo "Debezium is setting up.."
  download_debezium_configuration

  NAMESPACE=env-$(oc project -q)
  oc process -f ./deploy/debezium-connector.yml -p KAFKA_CONNECT_INSTANCE="$NAMESPACE" --param-file=./scripts/connector-params.env | oc apply -f -

  # TODO: remove the following lines with topics set directly in the rbac ClowdApp template, as in
  # https://github.com/tonytheleg/inventory-api/blob/8db7dbbaca054193c19d2cc109fe152a24e51e29/deploy/kessel-inventory-ephem.yaml#L82
  KAFKA_POD="$NAMESPACE"-kafka-0
  oc wait pod "$KAFKA_POD" --for=condition=Ready --timeout=60s
  KAFKA_BOOTSTRAP="$NAMESPACE"-kafka-bootstrap
  oc rsh $KAFKA_POD /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server="$KAFKA_BOOTSTRAP":9092 \
  --create --if-not-exists --topic outbox.event.workspace --partitions 3 --replication-factor 1

  # Force re-seed of permissions, roles and groups when we are sure the replication slot has been created in rbac db
  force_seed_rbac_data_in_relations
}

# workaround for the case where seeding attempted before replication slot has been created for debezium and events are lost
force_seed_rbac_data_in_relations() {
  echo "Force re-seeding of rbac permissions, roles and groups in kessel..."
  echo "Wait for rbac debezium connector to be ready to ensure replication slot has been created..."
  oc wait kafkaconnector/rbac-connector --for=condition=Ready --timeout=300s
  echo "Wait for rbac service deployment..."
  oc rollout status deployment/rbac-service -w
  RBAC_SERVICE_POD=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
  while true; do
    OUTPUT=$(oc exec -it "$RBAC_SERVICE_POD" --container=rbac-service -- /bin/bash -c "./rbac/manage.py seeds --force-create-relationships"  | grep -E 'INFO: \*\*\*|ERROR:')
    EXIT_STATUS=$?
    if [ $EXIT_STATUS -ne 0 ]; then
      echo "Rbac service pod was OOMKilled or was otherwise unavailable when attempting to run the seed script. Trying again..."
      oc rollout status deployment/rbac-service -w
      RBAC_SERVICE_POD=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    else
      break
    fi
  done
  echo "$OUTPUT"

  setup_kessel
  setup_rbac_consumer
}

setup_rbac_consumer() {
  echo "RBAC consumer is setting up.."
  NAMESPACE=`oc project -q`

  bonfire process rbac \
    --source=appsre \
    --set-parameter rbac/RBAC_KAFKA_CONSUMER_TOPIC=outbox.event.relations-replication-event \
    --set-parameter rbac/RBAC_KAFKA_CONSUMER_GROUP_ID=connect-relations-sink-connector \
    -p rbac/MEMORY_LIMIT=512Mi \
    -p rbac/MEMORY_REQUEST=256Mi \
    -p rbac/RBAC_KAFKA_CONSUMER_REPLICAS=1 \
    -p rbac/V2_APIS_ENABLED=True -p rbac/V2_READ_ONLY_API_MODE=False -p rbac/V2_BOOTSTRAP_TENANT=True \
    -p rbac/REPLICATION_TO_RELATION_ENABLED=True \
    -p rbac/KAFKA_ENABLED=True \
    -p rbac/RBAC_KAFKA_CONSUMER_TOPIC=outbox.event.relations-replication-event \
    -p rbac/RBAC_KAFKA_CONSUMER_GROUP_ID=connect-relations-sink-connector \
    -p rbac/NOTIFICATONS_ENABLED=False \
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
    -p rbac/V2_MIGRATION_RESOURCE_EXCLUDE_LIST="empty-exclude-list" \
    --namespace $NAMESPACE | oc apply -f - -n $NAMESPACE
}

setup_kessel() {
  echo "Kessel inventory is setting up.."
  bonfire deploy kessel -C kessel-inventory -C kessel-relations --set-image-tag quay.io/redhat-services-prod/project-kessel-tenant/kessel-inventory/inventory-api=latest -p kessel-relations/SPICEDB_QUANTIZATION_INTERVAL=2.5s -p kessel-relations/SPICEDB_QUANTIZATION_STALENESS_PERCENT=0
}

apply_schema() {
  local LOCAL_SCHEMA_FILE="$1"
  local SCHEMA_FILE="deploy/schema.zed"
  local CLEANUP_SCHEMA=true

  if [ -n "$LOCAL_SCHEMA_FILE" ]; then
    # Use local schema file
    if [ ! -f "$LOCAL_SCHEMA_FILE" ]; then
      echo "❌ ERROR: Local schema file not found: $LOCAL_SCHEMA_FILE"
      exit 1
    fi
    echo "Applying local SpiceDB schema from: $LOCAL_SCHEMA_FILE"
    cp "$LOCAL_SCHEMA_FILE" "$SCHEMA_FILE"
  else
    # Download latest schema from rbac-config (default behavior)
    echo "Applying latest SpiceDB schema from rbac-config"
    curl -H 'Cache-Control: no-cache' -o  "$SCHEMA_FILE" https://raw.githubusercontent.com/RedHatInsights/rbac-config/refs/heads/master/configs/stage/schemas/schema.zed
    if [ $? -ne 0 ]; then
      echo "❌ ERROR: Failed to download schema from rbac-config"
      exit 1
    fi
  fi

  # Delete the schema that was created already
  oc delete configmap spicedb-schema
  # Apply the schema
  oc create configmap spicedb-schema --from-file="$SCHEMA_FILE" -o yaml --dry-run=client | oc apply -f -
  # Ensure the pods are using the new schema
  oc rollout restart deployment/kessel-relations-api
  # Clean up only if we downloaded the file
  # if [ -z "$LOCAL_SCHEMA_FILE" ]; then
  #   rm "$SCHEMA_FILE"
  # fi
}

setup_kessel_inventory_consumer() {
  echo "Kessel Inventory Consumer is setting up.."
  # Add kessel-relations parameters again, otherwise it gets redeployed with default params
  bonfire deploy kessel -C kessel-inventory-consumer -p kessel-relations/SPICEDB_QUANTIZATION_INTERVAL=2.5s -p kessel-relations/SPICEDB_QUANTIZATION_STALENESS_PERCENT=0
}

download_debezium_configuration() {
  RAW_BASE_URL="https://raw.githubusercontent.com/RedHatInsights/insights-rbac/master"
  FILES=(
    "deploy/debezium-connector.yml"
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
      REPO_NAME=kessel-unleash-import
      IMAGE="quay.io/$quay_user/$REPO_NAME"
      TAG="latest"
      IMAGE_TAG="$IMAGE:$TAG"
      podman build --platform linux/amd64 . -f docker/Dockerfile.UnleashImporter -t "$IMAGE_TAG"
      podman push "$IMAGE_TAG"
      if podman rmi "$IMAGE_TAG" 2>/dev/null; then
        echo "Image built, pushed to $IMAGE_TAG and deleted locally."
      else
        echo "Image built and pushed to $IMAGE_TAG (local cleanup skipped - image in use)."
      fi
      UNLEASH_IMAGE="$IMAGE"
      UNLEASH_TAG="$TAG"

      check_quay_repo_public "$quay_user" "$REPO_NAME"
    fi
  fi
}

check_quay_repo_public() {
  echo "Checking visibility of your personal Unleash Quay repo, which needs to be public..."

  local REPO_NAMESPACE="$1"
  local REPO_NAME="$2"

  local API_BASE="https://quay.io/api/v1"
  local REPO_ENDPOINT="$API_BASE/repository/$REPO_NAMESPACE/$REPO_NAME"

  local response
  response=$(curl -s -w "\n%{http_code}" "$REPO_ENDPOINT")
  local body=$(echo "$response" | sed '$d')
  local http_code=$(echo "$response" | tail -n1)

  if [[ "$http_code" == "401" ]]; then
    :
  elif [[ "$http_code" != "200" ]]; then
    echo "❌ Failed to retrieve repository info for '$REPO_NAMESPACE/$REPO_NAME'. HTTP status: $http_code"
    echo "$body"
    echo "This is a bug with the script. Please contact the kessel team!"
    return 1
  fi

  local is_public="false"
  if [[ "$http_code" == "200" ]]; then
    is_public=$(echo "$body" | jq -r '.is_public' 2>/dev/null)
  fi

  if [[ "$is_public" == "true" ]]; then
    echo "✅ Repository is public."
  else
    echo "⚠️ $REPO_NAMESPACE/$REPO_NAME repository looks like it's private."
    echo ""
    echo "  What happened?"
    echo "  If it's the first time you've run this script, and it built and pushed a new unleash"
    echo "  image to manage ephemeral feature flags (based on flags in unleash/unleash_project.json), then you need to manually"
    echo "  change the visibility of the repo to 'public'. Then just re-run the script and you should be good."
    echo ""
    echo "👉 Please make the repository public manually via the Quay.io web console:"
    echo "  1. Go to https://quay.io/repository/$REPO_NAMESPACE/$REPO_NAME"
    echo "  2. Click the 'Settings' tab."
    echo "  3. Change the 'Repository Visibility' to Public."
    return 1
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
  oc exec -it -c host-inventory-service-reads "$HOST_INVENTORY_READ_POD" -- /bin/bash -c 'NUM_HOSTS="$1" INVENTORY_HOST_ACCOUNT="$2" KAFKA_BOOTSTRAP_SERVERS="$3" python3 utils/kafka_producer.py' _ "$NUM_HOSTS" "$ORG_ID" "$HBI_BOOTSTRAP_SERVERS"

  until [ "$AFTER_COUNT" == "$TARGET_COUNT" ]; do
    echo "Waiting for ${NUM_HOSTS} hosts added via kafka to sync to the hbi db... [AFTER_COUNT: ${AFTER_COUNT}, TARGET_COUNT: ${TARGET_COUNT}]"
    sleep 1
    AFTER_COUNT=$(oc exec -it "$HOST_INVENTORY_DB_POD" -- /bin/bash -c "psql -d host-inventory -c \"select count(*) from hbi.hosts;\"" | head -3 | tail -1 | tr -d '[:space:]')
  done
  AFTER_COUNT=$(oc exec -it "$HOST_INVENTORY_DB_POD" -- /bin/bash -c "psql -d host-inventory -c \"select count(*) from hbi.hosts;\"" | head -3 | tail -1 | tr -d '[:space:]')
  echo "Done. [AFTER_COUNT: ${AFTER_COUNT}, TARGET_COUNT: ${TARGET_COUNT}]"
}

create_hbi_connectors() {
  echo "Creating HBI debezium connectors..."
  NAMESPACE=env-$(oc project -q)
  oc process -f https://raw.githubusercontent.com/project-kessel/kessel-kafka-connect/refs/heads/main/deploy/sp-connectors/hbi-hosts-migration-connector.yml \
    -p KAFKA_CONNECT_INSTANCE="kessel-kafka-connect" \
    -p ENV_NAME="$NAMESPACE" \
    -p BOOTSTRAP_SERVERS="${NAMESPACE}-kafka-bootstrap:9092" \
    -p DB_SECRET_NAME="host-inventory-db" | oc apply -f -

  oc process -f https://raw.githubusercontent.com/project-kessel/kessel-kafka-connect/refs/heads/main/deploy/sp-connectors/hbi-outbox-connector.yml \
    -p KAFKA_CONNECT_INSTANCE="kessel-kafka-connect" \
    -p DB_SECRET_NAME="host-inventory-db" | oc apply -f -
}

add_users() {
  echo "Importing users from data/rbac_users_data.json into Keycloak..."
  scripts/rbac_load_users.sh
  echo "Seeding users to RBAC.."
  scripts/rbac_seed_users.sh
}

iqe() {
    bonfire deploy-iqe-cji kessel-inventory --namespace `oc project -q` --debug-pod
}

show_bonfire_namespace() {
  bonfire namespace describe
}

usage() {
  echo "Usage: $SCRIPT_NAME <command> [options]"
  echo ""
  echo "Commands:"
  echo "  release_current_namespace           Release the current bonfire namespace"
  echo "  deploy [template_ref] [image] [tag] [schema_file]"
  echo "                                     Deploy the full stack"
  echo "  deploy_with_hbi_demo               Deploy with demo data"
  echo "  clean_download_debezium_configuration"
  echo "                                     Clean downloaded debezium files"
  echo "  deploy_unleash_importer_image      Deploy unleash importer"
  echo "  add_hosts_to_hbi [org_id] [count]  Add test hosts to HBI"
  echo "  add_users                          Add test users"
  echo "  host-replication-kafka             Set up host replication kafka connectors/consumers"
  echo "  apply-schema  [schema_file]        Applies the schema from the file in the arg, if no arg then the latest one from rbac-config"
  echo ""
  echo "Deploy Options:"
  echo "  template_ref    Git ref for host-inventory deploy template (default: latest commit)"
  echo "  image          Custom host-inventory image (default: quay.io/cloudservices/insights-inventory)"
  echo "  tag            Custom image tag (default: latest)"
  echo "  schema_file    Path to local SpiceDB schema file (default: download from rbac-config)"
  echo ""
  echo "Examples:"
  echo "  $SCRIPT_NAME deploy"
  echo "  $SCRIPT_NAME deploy main quay.io/myrepo/inventory v1.0"
  echo "  $SCRIPT_NAME deploy \"\" \"\" \"\" /path/to/local/schema.zed"
  echo "  $SCRIPT_NAME deploy main quay.io/myrepo/inventory v1.0 ../rbac-config/configs/stage/schemas/schema.zed"
  exit 1
}

case "$1" in
  release_current_namespace)
    release_current_namespace
    ;;
  deploy)
    login
    check_bonfire_namespace
    deploy_unleash_importer_image
    deploy "$2" "$3" "$4" "$5"
    show_bonfire_namespace
    ;;
  deploy_with_hbi_demo)
    login
    check_bonfire_namespace
    deploy_unleash_importer_image
    deploy "$2" "$3" "$4" "$5"
    setup_kessel_inventory_consumer
    create_hbi_connectors
    oc patch kafkaconnector "hbi-outbox-connector" --type='merge' -p='{"spec":{"state":"running"}}'
    add_users
    add_hosts_to_hbi
    apply_schema "$5"
    show_bonfire_namespace
    ;;
  clean_download_debezium_configuration)
    clean_download_debezium_configuration
    ;;
  setup_rbac_debezium)
    setup_rbac_debezium
    ;;
  add_hosts_to_hbi)
    # $2 is ORG_ID, $3 is the number of hosts to add
    add_hosts_to_hbi "$2" "$3"
    ;;
  add_users)
    add_users
    ;;
  deploy_unleash_importer_image)
    deploy_unleash_importer_image
    ;;
  host-replication-kafka)
    setup_kessel_inventory_consumer
    create_hbi_connectors
    ;;
  apply-schema)
    apply_schema "$2"
    ;;
  iqe)
    iqe
    ;;
  *)
    usage
    ;;
esac
