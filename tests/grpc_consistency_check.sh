#!/usr/bin/env bash
# Some gRPC files in this repository are generated and based upon other
# sources. When these sources change, the generated files must be generated
# (and committed) again. It is the task of the contributing user to do this
# properly.
#
# This tests makes sure the generated gRPC files are consistent with its
# sources. If this fails, you probably have to generate the gRPC files again.
#
# Read more here: https://github.com/qdrant/qdrant/blob/master/docs/DEVELOPMENT.md#grpc

set -ex

# Ensure current path is project root
cd "$(dirname "$0")/../"

# Keep current version of file to check
cp ./lib/api/src/grpc/{,.diff.}qdrant.rs

# Regenerate gRPC files
touch ./lib/api/src/grpc/proto/.build-trigger.proto
cargo build --package api

# Ensure generated files are the same as files in this repository
if diff -Zwa ./lib/api/src/grpc/{,.diff.}qdrant.rs
then
    set +x
    echo "No diff found."
else
    set +x
    echo "ERROR: Generated gRPC file is not consistent with files in this repository, see diff above."
    echo "ERROR: See: https://github.com/qdrant/qdrant/blob/master/docs/DEVELOPMENT.md#grpc"
    exit 1
fi

PRIVATE_ORAM_GRPC_METHODS=(
    "/qdrant.PrivateHnswOram/GetPrivateHnswManifest"
    "/qdrant.PrivateHnswOram/UploadPrivateHnswManifest"
    "/qdrant.PrivateHnswOram/UploadPrivateHnswBuckets"
    "/qdrant.PrivateHnswOram/OpenPrivateHnswSession"
    "/qdrant.PrivateHnswOram/ReadPrivateHnswPaths"
    "/qdrant.PrivateHnswOram/CommitPrivateHnswPaths"
    "/qdrant.PrivateHnswOram/ClosePrivateHnswSession"
    "/qdrant.PrivateResultOram/GetPrivateResultOramManifest"
    "/qdrant.PrivateResultOram/UploadPrivateResultOramManifest"
    "/qdrant.PrivateResultOram/UploadPrivateResultOramBuckets"
    "/qdrant.PrivateResultOram/OpenPrivateResultOramSession"
    "/qdrant.PrivateResultOram/ReadPrivateResultOramBuckets"
    "/qdrant.PrivateResultOram/CommitPrivateResultOramBuckets"
    "/qdrant.PrivateResultOram/ClosePrivateResultOramSession"
)

for PRIVATE_ORAM_GRPC_METHOD in "${PRIVATE_ORAM_GRPC_METHODS[@]}"; do
    if ! awk -v method="$PRIVATE_ORAM_GRPC_METHOD" \
        'index($0, method) { found = 1 } END { exit found ? 0 : 1 }' \
        ./lib/api/src/grpc/qdrant.rs
    then
        echo "ERROR: Missing private ORAM gRPC method: $PRIVATE_ORAM_GRPC_METHOD"
        exit 1
    fi
done

# Cleanup
rm -f ./lib/api/src/grpc/{.diff.qdrant.rs,proto/.build-trigger.proto}
