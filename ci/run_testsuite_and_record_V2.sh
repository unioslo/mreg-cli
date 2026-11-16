#!/bin/bash

# exit immediately on error
set -e

# check if we have docker or podman
if command -v docker >/dev/null 2>&1 && ! docker 2>&1 | grep -q podman; then
	echo "Using Docker"
	GH_PARAMS="--ansi=never"
elif command -v podman >/dev/null 2>&1; then
	echo "Using Podman"
	GH_PARAMS="--no-ansi"
	PODMAN=1
	alias docker=podman
else
	echo "Found neither docker nor podman."
	exit 1
fi

# clean up on exit, even if something fails
function cleanup {
	set +e
	if [[ -n "$GITHUB_ACTIONS" ]]; then
		docker compose $GH_PARAMS down
	else
		docker compose down
	fi
	docker ps -a | grep "mreg-" | awk '{print $1}' | xargs -r docker stop
	docker ps -a | grep "mreg-" | awk '{print $1}' | xargs -r docker rm
	docker images | grep "mreg-" | awk '{print $1}' | xargs -r docker rmi
	echo "cleanup done."
}
trap cleanup EXIT

# chdir to where this script is
cd `dirname $0`

# get Python version from argument
PYTHON_VERSION=3.12
if [ ! -z "$1" ]; then
	PYTHON_VERSION=$1
fi
echo "Python version $PYTHON_VERSION"

# get mreg image in order of argument > environment variable > default
if [ -n "$2" ]; then
	MREG_IMAGE=$2
elif [ -z "$MREG_IMAGE" ]; then
	MREG_IMAGE="ghcr.io/unioslo/mreg:master"
fi
export MREG_IMAGE

if [[ -n "$GITHUB_ACTIONS" ]]; then
	echo "::notice::Using MREG image: $MREG_IMAGE"
else
	echo "Using MREG image: $MREG_IMAGE"
fi

# List the files to include in the build context: .git (needed by setuptools_scm),
# plus all files tracked by git. `--exclude-standard` ensures both repo .gitignore
# as well as global .gitignore is respected.
function context_files {
	printf '.git\0'
	git ls-files -z --cached --others --exclude-standard
}

# Write the build context as a tar archive to stdout.
function build_context {
	cd "$(git rev-parse --show-toplevel)"
	context_files | tar --null --files-from=- -cf -
}

# build a container image for mreg-cli
# docker and podman both accept a tar archive on stdin as the build context
build_context | docker build -f ci/Dockerfile -t mreg-cli --build-arg python_version=$PYTHON_VERSION -

# arm64 hosts refuse to pull amd64-only mreg images without an explicit platform.
# Force amd64 only if the published image has no arm64 variant, so we switch to
# native images automatically once they exist. Only applies to the mreg service
# (see docker-compose.yml), so postgres and mreg-cli always stay native.
if [[ -z "$MREG_PLATFORM" && "$(uname -m)" =~ ^(arm64|aarch64)$ && "$MREG_IMAGE_PULL_POLICY" != "never" ]] &&
	! docker manifest inspect "$MREG_IMAGE" 2>/dev/null | grep -q '"architecture": *"arm64"'; then
	export MREG_PLATFORM=linux/amd64
fi

# start mreg+postgres in containers
if [[ -n "$GITHUB_ACTIONS" ]]; then
	docker compose $GH_PARAMS up -d
else
	docker compose up -d
fi

# give mreg some time to create the database schema and start up
sleep 5

# create a superuser
if docker exec -t mreg uv version >/dev/null; then
	docker exec -t mreg uv run /app/manage.py create_mreg_superuser --username test --password test
else
	docker exec -t mreg /app/manage.py create_mreg_superuser --username test --password test
fi

# test connectivity
#docker run --rm --tty --network host --entrypoint curl mreg-cli --head http://127.0.0.1:8000/admin/login/

# start the mreg-cli container, which will automatically run the test suite
echo "Running the tests..."
docker run --name mreg-cli --network host --tty mreg-cli
docker commit mreg-cli finished-mreg-tests # because inside is the file new_testsuite_log.json which we want to look at

# show a detailed diff (and review if running locally)
# Override UV_NO_DEV to ensure we install dev dependencies for the diff script
DIFF_CMD="UV_NO_DEV=0 /root/.local/bin/uv run diff.py"
if [[ -n "$GITHUB_ACTIONS" ]]; then
	docker run --rm --tty --entrypoint bash finished-mreg-tests -c "cd /build/ci; $DIFF_CMD testsuite-result.json new_testsuite_log.json"
	exit $?
else
	set +e
	docker run -it --name finished-mreg-tests --entrypoint bash finished-mreg-tests -c "cd /build/ci; $DIFF_CMD testsuite-result.json new_testsuite_log.json --review"
	EXITCODE=$?
	docker cp finished-mreg-tests:/build/ci/new_testsuite_log.json .
	docker cp finished-mreg-tests:/build/ci/testsuite-result.json .
	exit $EXITCODE
fi
