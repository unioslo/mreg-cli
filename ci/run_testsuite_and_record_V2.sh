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

# build a container image for mreg-cli
docker build -f Dockerfile -t mreg-cli --build-arg python_version=$PYTHON_VERSION ..

# start mreg+postgres in containers
if [[ -n "$GITHUB_ACTIONS" ]]; then
	if [[ "$PODMAN" == "1" ]]; then
		docker compose $GH_PARAMS pull >/dev/null 2>&1
	else
		docker compose $GH_PARAMS pull --quiet
	fi
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
