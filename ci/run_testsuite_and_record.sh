#!/bin/bash
cd `dirname $0`

# exit immediately on error
set -e

# clean up on exit, even if something fails
function cleanup {
    docker compose --ansi=never down
}
trap cleanup EXIT

# start mreg+postgres in containers
if [[ -n "$GITHUB_ACTIONS" ]]; then
    docker compose --ansi=never pull --quiet
    docker compose --ansi=never up -d
else
    docker compose up -d
fi

# create a superuser
# TODO: Replace this with python manage.py create_mreg_superuser --username test --password test,
#       but only after we're sure that every branch we want to test has that feature merged in already.
echo -ne '
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
user = get_user_model().objects.create_user(username="test",password="test")
#user = get_user_model().objects.get(username="test")
user.groups.clear()
group, created = Group.objects.get_or_create(name="default-super-group")
group.user_set.add(user)
' | docker exec -i mreg python /app/manage.py shell

# run the test suite
rm -f new_testsuite_log.json
echo "test" | mreg-cli -u test -d example.org --url http://127.0.0.1:8000 --source testsuite --record new_testsuite_log.json --record-without-timestamps -v ERROR >/dev/null

# show a detailed diff (and review if running locally)
if [[ -n "$GITHUB_ACTIONS" ]]; then
    python diff.py testsuite-result.json new_testsuite_log.json
else
    python diff.py testsuite-result.json new_testsuite_log.json --review
fi
exit $?

