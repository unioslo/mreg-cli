#!/bin/bash
cd `dirname $0`

# exit immediately on error
set -e

# clean up on exit, even if something fails
function cleanup {
    docker compose down
}
trap cleanup EXIT

# start mreg+postgres in containers
docker compose up -d

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
echo "test" | mreg-cli -u test -d example.org --url http://127.0.0.1:8000 --source testsuite --record new_output.json >/dev/null
diff testsuite-result.json new_output.json
exit $?
