# This container image is only used temporarily for testing during a CI process.
FROM ubuntu:latest
ARG python_version=3.12

# Disable dev dependencies to ensure parity with pypi package installs
ENV UV_NO_DEV=1

RUN apt-get -qq update
RUN apt-get -y install curl git >/dev/null
RUN curl -LsSf https://astral.sh/uv/0.5.6/install.sh | sh
RUN /root/.local/bin/uv self update -q
RUN /root/.local/bin/uv python install ${python_version}
COPY . /build
RUN cd /build; /root/.local/bin/uv sync -q

CMD cd /build/ci; /root/.local/bin/uv run bash -c 'echo "test" | mreg-cli -u test -d example.org --url http://127.0.0.1:8000 --source testsuite --record new_testsuite_log.json --record-without-timestamps -v ERROR >/dev/null'
