# This container image is only used temporarily for testing during a CI process.
FROM ubuntu:latest
ARG python_version=3.12

SHELL ["/bin/bash", "-c"]
RUN apt update
RUN apt install -y curl git
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
RUN /root/.local/bin/uv self update
RUN /root/.local/bin/uv python install ${python_version}
COPY . /build
RUN cd /build; /root/.local/bin/uv sync

CMD cd /build/ci; /root/.local/bin/uv run bash -c 'echo "test" | mreg-cli -u test -d example.org --url http://127.0.0.1:8000 --source testsuite --record new_testsuite_log.json --record-without-timestamps -v ERROR >/dev/null'
