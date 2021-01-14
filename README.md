# sage-charts

Helm Charts repository for Sage.

## Prerequisites

- Unix-like OS
- [chart-releaser](https://github.com/helm/chart-releaser) installed and available on the path as `helm-cr`. The recommended way to install chart-releaser is to use ASDF. `asdf plugin-add helm-cr https://github.com/Antiarchitect/asdf-helm-cr.git`
- [pre-commit](https://pre-commit.com/)
- [go-task](https://taskfile.dev)

The container image [Anvil](https://hub.docker.com/r/saicoss/anvil) contains all prerequisites. Here's an example of opening a bash shell in Anvil with your working directory mounted:

```sh
docker run -it --rm \
  --mount type=bind,source=$HOME/.cache,target=/home/anvil/.cache \
  --mount type=bind,source=$HOME/.ssh,target=/home/anvil/.ssh \
  --mount type=bind,source="$(pwd)",target=/home/anvil/workdir \
  --workdir /home/anvil/workdir \
  saicoss/anvil:latest \
  bash
```

Anvil is also what we use as our CI runner.

## Usage

```sh
# Validate everything to make sure nothing is screwed up
task validate

# Run tests
task test

# Package, push, and release new changes
export CR_TOKEN='abc123abc123abc123abc123abc123abc123'
export CR_OWNER='my-org'
export CR_GIT_REPO='my-cool-repo'
export CR_CHARTS_REPO='https://my-org.github.io/my-cool-repo'
task deliver

# Just package
task chart-releaser:package

# Just push
task chart-releaser:upload

# Just release
task chart-releaser:indexAndPush
```

## Notes

1. This project does not support signing charts at this time. It is something we are looking into doing in the future. Please let us know if creating signed charts is something you can't live without.
