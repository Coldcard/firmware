# Docker Build

For deterministic builds, we are using Docker.

Thanks to <https://github.com/lucaszanella/coldcard-docker> for inspiration.

## Background

- Alpine base image
- files in this directory will be visible in container at /work
- no need for git to be pushed, because we clone into container from current checkout


