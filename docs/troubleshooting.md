# Troubleshooting

## Docker Environment Not Found for Integration Tests

The Integration Tests require a container runtime environment. If you encounter the error "Could not find a valid Docker environment", this typically occurs when:

1. Docker is not running
2. You're using a non-default Docker socket
3. The container socket is not accessible

### Docker Desktop

Ensure Docker Desktop is running:
```bash
docker info
```

If you previously set `DOCKER_HOST`, unset it so Testcontainers can auto-detect:
```bash
unset DOCKER_HOST
```

### For Podman Users

To run the tests with Podman, configure the Docker compatibility socket:

```bash
export DOCKER_HOST=unix://${XDG_RUNTIME_DIR}/podman/podman.sock
mvn clean verify
```

### API Version Mismatch

If you see "client version 1.32 is too old", force a newer Docker API version:

```bash
mvn -Ddocker.api.version=1.44 clean verify
```

### Rootless Docker (Linux)

```bash
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock
mvn clean verify
```
