# Start from the official Go alpine image
FROM docker.io/library/golang:alpine
# Set WD in container
WORKDIR /app
# Install latest SSHamble from github
RUN go install github.com/runZeroInc/sshamble@latest