#! /bin/bash
rm -rf crypto.upstream/ && \
git clone https://github.com/golang/crypto.git crypto.upstream/ && \
LC_ALL=C find ./crypto.upstream/ -type f -exec sed -i '' -e 's@golang.org/x/crypto@github.com/runZeroInc/sshamble/crypto@g' {} \; && \
rm -f ./crypto.upstream/go.mod ./crypto.upstream/go.sum && \
diff --exclude=.git -ruN crypto.upstream/ crypto/ > crypto.patch && \
rm -rf crypto.upstream/
