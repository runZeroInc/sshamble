#! /bin/bash
if [[ ! -e crypto.patch ]]; then 
    echo "missing crypto.patch, run crypto.rediff.sh first"
    exit 1
fi

rm -rf crypto.upstream/ && \
git clone https://github.com/golang/crypto.git crypto.upstream/ && \
LC_ALL=C find ./crypto.upstream/ -type f -exec sed -i '' -e 's@golang.org/x/crypto@github.com/runZeroInc/sshamble/crypto@g' {} \; && \
rm -f ./crypto.upstream/go.mod ./crypto.upstream/go.sum && \
rm -rf crypto.upstream/.git/ && \
rm -rf crypto/ && \
mv crypto.upstream/ crypto/ && \
patch -p0 < crypto.patch