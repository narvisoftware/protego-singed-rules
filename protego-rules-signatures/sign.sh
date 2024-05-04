#!/bin/bash
set -x

RUN_DIR=$(pwd)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo Scrip is running in: $RUN_DIR
echo Script is located in: $SCRIPT_DIR

cd $SCRIPT_DIR
mvn clean package exec:java -Dexec.args="$RUN_DIR"

java -cp $SCRIPT_DIR/target/classes/:. app.narvi.protego.signatures.CreateSignature "$RUN_DIR" "$SCRIPT_DIR" "$@"