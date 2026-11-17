#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mvn -q compile dependency:copy-dependencies
exec java -cp 'target/classes:target/dependency/*' com.cookietrace.web.WebServer
