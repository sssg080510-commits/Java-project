#!/bin/sh
# ----------------------------------------------------------------------------
# Maven Wrapper for CookieTrace
# ----------------------------------------------------------------------------
PRG="$0"
while [ -h "$PRG" ]; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done
PROJECT_DIR=`dirname "$PRG"`
PROJECT_DIR=`cd "$PROJECT_DIR" && pwd`

if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/java" ]; then
  if [ -x "$PROJECT_DIR/tools/jdk-17/bin/java" ]; then
    export JAVA_HOME="$PROJECT_DIR/tools/jdk-17"
    export PATH="$JAVA_HOME/bin:$PATH"
  fi
fi

if [ -x "$PROJECT_DIR/tools/maven/bin/mvn" ]; then
  exec "$PROJECT_DIR/tools/maven/bin/mvn" "$@"
fi

if [ -f "$PROJECT_DIR/.mvn/wrapper/maven-wrapper.jar" ]; then
  exec "$JAVA_HOME/bin/java" -jar "$PROJECT_DIR/.mvn/wrapper/maven-wrapper.jar" "$@"
fi

echo "Error: Maven wrapper could not locate Maven executable or wrapper JAR."
exit 1
