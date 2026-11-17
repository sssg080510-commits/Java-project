FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src src
RUN mvn -B package dependency:copy-dependencies -DskipTests
FROM eclipse-temurin:17-jre
WORKDIR /app
RUN mkdir /app/data && chown 10001:10001 /app/data
COPY --from=build /app/target/classes /app/classes
COPY --from=build /app/target/dependency /app/lib
USER 10001:10001
ENV BIND_ADDRESS=0.0.0.0
EXPOSE 8080
CMD ["java","-cp","classes:lib/*","com.cookietrace.web.WebServer"]
