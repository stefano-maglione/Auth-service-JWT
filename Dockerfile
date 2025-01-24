FROM maven:3.9.6-eclipse-temurin-22 AS build

WORKDIR /app
COPY . .

RUN mvn clean test -X -DskipTests=false surefire-report:report

RUN mvn clean package

FROM eclipse-temurin:22-jdk-alpine
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar
COPY --from=build /app/target/surefire-reports /app/surefire-reports

EXPOSE 8087

ENTRYPOINT ["java", "-jar", "app.jar"]
