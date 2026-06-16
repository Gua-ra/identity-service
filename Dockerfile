# syntax=docker/dockerfile:1.6

##############################
# Build stage
##############################
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /workspace

# Copy Gradle wrapper and build files first for better layer caching
COPY gradlew ./
COPY gradle gradle
COPY build.gradle settings.gradle ./
RUN chmod +x gradlew

# Warm up dependency cache (ignore failure if dependencies task isn't available)
RUN ./gradlew --no-daemon help >/dev/null 2>&1 || true

# Copy source and resources
COPY src src

# Build the fat jar (tests skipped – rely on CI instead)
RUN ./gradlew --no-daemon bootJar -x test

##############################
# Runtime stage
##############################
FROM eclipse-temurin:21-jre
LABEL org.opencontainers.image.source="https://github.com/Gua-ra/identity-service"
WORKDIR /app

# Copy built jar
COPY --from=builder /workspace/build/libs/identity-service-*.jar app.jar

ENV JAVA_OPTS="" \
    SPRING_PROFILES_ACTIVE=prod

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
