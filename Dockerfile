FROM openjdk:11-jdk as build

WORKDIR /kafka-ldap-integration

COPY . .

RUN ./gradlew build test && \
    ./gradlew shadowJar -x test

FROM confluentinc/cp-kafka:7.3.0

COPY --from=build /kafka-ldap-integration/build/libs/kafka-ldap-integration-* /usr/share/java/kafka

ENV KAFKA_OPTS='-Djava.security.auth.login.config=/etc/kafka/kafka_server_jaas.conf'
ENV CLASSPATH="/etc/kafka"
