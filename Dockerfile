FROM blackducksoftware/detect:7

ENV PYTHONUNBUFFERED=1
RUN apk add build-base
RUN apk add --update --no-cache python3 npm && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --upgrade pip && pip3 install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple blackduck-scan-action

#ADD *.py /
#ADD BlackDuckUtils/*.py /BlackDuckUtils/

# Add Maven
ARG MAVEN_VERSION=3.6.3
ARG USER_HOME_DIR="/root"
ARG BASE_URL=https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries

# Install Java.
#RUN apk --update --no-cache add openjdk7 curl

RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
 && curl -fsSL -o /tmp/apache-maven.tar.gz ${BASE_URL}/apache-maven-${MAVEN_VERSION}-bin.tar.gz \
 && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
 && rm -f /tmp/apache-maven.tar.gz \
 && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

# Install Dotnet
RUN apk add bash icu-libs krb5-libs libgcc libintl libssl1.1 libstdc++ zlib \
 && curl -fsSL -o /tmp/dotnet-install.sh https://dot.net/v1/dotnet-install.sh \
 && chmod +x /tmp/dotnet-install.sh \
 && /tmp/dotnet-install.sh --channel 5.0 --runtime dotnet
ENV PATH="$PATH:/root/.dotnet"

# scan-action specific
WORKDIR /app

ENTRYPOINT ["blackduck-scan-action"]
CMD ["--help"]
