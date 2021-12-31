FROM blackducksoftware/detect:7-buildless

ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 npm && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --upgrade pip && pip3 install PyGithub && pip3 install -i https://test.pypi.org/simple/ blackduck-scan-action

#ADD *.py /
#ADD BlackDuckUtils/*.py /BlackDuckUtils/

WORKDIR /app

ENTRYPOINT ["blackduck-scan-action"]
CMD ["--help"]
