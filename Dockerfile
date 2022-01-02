FROM blackducksoftware/detect:7

ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 npm && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --upgrade pip && pip3 install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple blackduck-scan-action

#ADD *.py /
#ADD BlackDuckUtils/*.py /BlackDuckUtils/

WORKDIR /app

ENTRYPOINT ["blackduck-scan-action"]
CMD ["--help"]
