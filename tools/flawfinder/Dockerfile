# Container image that runs your code
FROM python:3

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY entrypoint.py /entrypoint.py

RUN pip install flawfinder

# Code file to execute when the docker container starts up (`entrypoint.py`)
ENTRYPOINT ["python3", "/entrypoint.py"]
