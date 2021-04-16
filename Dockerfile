FROM ubuntu:latest

WORKDIR /NMS2021

COPY . /NMS2021
ENV DEBIAN_FRONTEND=noninteractive 
RUN set -xe \
    && apt-get update -y \
    && apt-get install python3-pip -y \
    && apt-get install graphviz -y 
RUN pip3 install --upgrade pip
RUN pip3 install -r requirement.txt                                                                   

EXPOSE 5000

ENTRYPOINT  ["python3"]

CMD ["App.py"]
