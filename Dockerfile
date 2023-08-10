FROM python:3

RUN apt-get update \
&& apt-get install -y \
  sudo \
  whois \
  usbutils \
  cups-filters \
  foomatic-db-compressed-ppds \
  printer-driver-all \
  openprinting-ppds \
  hpijs-ppds \
  hp-ppd \
  hplip \
  smbclient \
  printer-driver-cups-pdf \
&& apt-get clean \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

WORKDIR /httprint
COPY httprint/ .

ENTRYPOINT [ "python", "httprint.py" ]
