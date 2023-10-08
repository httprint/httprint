# HTTPrint

A very simple web interface to upload and print files.

Server application, allows multiple devices to get prints using code

Runs on docker

## How to

### Docker

Add following settings to your`docker-compose.yml` file:

```yaml
version: '3.7'
services:
  httprint:
    build: https://github.com/httprint/httprint.git
    container_name: httprint
    restart: unless-stopped
    ports:
      - 7777:7777
    volumes:
      - /data/containers/httprint/queue:/httprint/queue
      - /data/containers/httprint/ppd:/httprint/ppd
    environment:
      - TOKEN_LIST=token1,token2

  ```
  
  * `TOKEN_LIST` is a list of tokens used to allow clients to connect.
  * `/httprint/ppd` folder may contain printer's ppd file to use server side spooling

Now you can **point your browser to [http://localhost:7777/](http://localhost:7777/)**


# License and copyright

Copyright 2023 itec <itec@ventuordici.org>, Davide Alberani <da@mimante.net>

Forked from: https://github.com/alberanid/httprint


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Printer icon created by Good Ware - Flaticon
