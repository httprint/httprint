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
      - CODE_DIGITS=6
      - CODE_EXCLUDE_LIST=0,1
      - KEEP_TIME=60
      - UPLOAD_LIMIT_NUM = 5
      - UPLOAD_LIMIT_SEC = 30

  ```
  
  * `TOKEN_LIST` is a list of tokens used to allow clients to connect. Default empty
  * `CODE_DIGITS` is the number of digits for the code. Default 6
  * `CODE_EXCLUDE_LIST` is a list of numbers excluded from random code generation. Ex: 0,1 doesn't generate codes starting with 0 or 1 
  * `KEEP_TIME` is the number of minutes the document is kept before deletion. Default 12 hours
  * `UPLOAD_LIMIT_NUM` is the max number of uploads in `UPLOAD_LIMIT_SEC` seconds
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
