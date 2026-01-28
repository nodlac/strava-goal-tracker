# Valkey script 

```
#!/bin/bash

# 1. Setup the "Virtual Wire"
docker network create app-network || true

# 2. Start Valkey
docker run -d \
  --name valkey-server \
  --network app-network \
  -v valkey_data:/data \
  valkey/valkey:latest \
  valkey-server --requirepass "StrongPassword"

# 3. Build and Run Go App
docker build -t my-go-app .
docker run -d \
  --name my-go-app \
  --network app-network \
  -e VALKEY_ADDR="valkey-server:6379" \
  my-go-app

```


# TODO: 
    - [ ] build delete my data function
    - [ ] create privacy policy and terms of use. 
