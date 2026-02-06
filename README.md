# Dev Valkey Setup
## If you get a daemon not running
```
sudo systemctl start docker
```

## Start the container
```
docker run valkey-server
```

## First run
``` 
docker run -d \
  --name valkey-server \
  -p 6379:6379 \
  -v valkey_data:/data \
  valkey/valkey:latest \
  valkey-server 
```


# prod valkey-server setup
``` 
docker run -d \
  --name valkey-server \
  -p 6379:6379 \
  --restart always \
  -v valkey_data:/data \
  valkey/valkey:latest \
  valkey-server --requirepass "StrongPassword" --appendonly yes
```

# TODO: 
    - [ ] create dev startup script that setups up docker and runs air for simplicity
    - [ ] Connect up valkey for session auth
    - [ ] Start figuring out how to pull in data from Strava

# LATER
    - [ ] build delete my data function
    - [ ] create privacy policy and terms of use.  
