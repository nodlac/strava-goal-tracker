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
    - [x] make it so that if you try to login but are already authed it redirects to the dashboard
    - [x] logout endpoint
    - [x] refesh token on pageload
    - [ ] get athlete activities
    - [ ] get activity data 
    - [ ] record activities in database
    - [ ] pull in 2026 performance
    - [ ] refresh data on dashboard load
    - [ ] Sync athlete data button 
    - [ ] build out goals table
    - [ ] build out set goals section
    - [ ] build out dashboard page run calculations for where we should be at
    - [x] Connect up valkey for session auth
    - [x] create dev startup script that setups up docker and runs air for simplicity

# LATER
    - [ ] build delete my data function
    - [ ] create privacy policy and terms of use.  
