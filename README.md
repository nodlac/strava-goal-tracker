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
    - [ ] get and save user timezone
    - [ ] get athlete activities
    - [ ] get activity data 
    - [ ] record activities in database
    - [ ] pull in 2026 performance
    - [ ] refresh data on dashboard load
    - [ ] Sync athlete data button 
    - [ ] build out goals table
    - [ ] build out set goals section
    - [ ] build out dashboard page run calculations for where we should be at
    - [ ] add way to manually set your timezone

    - [x] refesh token on pageload
    - [x] make it so that if you try to login but are already authed it redirects to the dashboard
    - [x] logout endpoint
    - [x] Connect up valkey for session auth
    - [x] create dev startup script that setups up docker and runs air for simplicity
    - [x] setup key refresh script and fire when requests is authed but key is invalid and making a 
            request to strava

# LATER
    - [ ] setup golang-migrate to handle changes to tables
    - [ ] build delete my data function
    - [ ] create privacy policy and terms of use.  
