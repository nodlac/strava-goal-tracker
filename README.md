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
- [ ] pull in metric preference "measurement_preference"
- [ ] only save user data on initial login
- [ ] setup webhook for activity creation so that you only need to sync if 
- [ ] build out goals table and data fetch
- [ ] build out set goals section
- [ ] build out prefeernces
    - [ ] add way to set measurement preference
    - [ ] add sync strava profile button
    - [ ] add way to manually set your timezone
    - [ ] build delete my data function w/ confirm.
    - [ ] build delete my account function w/ confirm.
- [ ] build out dashboard page run calculations for where we should be at
- [ ] build webhook that will invalidate / delete user on app access revocation.

- [x] finish activity sync -- just need to be able to handle pagination and getting all activities.
- [x] get and save user timezone 
- [x] setup activites DB
- [x] get athlete activities
- [x] record activities in database
- [x] pull in 2026 performance
- [x] Sync athlete data button 
- [x] refesh token on pageload
- [x] make it so that if you try to login but are already authed it redirects to the dashboard
- [x] logout endpoint
- [x] Connect up valkey for session auth
- [x] create dev startup script that setups up docker and runs air for simplicity
- [x] setup key refresh script and fire when requests is authed but key is invalid and making a 
        request to strava

# LATER
- [ ] create privacy policy and terms of use.  
- [ ] expire users that haven't logged in with X months
- [ ] setup golang-migrate to handle changes to tables

