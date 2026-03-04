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
- [ ] add way to edit / delete goals from goal select page
- [ ] handle raw data being sent up (also need to setup endpoint to capture goals and setup way to 
- [x] Make it so you can add arbitrary goals. IE target date ... sport type
    - [x] build form 
- [ ] setup standard head and load HTMX there
- [ ] Set up tmpl and all the html pages. It'll take a bit but it's time. 
       bare-bones for now but then build it more complex
- [ ] handle error use logged in and account gets deleted should drop the valkey
- [ ] build out set goals section
    - [/] build goals form  (A little blocked here because the template is so bad.
    - [ ] handle units
    - [ ] convert all data into meters so that data is stored uniformly. 
        (Will result in extra calculations but it'll be worth it);
- [ ] build out dashboard page run calculations for where we should be at
- [ ] build out prefeernces
    - [ ] add way to set measurement preference
    - [ ] add sync strava profile button
    - [ ] add way to manually set your timezone
    - [ ] build delete my data function w/ confirm.
    - [ ] build delete my account function w/ confirm.
    - [ ] remove sync data button and replace with delete data and re-sync 
            (add warning that this is only if data has become corrupted or if data is missing)
- [ ] build webhook that will invalidate / delete user on app access revocation.
- [ ] setup webhook for activity creation so that you only need to sync if 

# LATER
- [ ] create privacy policy and terms of use.  
- [ ] expire users that haven't logged in with X months
- [ ] setup golang-migrate to handle changes to tables
- [ ] add ability to sync previous years and display previous yekkkk21kar data.
- [ ] add rate limits

# Done
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
- [x] pull in metric preference "measurement_preference"
- [x] only save user data on initial login
- [x] only sync user activities on initial login after that it should be handled by webhooks
    - [x] build goals table
    - [x] build out list of sports insertion query -- Support aggragate virtual
    - [x] build out display struct
- [x] Move handlers to templates -- will likely need to refactor later.
