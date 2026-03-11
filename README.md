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

---

# Distractions 
- [ ] low bar with privacy and terms of use
- [ ] update color scheme
- [ ] build out landing page.
- [ ] add user logo to navbar

# MVP

## MVP: Goal Setting
- [ ] Pre-populate existing goals in form (for editing)
- [ ] Add goal_id hidden field to template rows -- setup current goals in table (this is what's missing)
- [ ] fix user logo in nav It's broken
- [x] Implement handleSaveGoals handler
- [x] Add GoalForm struct to main.go
- [x] Add "Go to Dashboard" button to template  
- [x] Register /save-goals route

## MVP: Dashboard
- [ ] Build dashboard template showing goal progress
- [ ] Display current totals vs goal targets (simple list, no charts)

---

# Nice to Have (Low Lift)

## HTML Partials
- [x] Create templates/header.html with common head, HTMX, Chart.js
- [x] Create templates/nav.html with common navigation
- [ ] Update all templates to use partials

---

# Phase 2: Dashboard with Charts

## Dashboard Data Structures
- DashboardData struct for template payload
- PeriodActivity, GoalWithProgress structs

## Dashboard Functions
- [ ] fetchActivitiesInRange(userID, startDate, endDate)
- [ ] calculateGoalProgress(goal, activities) 
- [ ] groupActivitiesByWeek(activities)
- [ ] groupActivitiesByMonth(activities)
- [ ] buildCumulativeData(activities)
- [ ] getActivityTypeDistribution(activities)

## Dashboard Implementation
- [ ] Add Chart.js to header
- [ ] Build charts: cumulative progress, weekly/monthly bars, activity distribution
- [ ] Add filter controls (time range, group by week/month)

---

# Phase 3: Preferences & Account

- [ ] Handle units (convert to meters on save)
- [ ] Preferences page: measurement preference, timezone,
- [ ] Delete my data function
- [ ] Delete my account function

---

# Phase 4: Webhooks

- [ ] Register webhook with Strava
- [ ] Handle webhook events (new activities)
- [ ] Webhook to delete user on access revocation

---

# Later

- [ ] Sync all historical data (last 2+ years)
- [ ] Privacy policy and terms of use
- [ ] Expire users after X months inactivity
- [ ] Setup golang-migrate for database migrations
- [ ] Add rate limits

---

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
