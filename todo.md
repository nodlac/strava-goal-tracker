# Distractions 
- [/] low bar with privacy and terms of use
- [ ] could cache the user's goals / dashboard queries I'd do that once we see if compute is heavy could even cache it for 30 min or something 
- [ ] I think it would be neat to have a section where users could see total goal completions.
- [ ] Build a very simple page view tracker. Just so we can analyze what pages if any users gravitate to.

## MVP: Activities

- [ ] setup env var system and pull down envars

### Example implementation:
```go
// handleActivites updates
page := r.URL.Query().Get("page")
limit := 50  // or from query param
offset := (page - 1) * limit
activities, _ := fetchUserActivites(user, limit, offset)
```

- [x] activities page just a list of activities probably 100 per page paginated.

## MVP: Dashboard
- [ ] Build dashboard template showing goal progress
- [ ] Display current totals vs goal targets (simple list, no charts)
    
## Mobile 
- [ ] make everything comply with mobile standards

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

- [ ] need to think through can you delete a goal? when a goal is over where do I put it? 
    - create a way to display goals 

- [ ] Sync all historical data (last 2+ years)
- [ ] Privacy policy and terms of use
- [ ] Expire users after X months inactivity
- [ ] Setup golang-migrate for database migrations
- [ ] Add rate limits

---

