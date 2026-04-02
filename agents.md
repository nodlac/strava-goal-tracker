# Agent Instructions for Strava Goal Tracker

## Project Overview
A Go web application that integrates with Strava API to track athletic goals (distance, elevation, duration) for cycling, running, and swimming. Uses SQLite for data storage and Valkey (Redis) for session management.

## Tech Stack
- **Backend**: Go (you must NOT write Go code - the user wants to author this themselves)
- **Database**: SQLite with WAL mode (you must NOT write Database code - the user wants to author this themselves)
- **Session**: Valkey/Redis with SCS session manager (you must NOT write Valkey/Rdis code - the user wants to author this themselves)
- **Frontend**: HTML/CSS (autofilling and generating templates is fine. Don't write HTMX code but do provide examples and help solve the problems.)
- **Build**: Air for live reload

## User Preferences

### Learning Focus
- The Go backend code is to be completely authored by the user
- Provide **short explanations** and **conceptual explanations** when helping
- This is a learning project - prioritize teaching over just completing tasks

### What I Can Help With
1. **HTML/CSS** - Create and modify frontend markup and styles
2. **Code explanations** - Explain Go concepts, patterns, and best practices
3. **Code examples** - Show examples of how to accomplish specific tasks in Go (for learning)
4. **Debugging** - Help identify and fix issues
5. **Database queries** - SQL query construction and optimization -- explain why optimizations are necessary.
6. **API integration** - How to work with Strava API

### What I Won't Do
- Write Go code directly (you will write it with guidance)
- Implement HTMX features (user wants to learn this themselves)
- Implement SQLite features (user wants to learn this themselves)
- Implement Valkey/Reids features (user wants to learn this themselves)

## Agent Behavior

- **Do NOT ask to switch into "build mode"** - the user prefers conversational assistance
- **Reread relevant code before responding** - the user frequently makes updates, so check if issues are already resolved before flagging them

## Common Tasks

### Running the Project
```bash
# Start Valkey (if not running)
docker start valkey-server

# Run with air for live reload
air
```

### Adding New Pages
1. Create handler function in main.go
2. Add HTML template (plain HTML, no HTMX)
3. Register route with `mux.Handle()` or `mux.HandleFunc()`

### Database Changes
- Tables defined in `initDB()` function
- Uses `database/sql` with sqlite driver
- Review TODO comments in README.md for planned features

## Key Files
- `main.go` - All Go backend logic
- `README.md` - Project plan and TODO list
- `.env.template` - Environment variables template
