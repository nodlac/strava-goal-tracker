Dev setup uses a hybrid setup where only valkey is in a docker container.
I wanted my prod setup to be something more concrete and packaged

This essentially creates a group of apps that can talk to eachother


# Valkey script 

# 0. Docker user permissions 
    ```
        sudo groupadd docker
        sudo usermod -aG docker $USER
        newgrp docker
    ```

# 1. Setup the "Virtual Wire"
    `sudo systemctl start docker`
    `docker network create app-network || true

# 2. Start Valkey
    ```
        docker run -d \
          --name valkey-server \
          --network app-network \
          -v valkey_data:/data \
          valkey/valkey:latest \
          valkey-server --requirepass "StrongPassword"
    ```

# 3. Build and Run Go App
    ```
        docker build -t strava-goal-tracker .
        docker run -d \
          --name strava-goal-tracker \
          --network app-network \
          -e VALKEY_ADDR="valkey-server:6379" \
          strava-goal-tracker
    ```
