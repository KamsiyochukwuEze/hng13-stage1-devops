# Robust Production-grade bash script
### This `bash` script automates the setup, deployment, and configuration of a Dockerized application on an EC2 server.
### ✨Features
- Collects parameters from input (git repo URL, Personal access token, branch name and server details)
- Clones the repo inputed using the personal access token or pulls changes if already cloned. 
- SSH into the server from the details provided and installs Docker, Docker compose and Ngnix 
- Builds and runs Dockerized application
- Nginx as a reverse proxy
