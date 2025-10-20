#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/deploy_$(date +%Y%m%d_%H%M%S).log"
readonly TEMP_DIR="/tmp/deploy_$$"
readonly LOCK_FILE="/tmp/deploy.lock"

# Global variables
CLEANUP_MODE=false
REPO_URL=""
PAT=""
BRANCH="main"
SSH_USER=""
SERVER_IP=""
SSH_KEY_PATH=""
APP_PORT=""
REPO_NAME=""
PROJECT_DIR=""


log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "${LOG_FILE}"
}

cleanup() {
    log_info "Performing cleanup..."
    rm -rf "${TEMP_DIR}"
    rm -f "${LOCK_FILE}"
    log_info "Cleanup completed"
}

error_exit() {
    log_error "$1"
    cleanup
    exit "${2:-1}"
}

trap 'error_exit "Script interrupted" 130' INT TERM
trap 'cleanup' EXIT

check_dependencies() {
    log_info "Checking local dependencies..."
    local deps=("git" "ssh" "scp" "curl")
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error_exit "Required command '$cmd' not found. Please install it." 127
        fi
    done
    
    log_success "All local dependencies satisfied"
}

acquire_lock() {
    if [ -f "${LOCK_FILE}" ]; then
        local pid=$(cat "${LOCK_FILE}")
        if ps -p "$pid" > /dev/null 2>&1; then
            error_exit "Another deployment is already running (PID: $pid)" 1
        else
            log_warning "Stale lock file found, removing..."
            rm -f "${LOCK_FILE}"
        fi
    fi
    echo $$ > "${LOCK_FILE}"
    log_info "Lock acquired"
}



validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    return 0
}

validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

read_secret() {
    local prompt="$1"
    local secret
    echo -n "$prompt"
    read -s secret
    echo
    echo "$secret"
}

collect_parameters() {
    log_info "Collecting deployment parameters..."
    
    # Git Repository URL
    while true; do
        read -p "Enter Git Repository URL: " REPO_URL
        if validate_url "$REPO_URL"; then
            break
        else
            log_error "Invalid URL format. Please enter a valid HTTP(S) URL."
        fi
    done
    
    # Personal Access Token
    PAT=$(read_secret "Enter Personal Access Token (PAT): ")
    if [ -z "$PAT" ]; then
        error_exit "PAT cannot be empty" 1
    fi
    
    # Branch name
    read -p "Enter branch name [main]: " BRANCH
    BRANCH=${BRANCH:-main}
    
    # SSH Username
    read -p "Enter SSH username: " SSH_USER
    if [ -z "$SSH_USER" ]; then
        error_exit "SSH username cannot be empty" 1
    fi
    
    # Server IP
    while true; do
        read -p "Enter server IP address: " SERVER_IP
        if validate_ip "$SERVER_IP"; then
            break
        else
            log_error "Invalid IP address format."
        fi
    done
    
    # SSH Key Path
    while true; do
        read -p "Enter SSH key path [~/.ssh/id_rsa]: " SSH_KEY_PATH
        SSH_KEY_PATH=${SSH_KEY_PATH:-~/.ssh/id_rsa}
        SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"
        
        if [ -f "$SSH_KEY_PATH" ]; then
            break
        else
            log_error "SSH key not found at: $SSH_KEY_PATH"
        fi
    done
    
    # Application Port
    while true; do
        read -p "Enter application port: " APP_PORT
        if validate_port "$APP_PORT"; then
            break
        else
            log_error "Invalid port number (1-65535)."
        fi
    done
    
    # Extract repo name
    REPO_NAME=$(basename "$REPO_URL" .git)
    PROJECT_DIR="${TEMP_DIR}/${REPO_NAME}"
    
    log_success "Parameters collected successfully"
    log_info "Repository: $REPO_URL"
    log_info "Branch: $BRANCH"
    log_info "Server: ${SSH_USER}@${SERVER_IP}"
    log_info "App Port: $APP_PORT"
}


clone_repository() {
    log_info "Cloning repository..."
    
    mkdir -p "${TEMP_DIR}"
    cd "${TEMP_DIR}"
    
    # Build authenticated URL
    local auth_url
    if [[ "$REPO_URL" =~ github.com ]]; then
        auth_url="${REPO_URL/https:\/\//https://${PAT}@}"
    elif [[ "$REPO_URL" =~ gitlab.com ]]; then
        auth_url="${REPO_URL/https:\/\//https://oauth2:${PAT}@}"
    else
        auth_url="${REPO_URL/https:\/\//https://${PAT}@}"
    fi
    
    if [ -d "$PROJECT_DIR" ]; then
        log_warning "Repository already exists, pulling latest changes..."
        cd "$PROJECT_DIR"
        git fetch --all >> "${LOG_FILE}" 2>&1 || error_exit "Failed to fetch repository" 2
        git checkout "$BRANCH" >> "${LOG_FILE}" 2>&1 || error_exit "Failed to checkout branch: $BRANCH" 2
        git pull origin "$BRANCH" >> "${LOG_FILE}" 2>&1 || error_exit "Failed to pull latest changes" 2
    else
        git clone -b "$BRANCH" "$auth_url" "$PROJECT_DIR" >> "${LOG_FILE}" 2>&1 || \
            error_exit "Failed to clone repository" 2
        cd "$PROJECT_DIR"
    fi
    
    log_success "Repository ready at: $PROJECT_DIR"
}

verify_docker_files() {
    log_info "Verifying Docker configuration files..."
    
    if [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
        log_success "Found docker-compose.yml"
        return 0
    elif [ -f "Dockerfile" ]; then
        log_success "Found Dockerfile"
        return 0
    else
        error_exit "No Dockerfile or docker-compose.yml found in repository" 3
    fi
}


ssh_exec() {
    local command="$1"
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        -i "$SSH_KEY_PATH" "${SSH_USER}@${SERVER_IP}" "$command"
}

test_ssh_connection() {
    log_info "Testing SSH connection to ${SSH_USER}@${SERVER_IP}..."
    
    if ssh_exec "echo 'Connection successful'" >> "${LOG_FILE}" 2>&1; then
        log_success "SSH connection established"
    else
        error_exit "Failed to establish SSH connection" 4
    fi
}

prepare_remote_environment() {
    log_info "Preparing remote environment..."
    
    log_info "Updating system packages..."
    ssh_exec "sudo apt-get update -y" >> "${LOG_FILE}" 2>&1 || \
        log_warning "Package update failed or not using apt-based system"
    
    log_info "Installing Docker..."
    ssh_exec "
        if ! command -v docker &> /dev/null; then
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            rm get-docker.sh
            sudo usermod -aG docker \$USER
        else
            echo 'Docker already installed'
        fi
    " >> "${LOG_FILE}" 2>&1 || log_warning "Docker installation encountered issues"
    
    log_info "Installing Docker Compose..."
    ssh_exec "
        if ! command -v docker-compose &> /dev/null; then
            sudo curl -L \"https://github.com/docker/compose/releases/latest/download/docker-compose-\$(uname -s)-\$(uname -m)\" -o /usr/local/bin/docker-compose
            sudo chmod +x /usr/local/bin/docker-compose
        else
            echo 'Docker Compose already installed'
        fi
    " >> "${LOG_FILE}" 2>&1 || log_warning "Docker Compose installation encountered issues"
    
    log_info "Installing Nginx..."
    ssh_exec "
        if ! command -v nginx &> /dev/null; then
            sudo apt-get install -y nginx
        else
            echo 'Nginx already installed'
        fi
    " >> "${LOG_FILE}" 2>&1 || log_warning "Nginx installation encountered issues"
    
    log_info "Starting services..."
    ssh_exec "
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo systemctl enable nginx
        sudo systemctl start nginx
    " >> "${LOG_FILE}" 2>&1 || log_warning "Service startup encountered issues"
    
    log_info "Verifying installations..."
    local docker_version=$(ssh_exec "docker --version" 2>/dev/null || echo "not installed")
    local compose_version=$(ssh_exec "docker-compose --version" 2>/dev/null || echo "not installed")
    local nginx_version=$(ssh_exec "nginx -v 2>&1" || echo "not installed")
    
    log_info "Docker: $docker_version"
    log_info "Docker Compose: $compose_version"
    log_info "Nginx: $nginx_version"
    
    log_success "Remote environment prepared"
}


transfer_files() {
    log_info "Transferring project files to remote server..."
    
    local remote_dir="/home/${SSH_USER}/${REPO_NAME}"
    
    ssh_exec "mkdir -p ${remote_dir}" >> "${LOG_FILE}" 2>&1 || \
        error_exit "Failed to create remote directory" 5
    
    rsync -avz --delete -e "ssh -i ${SSH_KEY_PATH} -o StrictHostKeyChecking=no" \
        "${PROJECT_DIR}/" "${SSH_USER}@${SERVER_IP}:${remote_dir}/" >> "${LOG_FILE}" 2>&1 || \
        error_exit "Failed to transfer files" 5
    
    log_success "Files transferred successfully"
}

deploy_application() {
    log_info "Deploying application..."
    
    local remote_dir="/home/${SSH_USER}/${REPO_NAME}"
    local container_name="${REPO_NAME}_app"
    
    
    log_info "Stopping existing containers..."
    ssh_exec "
        cd ${remote_dir}
        if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then
            docker-compose down 2>/dev/null || true
        fi
        docker stop ${container_name} 2>/dev/null || true
        docker rm ${container_name} 2>/dev/null || true
    " >> "${LOG_FILE}" 2>&1
    
    
    if ssh_exec "[ -f ${remote_dir}/docker-compose.yml ] || [ -f ${remote_dir}/docker-compose.yaml ]" 2>/dev/null; then
        log_info "Deploying with Docker Compose..."
        ssh_exec "
            cd ${remote_dir}
            docker-compose build
            docker-compose up -d
        " >> "${LOG_FILE}" 2>&1 || error_exit "Docker Compose deployment failed" 6
    else
        log_info "Deploying with Docker..."
        ssh_exec "
            cd ${remote_dir}
            docker build -t ${REPO_NAME}:latest .
            docker run -d --name ${container_name} -p ${APP_PORT}:${APP_PORT} --restart unless-stopped ${REPO_NAME}:latest
        " >> "${LOG_FILE}" 2>&1 || error_exit "Docker deployment failed" 6
    fi
    
    sleep 5
    log_success "Application deployed"
}

verify_container_health() {
    log_info "Verifying container health..."
    
    local container_name="${REPO_NAME}_app"
    local status=$(ssh_exec "docker ps --filter name=${container_name} --format '{{.Status}}'" 2>/dev/null || echo "")
    
    if [ -z "$status" ]; then
        # Try docker-compose containers
        status=$(ssh_exec "docker-compose -f /home/${SSH_USER}/${REPO_NAME}/docker-compose.yml ps -q | xargs docker inspect -f '{{.State.Status}}'" 2>/dev/null || echo "")
    fi
    
    if [[ "$status" == *"Up"* ]] || [[ "$status" == "running" ]]; then
        log_success "Container is running: $status"
    else
        log_error "Container health check failed: $status"
        ssh_exec "docker logs ${container_name} --tail 50" >> "${LOG_FILE}" 2>&1
        error_exit "Container is not healthy" 7
    fi
}


configure_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
    local nginx_config="/etc/nginx/sites-available/${REPO_NAME}"
    local domain="${SERVER_IP}"
    
    ssh_exec "sudo tee ${nginx_config} > /dev/null << 'EOF'
server {
    listen 80;
    server_name ${domain};

    location / {
        proxy_pass http://localhost:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
" >> "${LOG_FILE}" 2>&1 || error_exit "Failed to create Nginx config" 8
    
    ssh_exec "
        sudo ln -sf ${nginx_config} /etc/nginx/sites-enabled/${REPO_NAME}
        sudo nginx -t
        sudo systemctl reload nginx
    " >> "${LOG_FILE}" 2>&1 || error_exit "Failed to enable Nginx config" 8
    
    log_success "Nginx configured successfully"
}


validate_deployment() {
    log_info "Validating deployment..."
    
    # Test Docker service
    if ssh_exec "sudo systemctl is-active docker" >> "${LOG_FILE}" 2>&1; then
        log_success "Docker service is running"
    else
        log_error "Docker service is not running"
    fi
    
    # Test Nginx service
    if ssh_exec "sudo systemctl is-active nginx" >> "${LOG_FILE}" 2>&1; then
        log_success "Nginx service is running"
    else
        log_error "Nginx service is not running"
    fi
    
    # Test application endpoint locally on server
    log_info "Testing application endpoint on server..."
    if ssh_exec "curl -f -s http://localhost:${APP_PORT} > /dev/null" 2>> "${LOG_FILE}"; then
        log_success "Application responds on port ${APP_PORT}"
    else
        log_warning "Application may not be responding on port ${APP_PORT}"
    fi
    
    # Test Nginx proxy
    log_info "Testing Nginx proxy..."
    sleep 2
    if ssh_exec "curl -f -s http://localhost > /dev/null" 2>> "${LOG_FILE}"; then
        log_success "Nginx proxy is working"
    else
        log_warning "Nginx proxy may not be working correctly"
    fi
    
    # Test from deployment machine
    log_info "Testing external access..."
    if curl -f -s "http://${SERVER_IP}" > /dev/null 2>&1; then
        log_success "Application is accessible from external network"
    else
        log_warning "Application may not be accessible externally (check firewall rules)"
    fi
    
    log_success "Deployment validation completed"
}

# cleanup
perform_cleanup() {
    log_info "Performing deployment cleanup..."
    
    local remote_dir="/home/${SSH_USER}/${REPO_NAME}"
    local container_name="${REPO_NAME}_app"
    
    ssh_exec "
        cd ${remote_dir} 2>/dev/null || true
        if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then
            docker-compose down -v 2>/dev/null || true
        fi
        docker stop ${container_name} 2>/dev/null || true
        docker rm ${container_name} 2>/dev/null || true
        docker rmi ${REPO_NAME}:latest 2>/dev/null || true
        sudo rm -f /etc/nginx/sites-enabled/${REPO_NAME}
        sudo rm -f /etc/nginx/sites-available/${REPO_NAME}
        sudo systemctl reload nginx 2>/dev/null || true
        cd .. && rm -rf ${remote_dir}
    " >> "${LOG_FILE}" 2>&1 || log_warning "Some cleanup operations failed"
    
    log_success "Cleanup completed"
}



print_usage() {
    cat << EOF

Usage: $0 [OPTIONS]

OPTIONS:
    --cleanup    Remove all deployed resources and exit
    -h, --help   Display this help message

DESCRIPTION:
    Automated deployment script for Dockerized applications.
    Handles cloning, building, deploying, and configuring
    applications on remote servers with Nginx reverse proxy.

EXAMPLE:
    $0
    $0 --cleanup

EOF
}

main() {
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cleanup)
                CLEANUP_MODE=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    log_info "Deployment started at $(date)"
    log_info "Log file: ${LOG_FILE}"
    
    acquire_lock
    check_dependencies
    
    if [ "$CLEANUP_MODE" = true ]; then
        collect_parameters
        test_ssh_connection
        perform_cleanup
        log_success "Cleanup mode completed successfully"
        exit 0
    fi
    
    # Standard deployment flow
    collect_parameters
    clone_repository
    verify_docker_files
    test_ssh_connection
    prepare_remote_environment
    transfer_files
    deploy_application
    verify_container_health
    configure_nginx
    validate_deployment
    
    log_success "═══════════════════════════════════════════════════════════════"
    log_success "Deployment completed successfully!"
    log_success "Application URL: http://${SERVER_IP}"
    log_success "Container Port: ${APP_PORT}"
    log_success "Log file: ${LOG_FILE}"
    log_success "═══════════════════════════════════════════════════════════════"
}


main "$@"