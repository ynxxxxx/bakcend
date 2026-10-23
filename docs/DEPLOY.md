# Ubuntu 24.04 LTS Production Deployment & Hardening Guide

Comprehensive deployment, network security hardening, and administration bootstrap guide for Hostinger VPS (Ubuntu 24.04, 32 GB RAM, 8 vCPU).

---

## 1. Initial VPS System Hardening

### A. Non-Root Sudo User & SSH Key Enforcement
SSH into your fresh VPS as `root`:
```bash
# Update base repositories
apt update && apt upgrade -y

# Create an unprivileged administrative user
adduser deployer
usermod -aG sudo deployer

# Setup SSH key authentication for deployer
mkdir -p /home/deployer/.ssh
cp /root/.ssh/authorized_keys /home/deployer/.ssh/
chown -R deployer:deployer /home/deployer/.ssh
chmod 700 /home/deployer/.ssh
chmod 600 /home/deployer/.ssh/authorized_keys

# Hardened SSH configuration
cat << 'EOF' > /etc/ssh/sshd_config.d/99-hardened.conf
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

systemctl restart ssh
```

### B. Unattended Security Upgrades & Fail2ban
```bash
apt install -y unattended-upgrades fail2ban

# Enable automated security patching
dpkg-reconfigure -plow unattended-upgrades

# Configure Fail2ban for SSH
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = ssh
EOF

systemctl restart fail2ban
systemctl enable fail2ban
```

### C. Firewall Hardening (UFW & Cloudflare-Only Ingress)
Only allow HTTP (80) and HTTPS (443) from Cloudflare IP addresses:
```bash
# Reset UFW
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow OpenSSH

# Restrict ports 80 and 443 to Cloudflare IPv4 ranges
curl -s https://www.cloudflare.com/ips-v4 | while read ip; do
    ufw allow proto tcp from $ip to any port 80,443 comment "Cloudflare IPv4"
done

# Restrict ports 80 and 443 to Cloudflare IPv6 ranges
curl -s https://www.cloudflare.com/ips-v6 | while read ip; do
    ufw allow proto tcp from $ip to any port 80,443 comment "Cloudflare IPv6"
done

# Enable firewall
ufw --force enable
```

---

## 2. Docker & Compose Installation (Official Docker Engine)

```bash
# Install Docker prerequisites
apt install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Grant deployer user Docker permissions
usermod -aG docker deployer
```

---

## 3. Application Deployment & Environment Setup

Switch to `deployer` user:
```bash
su - deployer
git clone https://github.com/ynxxxxx/bakcend.git /home/deployer/app
cd /home/deployer/app

# Create production environment configuration
cp .env.example .env
chmod 600 .env

# Edit environment variables with production secrets
nano .env
```

Ensure `.env` contains:
- `SUPABASE_URL`: Points to your Supabase project URL (e.g. `https://xxx.supabase.co` or internal VPS host).
- `SUPABASE_ANON_KEY`: Client anonymous key.
- `SUPABASE_SERVICE_ROLE_KEY`: Server-side administrative key.
- `ADMIN_DOMAIN`: Domain pointing to Caddy (e.g. `admin.yourdomain.com`).

---

## 4. Launching the Hardened Stack

```bash
cd /home/deployer/app/infra
docker compose up -d --build

# Verify container health
docker compose ps
```

---

## 5. Bootstrapping the First Administrator & MFA

Once the stack is running, execute the one-time bootstrap script from the repository root:

```bash
cd /home/deployer/app

# Bootstrap the initial platform administrator:
node scripts/bootstrap-admin.js create \
  --email "security-admin@yourdomain.com" \
  --password "GenerateStrongPassword2026!" \
  --role admin
```

### Initial Login & MFA Enrollment
1. Open `https://admin.yourdomain.com/login` in your browser.
2. Sign in with the credentials specified above.
3. The console will prompt you to scan a TOTP QR code into your authenticator app (e.g., Google Authenticator, 1Password, Aegis).
4. Enter the 6-digit verification code. Your session is now verified at assurance level `AAL2`.

### Emergency Staff MFA Reset
If a staff member loses their authenticator device:
```bash
node scripts/bootstrap-admin.js reset-mfa --email "security-admin@yourdomain.com"
```
The staff member can log in with their password and immediately enroll a new authenticator.

---

## 6. Automated Backup Strategy

Create `/home/deployer/backup.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR="/home/deployer/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

# Backup Caddy certificates & data
tar -czf "$BACKUP_DIR/caddy_$TIMESTAMP.tar.gz" -C /var/lib/docker/volumes/infra_caddy_data/_data .

# Keep only last 14 days
find "$BACKUP_DIR" -type f -mtime +14 -delete
```

Schedule daily via crontab:
```bash
crontab -e
# Add:
0 2 * * * /home/deployer/backup.sh > /dev/null 2>&1
```
