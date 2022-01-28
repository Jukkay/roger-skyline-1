## Setup SSL
# Create certificate and key. req -x509 is type of certificate, -nodes skips passphrase for using the certificate, -days 365 is the length of validity, -newkey rsa:2048 is the type of key, -keyout is the location of the key, -key is the location of the certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt

# Setup forward secrecy
sudo openssl dhparam -out /etc/nginx/dhparam.pem 4096

# Create configuration snippet for SSL
sudo touch /etc/nginx/snippets/self-signed.conf
sudo chown $USER /etc/nginx/snippets/self-signed.conf
echo "ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;" > /etc/nginx/snippets/self-signed.conf

# Create another snippet
sudo touch /etc/nginx/snippets/ssl-params.conf
sudo chown $USER /etc/nginx/snippets/ssl-params.conf
echo 'ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off; # Requires nginx >= 1.5.9
ssl_stapling on; # Requires nginx >= 1.3.7
ssl_stapling_verify on; # Requires nginx => 1.3.7
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
# Disable strict transport security for now. You can uncomment the following
# line if you understand the implications.
# add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";' > /etc/nginx/snippets/ssl-params.conf

# Edit nginx configuration
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
sudo chown $USER /etc/nginx/sites-available/default
echo "server {
    listen 443 ssl;
    listen [::]:443 ssl;
    include snippets/self-signed.conf;
    include snippets/ssl-params.conf;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name 10.11.254.253 www.10.11.254.253;
}" > /etc/nginx/sites-available/default
echo "server {
    listen 80;
    listen [::]:80;

    server_name 10.11.254.253 www.10.11.254.253;

    return 301 https://\$server_name\$request_uri;
}" >> /etc/nginx/sites-available/default

# Enable changes and restart nginx
sudo nginx -t
sudo systemctl restart nginx

# Remove unnecessary packages and processes
sudo apt-get uninstall git
