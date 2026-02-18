# ICT2212_MAW

# Requirements
System Requirements
1. Linux (Ubuntu recommended)
2. Python 3.9+
3. NGINX (compiled with mirror module)
4. Root or sudo access
5. OpenSSL (optional unless using HTTPS)

# Dependencies
1. Install Python dependencies
```
pip install flask waitress
```

# Installation Guide
1. Clone the Repository
```
git clone https://github.com/yourusername/your-repo.git
cd your-repo
```

2. Install and Replace NGINX config file
```
sudo mv nginx.conf /etc/nginx/
```

OR

2. Edit current NGINX config file
```
sudo nano /etc/nginx/nginx.conf
```
Add JSON log format
```
log_format new_log_format escape=json '{"timestamp": "$time_local", "action": "log", "protocol": "$server_protocol", "src_ip": "$remote_addr", "src_port": "$remote_port", "direction": "-]", "dst_ip": "$server_addr", "dst_port": "$server_port", "method": "$request_method", "uri": "$request_uri", "status": "$status", "Form": "$request_body"}';
```

3. Copy + Paste reverse-proxy config file into /etc/nginx/sites-available/
```
sudo cp reverse-proxy /etc/nginx/sites-available
```
P.S
If you are not using HTTPS, remove all lines that have 'ssl' inside

4. Enable site
```
sudo ln -s /etc/nginx/sites-available/reverse-proxy /etc/nginx/sites-enabled/
```

5. Test configurations
```
sudo nginx -t
```

6. Once the test is fine, modify your reverse-proxy config file as per what you wish

 Things that require changes:
 1. listen [port no.] (line 2) + Remove the "SSL" at the end of the line
 2. server_name [IP of reverse proxy server] (line 3)
 3. proxy_pass https:[IP of web server]:[port no.] (line 9) + Change to http
 4. proxy_pass http://[IP of web server]:[port no.]/uploads_test (line 29)
 
 If using HTTPS:
 1. ssl_certificate [.crt file] (line 4)
 2. ssl_certificate_key [.key file] (line 5)
 3. proxy_ssl_trusted_certificate [certificate authority file] (line 15)
 4. proxy_ssl_name [IP of web server] (line 20)


Restart NGINX
```
sudo systemctl restart nginx
```

# Running IDS
Start Python IDS Server
```
sudo python3 app.py
```
You should see:
```Starting IDS on port 6767```
The IDS UI will be available at http://[server-ip]:6767
