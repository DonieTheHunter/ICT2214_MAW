# ICT2214_MAW

Project MAW (Monitored Anomalies in Web) is a self-contained security tool that monitors all web traffic from within your private network. It uses a smart two-step process for analysis: first, a fast rule-based filter catches known attack patterns; then, a second AI layer examines anything unusual, scoring its risk to create clear, prioritized alerts for your team. Unlike many security tools that rely on external cloud services, MAW is built to run entirely on your own infrastructure, keeping all sensitive traffic data private. The system's key advantage is its ability to learn and adapt. When your security analysts review and confirm a high-risk alert from the AI, that verified threat is fed back to train the AI model. This guided learning loop allows the system to make smarter, more accurate decisions when it encounters similar suspicious traffic in the future.

# Requirements
System Requirements
1. Linux (Ubuntu recommended)
2. Python 3.9+
3. NGINX (compiled with mirror module)
4. Root or sudo access
5. OpenSSL (optional unless using HTTPS)
6. Your own VirusTotal API key & OpenAI API key

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

# Further Security Configurations
1. Setting up firewall rules

This is provided you are setting up the web server and reverse proxy in an internal network (The proper security configuration)

 Reverse Proxy
 ```
 sudo ufw allow from <subnet of internal network> to any port <port no. hosting IDS web app>
 sudo ufw allow from any to <IP address of Reverse Proxy> port <port no. hosting web server appplication from reverse proxy>
 ```

 Web Server
 ```
 sudo ufw allow from <internal IP of reverse proxy> to <internal IP of web server> port <port no. of web server>
 ```

# Setting up API keys
Create a .env file inside the same folder as the main app.py and add the following
```
API_KEY = <key>
OPENAI_API_KEY = <key>
```
