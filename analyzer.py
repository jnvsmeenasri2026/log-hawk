import pandas as pd
import re
from datetime import datetime

def parse_logs(file_content):
    logs = []
    lines = file_content.strip().split('\n')
    
    for line in lines:
        # Pattern: date time level message
        pattern = r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+) (.+)'
        match = re.match(pattern, line)
        
        if match:
            date, time, level, message = match.groups()
            logs.append({
                "date": date,
                "time": time,
                "level": level,
                "message": message,
                "hour": int(time.split(":")[0])
            })
    
    return pd.DataFrame(logs)

def detect_threats(df):
    threats = []
    
    # 1. Detect Brute Force → 5+ failed logins same IP
    failed = df[df['message'].str.contains('Failed login', case=False)]
    
    ip_pattern = r'IP (\d+\.\d+\.\d+\.\d+)'
    failed_ips = failed['message'].str.extract(ip_pattern)
    ip_counts = failed_ips[0].value_counts()
    
    for ip, count in ip_counts.items():
        if count >= 5:
            threats.append({
                "type": "🚨 Brute Force Attack",
                "detail": f"IP {ip} failed {count} times!",
                "severity": "HIGH"
            })
    
    # 2. Detect Late Night Activity → between 11PM and 5AM
    night = df[
        (df['level'] == 'WARNING') & 
        ((df['hour'] >= 23) | (df['hour'] <= 5))
    ]
    
    if len(night) > 0:
        threats.append({
            "type": "🌙 Suspicious Night Activity",
            "detail": f"{len(night)} suspicious events between 11PM-5AM!",
            "severity": "MEDIUM"
        })
    
    # 3. Detect System Errors
    errors = df[df['level'] == 'ERROR']
    
    if len(errors) > 0:
        threats.append({
            "type": "🔴 System Errors Detected",
            "detail": f"{len(errors)} system errors found in logs!",
            "severity": "MEDIUM"
        })
    
    return threats

def get_summary(df):
    return {
        "total": len(df),
        "info": len(df[df['level'] == 'INFO']),
        "warning": len(df[df['level'] == 'WARNING']),
        "error": len(df[df['level'] == 'ERROR'])
    }