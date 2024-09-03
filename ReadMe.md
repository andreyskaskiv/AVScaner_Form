
# Asynchronous Vulnerability Scanner

---

## Description
### A program for searching for vulnerabilities in forms

---

## Install:
```pycon
git clone 
cd AVScaner_Form
```
```pycon
1. Create a virtual environment:
    python -m venv .venv

2. Activate the virtual environment:
    On Windows:
    .venv\Scripts\activate
    
    On macOS/Linux:
    source .venv/bin/activate

pip install -r requirements.txt
# pip freeze > requirements.txt
```

---

## Preparing links before work:
### Tools:
- [uddup](https://github.com/rotemreiss/uddup)
- [p1radup](https://github.com/iambouali/p1radup)
- [urldedupe](https://github.com/ameenmaali/urldedupe)

```bash
uddup -s -u crawled_link.txt | grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" | sort -u | urldedupe -s > crawled_final.txt
```

---

### Use:
```text
"-i", "--input", help="Path to the file with links for check"
"-o", "--output", help="Output folder", default="output_report"
"-p", "--payloads", help="Path to file with payloads"
"-a", "--answers", help="Path to file with answers"
"-c", "--concurrency", help="Number of concurrent requests per sec", default=20)
"-t", "--timeout", help="Request timeout", default=15 sec)
"-v", "--verbose", help="Display all responses", default=None)
"-vv", "--verbose_requests", help="Display all requests", default=None)
"-post", "--post", help="Use post method", nargs='?', default=None)
"-px", "--proxy", help="Proxy for intercepting requests (e.g., http://127.0.0.1:8080)"
```
```pycon
python AVScaner_Form.py -c 10 

python AVScaner_Form.py -c 10 -vv -px http://127.0.0.1:8080

python AVScaner_Form.py -c 10 --post --proxy http://127.0.0.1:8080

python AVScaner_Form.py -c 10 -v -i "input_data/crawled_final.txt" -p "wordlist/payloads_LFI.txt" -a "wordlist/answers_LFI.txt"
```

### After scanning, check the **report** folder!

---

### RCE

```bash

```


```bash

```

---

## Proxy
####  Windows Subsystem for Linux ([WSL](https://stackoverflow.com/questions/51887784/using-aiohttp-with-proxy/78727608#78727608))

```text
import aiohttp
import ssl

url = 'https://example.com'
proxy_url = 'http://<user>:<pass>@<proxy>:<port>'
path_to_cafile = '/etc/ssl/certs/ca-certificates.crt'
ssl_ctx = ssl.create_default_context(cafile=path_to_cafile)

async with aiohttp.ClientSession() as session:
    async with session.get(url, proxy=proxy_url, ssl=ssl_ctx) 
```