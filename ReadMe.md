
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
python AVScaner_Form.py -c 5

[*] Starting @ 22:49:39 2024-09-03
[*] Total number of payload variants per link: 18


13/18 🐸  
[+] URL: http://example.com/wp-content/uploads/2024/08/404.php | Status: 200 | Response time: 0.11 sec
<form method="GET" name="404.php">
<input id="cmd" name="cmd" size="80" type="TEXT"/>
<input type="SUBMIT" value="Execute"/>
</form>
{'cmd': 'ls -la'}

17/18 🐦  
[+] URL: http://example.com/equipments/adapter | Status: 200 | Response time: 0.32 sec
<form method="GET" name="index.php">
<input id="cmd" name="cmd" size="80" type="TEXT"/>
<input type="SUBMIT" value="iQ Freeze"/>
</form>
{'cmd': 'ls -la'}

18/18 🐵  

[*] Finished @ 22:49:47 2024-09-03
[*] Duration: 0:00:08.334356

```


```bash

```

---
