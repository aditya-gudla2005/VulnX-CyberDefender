import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; VulnX/1.0; +https://example.com/bot)"
}


XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

visited_links = set()
vulnerabilities = []

def is_vulnerable_to_xss(response_text):
    return XSS_PAYLOAD in response_text

def is_vulnerable_to_sqli(response_text):
    return re.search(r"sql|syntax|mysql|error", response_text, re.I) is not None

def get_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        if name:
            inputs.append({"type": input_type, "name": name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=5)
        else:
            return requests.get(target_url, params=data, timeout=5)
    except:
        return None

def log_alert(url, reason):
    alert = {
        "timestamp": str(datetime.now()),
        "reason": reason,
        "source_ip": "scan-local",
        "url": url
    }
    try:
        with open("alerts.json", "r") as f:
            data = json.load(f)
    except:
        data = []
    data.append(alert)
    with open("alerts.json", "w") as f:
        json.dump(data, f, indent=2)

def scan_xss(url):
    try:
        forms = get_forms(url)
        if not forms:
            print(f"[--] No forms found on {url}")
            return
        for form in forms:
            details = form_details(form)
            response = submit_form(details, url, XSS_PAYLOAD)
            if response and is_vulnerable_to_xss(response.text):
                vulnerabilities.append((url, "XSS", details))
                log_alert(url, "XSS")
                print(f"[!!] XSS vulnerability on {url} — inputs: {[inp['name'] for inp in details['inputs']]}")
            else:
                print(f"[--] No XSS detected in form at {url}")
    except Exception as e:
        print(f"[ERR] XSS check failed on {url}: {e}")


def scan_sqli(url):
    test_url = f"{url}?id={SQLI_PAYLOAD}"
    try:
        response = requests.get(test_url, timeout=8)
        if is_vulnerable_to_sqli(response.text):
            vulnerabilities.append((test_url, "SQL Injection"))
            log_alert(test_url, "SQL Injection")
            print(f"[!!] SQL Injection vulnerability on {test_url}")
        else:
            print(f"[--] No SQLi on {test_url}")
    except Exception as e:
        print(f"[ERR] SQLi check failed on {test_url}: {e}")


def crawl(url):
    if url in visited_links:
        return
    visited_links.add(url)
    try:
        response = requests.get(url,timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href and href.startswith("http"):
                crawl(href)
    except:
        pass

def scan_target(target):
    visited_links.clear()
    vulnerabilities.clear()
    crawl(target)

    for link in list(visited_links):
        scan_xss(link)
        scan_sqli(link)

    results = []
    for v in vulnerabilities:
        if v[1] == "XSS":
            url = v[0]
            form_info = v[2]
            input_names = [inp['name'] for inp in form_info['inputs'] if inp['name']]
            results.append(f"[!!] XSS vulnerability on {url}\n      Affected Inputs: {input_names}")
        elif v[1] == "SQL Injection":
            url = v[0]
            results.append(f"[!!] SQL Injection vulnerability on {url}")

    # ✅ Save scan results to file BEFORE returning
    try:
        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        print(f"[ERR] Could not write scan results: {e}")

    return results




if __name__ == "__main__":
    target_site = input("Enter target URL (e.g., http://testphp.vulnweb.com): ")
    found = scan_target(target_site)
    for item in found:
        print(item)
