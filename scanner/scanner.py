import requests
from bs4 import BeautifulSoup

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []

    def scan(self):
        self.check_xss()
        self.check_sql_injection()
        self.check_csrf()
        return self.vulnerabilities

    def check_xss(self):
        test_payload = "<script>alert('XSS')</script>"
        response = self.session.get(self.target_url, params={"q": test_payload})
        if test_payload in response.text:
            self.vulnerabilities.append({
                'type': 'XSS',
                'url': response.url,
                'payload': test_payload
            })

    def check_sql_injection(self):
        test_payload = "' OR 1=1--"
        response = self.session.get(self.target_url, params={"id": test_payload})
        if "error in your SQL syntax" in response.text.lower():
            self.vulnerabilities.append({
                'type': 'SQL Injection',
                'url': response.url,
                'payload': test_payload
            })

    def check_csrf(self):
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                self.vulnerabilities.append({
                    'type': 'CSRF',
                    'url': self.target_url,
                    'payload': 'Missing CSRF token'
                })