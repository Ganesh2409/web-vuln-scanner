# Web Vulnerability Scanner

**Abstract**: The Web Vulnerability Scanner is a Flask-based application designed to identify and report security vulnerabilities in web applications. It performs automated scans for common vulnerabilities such as Cross-Site Scripting (XSS), SQL Injection, and Cross-Site Request Forgery (CSRF). The application features user registration and login functionality, allowing users to manage their scan results effectively.


## Folder Structure
```
web_vuln_scanner/
├── app.py
├── config.py
├── requirements.txt
├── runtime.txt
├── .gitignore
├── instance/
│   └── scans.db
├── models/
│   ├── __init__.py
│   └── database.py
├── scanner/
│   ├── __init__.py
│   ├── csrf_scanner.py
│   ├── scanner.py
│   ├── sqil_scanner.py
│   └── xss_scanner.py
├── static/
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── scripts.js
└── templates/
    ├── dashboard.html
    ├── history.html
    ├── index.html
    ├── layout.html
    ├── login.html
    ├── register.html
    ├── results.html
    ├── scan.html
    └── signup.html
```

## Cloning the Repository
To clone the repository, run the following command:
```bash
git clone <repository-url>
```

## Running the Project Locally
1. Ensure you have Python and Flask installed.
2. Navigate to the project directory:
   ```bash
   cd web_vuln_scanner
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set the environment variables:
   ```bash
   export SECRET_KEY='your_secret_key'
   export DATABASE_URL='sqlite:///scans.db'
   ```
5. Run the application:
   ```bash
   python app.py
   ```

## Documentation of Important Modules
### WebVulnerabilityScanner
The `WebVulnerabilityScanner` class is responsible for scanning the target URL for vulnerabilities. It includes methods for:
- **XSS**: Checks for Cross-Site Scripting vulnerabilities.
- **SQL Injection**: Checks for SQL Injection vulnerabilities.
- **CSRF**: Checks for Cross-Site Request Forgery vulnerabilities.

### Main Routes in app.py
- **/**: Displays the index page with a list of scans.
- **/scan**: Initiates a scan for the provided URL.
- **/results/<scan_id>**: Displays the results of the scan.
- **/register**: Handles user registration.
- **/login**: Handles user login.
- **/logout**: Logs the user out.

## Contribution Guidelines
Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## Contact Details
For further inquiries, please contact [Your Name] at [Your Email].
