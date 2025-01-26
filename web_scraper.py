"""
How to run:

Basic usage:
python3 web_scraper.py <url>

Example 1: Scrape a webpage:
python3 web_scraper.py https://example.com

Example 2: Access a login page on a server:
python3 web_scraper.py <ip_address>/<login_page>
   Example:
   python3 web_scraper.py http://example.com/login

Notes:
- Replace `<url>` with the full URL of the webpage you want to scrape.
- Replace `<ip_address>/<login_page>` with the appropriate IP address or domain and login page path.
- Ensure you have a stable internet connection and permissions to access the target URL.
"""



from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import argparse

def extract_info_with_selenium(url):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless") 
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        driver.get(url)

        title = driver.title

        links = [link.get_attribute("href") for link in driver.find_elements(By.TAG_NAME, "a")]

        forms = []
        form_elements = driver.find_elements(By.TAG_NAME, "form")
        for form in form_elements:
            form_data = {
                "action": form.get_attribute("action"),
                "method": form.get_attribute("method"),
                "inputs": []
            }
            inputs = form.find_elements(By.TAG_NAME, "input")
            for input_tag in inputs:
                input_data = {
                    "name": input_tag.get_attribute("name"),
                    "type": input_tag.get_attribute("type"),
                    "value": input_tag.get_attribute("value")
                }
                form_data["inputs"].append(input_data)
            forms.append(form_data)

        html = driver.page_source
        driver.quit()
        return title, links, forms, html, None

    except Exception as e:
        return None, None, None, None, f"Error: {e}"

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Scraper with Selenium")
    parser.add_argument("url", help="Target URL for scraping")
    args = parser.parse_args()

    url = args.url

    title, links, forms, html, error = extract_info_with_selenium(url)

    if error:
        print(error)
        return

    print(f"Title: {title}\n")
    
    print("Links:")
    if not links:
        print("  No links found.")
    else:
        for link in links:
            print(f"  - {link}")
    
    print("\nForms:")
    if not forms:
        print("  No forms found.")
    else:
        for i, form in enumerate(forms):
            print(f"  - Form {i+1}:")
            print(f"    Action: {form['action']}")
            print(f"    Method: {form['method']}")
            print("    Inputs:")
            for input_data in form['inputs']:
                print(f"      - Name: {input_data['name']}")
                print(f"      - Type: {input_data['type']}")
                print(f"      - Value: {input_data['value']}")
    
    print("\nPage Source:\n", html)

if __name__ == "__main__":
    main()

