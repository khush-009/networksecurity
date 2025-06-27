import tldextract
import requests
from urllib.parse import urlparse, urljoin
import re
import socket
import whois
from datetime import datetime
from bs4 import BeautifulSoup
import pandas as pd

class PhishingFeatureExtractor:
    def __init__(self):
        self.feature_order = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
            'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
            'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
            'Statistical_report'
        ]

    def get_domain_age(self, domain):
        try:
            w = whois.whois(domain)
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            if creation_date:
                age = (datetime.now() - creation_date).days
                return 1 if age > 365 else -1
        except:
            return -1

    def get_google_index(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            search_url = f"https://www.google.com/search?q=site:{url}"
            response = requests.get(search_url, headers=headers, timeout=5)
            return 1 if url in response.text else -1
        except:
            return -1

    def extract_features(self, url):
        features = {}
        try:
            parsed_url = urlparse(url)
            ext = tldextract.extract(url)
            domain = parsed_url.netloc
            registered_domain = ext.registered_domain

            # 1. having_IP_Address
            features['having_IP_Address'] = -1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain) else 1

            # 2. URL_Length
            features['URL_Length'] = -1 if len(url) > 75 else 1

            # 3. Shortining_Service
            shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly"]
            features['Shortining_Service'] = -1 if any(s in url for s in shorteners) else 1

            # 4. having_At_Symbol
            features['having_At_Symbol'] = -1 if '@' in url else 1

            # 5. double_slash_redirecting
            features['double_slash_redirecting'] = -1 if url.count('//') > 1 else 1

            # 6. Prefix_Suffix
            features['Prefix_Suffix'] = -1 if '-' in ext.domain else 1

            # 7. having_Sub_Domain
            subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
            features['having_Sub_Domain'] = -1 if len(subdomain_parts) > 2 else (0 if len(subdomain_parts) == 2 else 1)

            # 8. SSLfinal_State
            try:
                ssl_check = requests.get(url, timeout=5, verify=True)
                features['SSLfinal_State'] = 1 if ssl_check.url.startswith('https') else -1
            except:
                features['SSLfinal_State'] = -1

            # 9. Domain_registeration_length
            features['Domain_registeration_length'] = self.get_domain_age(registered_domain)

            # 10. Favicon
            try:
                favicon_url = urljoin(url, '/favicon.ico')
                fav_response = requests.get(favicon_url, timeout=5)
                features['Favicon'] = -1 if fav_response.status_code == 200 else 1
            except:
                features['Favicon'] = -1

            # 11. port
            features['port'] = -1 if ':' in domain else 1

            # 12. HTTPS_token
            features['HTTPS_token'] = -1 if 'https' in ext.domain else 1

            # Get HTML once
            try:
                page = requests.get(url, timeout=5)
                soup = BeautifulSoup(page.text, 'html.parser')
            except:
                soup = None

            # 13. Request_URL
            try:
                imgs = soup.find_all(['img', 'script', 'link'])
                external_objs = [tag for tag in imgs if tag.has_attr('src') and urlparse(tag['src']).netloc != domain]
                features['Request_URL'] = -1 if len(external_objs) > 10 else 1
            except:
                features['Request_URL'] = -1

            # 14. URL_of_Anchor
            try:
                anchors = soup.find_all('a', href=True)
                ext_anchors = [a for a in anchors if urlparse(a['href']).netloc != domain]
                features['URL_of_Anchor'] = -1 if len(ext_anchors)/len(anchors) > 0.5 else 1
            except:
                features['URL_of_Anchor'] = -1

            # 15. Links_in_tags
            try:
                metas = soup.find_all('meta', {'http-equiv': 'refresh'})
                scripts = soup.find_all('script', src=True)
                features['Links_in_tags'] = -1 if (len(metas) + len(scripts)) > 0 else 1
            except:
                features['Links_in_tags'] = -1

            # 16. SFH (Server Form Handler)
            try:
                forms = soup.find_all('form')
                external_forms = [form for form in forms if 'action' in form.attrs and urlparse(form['action']).netloc != domain]
                features['SFH'] = -1 if external_forms else 1
            except:
                features['SFH'] = -1

            # 17. Submitting_to_email
            try:
                forms = soup.find_all('form')
                email_forms = [form for form in forms if 'mailto:' in form.get('action', '')]
                features['Submitting_to_email'] = -1 if email_forms else 1
            except:
                features['Submitting_to_email'] = -1

            # 18. Abnormal_URL
            features['Abnormal_URL'] = -1 if parsed_url.path.count('/') > 5 else 1

            # 19. Redirect
            try:
                redirect_resp = requests.get(url, timeout=5, allow_redirects=True)
                features['Redirect'] = -1 if len(redirect_resp.history) > 2 else 0
            except:
                features['Redirect'] = 0

            # 20. on_mouseover
            try:
                features['on_mouseover'] = -1 if 'onmouseover' in str(soup).lower() else 1
            except:
                features['on_mouseover'] = -1

            # 21. RightClick
            try:
                features['RightClick'] = -1 if 'oncontextmenu' in str(soup).lower() else 1
            except:
                features['RightClick'] = -1

            # 22. popUpWidnow
            try:
                features['popUpWidnow'] = -1 if 'window.open' in str(soup).lower() else 1
            except:
                features['popUpWidnow'] = -1

            # 23. Iframe
            try:
                features['Iframe'] = -1 if soup.find_all('iframe') else 1
            except:
                features['Iframe'] = -1

            # 24. age_of_domain (same as domain registration length)
            features['age_of_domain'] = features['Domain_registeration_length']

            # 25. DNSRecord
            try:
                socket.gethostbyname(registered_domain)
                features['DNSRecord'] = 1
            except:
                features['DNSRecord'] = -1

            # 26. web_traffic (placeholder: assume low traffic)
            features['web_traffic'] = -1

            # 27. Page_Rank (placeholder: assume low rank)
            features['Page_Rank'] = -1

            # 28. Google_Index
            features['Google_Index'] = self.get_google_index(url)

            # 29. Links_pointing_to_page (placeholder)
            features['Links_pointing_to_page'] = -1

            # 30. Statistical_report (placeholder)
            features['Statistical_report'] = -1

            # Return in fixed order
            return [features[feat] for feat in self.feature_order]

        except Exception as e:
            print(f"[ERROR] Feature extraction failed: {e}")
            return [-1] * len(self.feature_order)
