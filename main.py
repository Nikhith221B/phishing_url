import whois
import socket
import ssl
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Union
import joblib

app = FastAPI()

# Allow all origins for simplicity. Adjust as necessary.
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load your phishing model
model_path = "phishing.pkl"
loaded_model = joblib.load(model_path)

# Define the input and output schemas
class URLList(BaseModel):
    urls: List[str]

class URLInfo(BaseModel):
    domain_name: Union[str, None]
    registrar: Union[str, None]
    creation_date: Union[str, None]
    emails: Union[List[str], None]
    name: Union[str, None]
    org: Union[str, None]
    whois_server: Union[str, None]
    ip_address: Union[str, None]
    ssl_certified: bool
    ssl_info: Union[Dict[str, Union[str, int, None]], str]

class URLCheckResponse(BaseModel):
    predictions: Dict[str, str]
    url_info: List[URLInfo]

def extract_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def is_ssl_certified(url):
    parsed_url = urlparse(url)
    host = parsed_url.netloc

    if not host:
        return False, "Invalid URL"

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssl_info = ssock.getpeercert()
                return True, ssl_info
    except Exception as e:
        return False, str(e)

@app.post("/check_urls", response_model=URLCheckResponse)
def check_urls(url_list: URLList):
    all_urls = url_list.urls

    # Predictions using the loaded model
    predictions = loaded_model.predict(all_urls)

    domains = [extract_domain(url) for url in all_urls]

    results = []
    prediction_dict = {url: pred for url, pred in zip(all_urls, predictions)}

    for url, domain in zip(all_urls, domains):
        info = URLInfo(
            domain_name=None,
            registrar=None,
            creation_date=None,
            emails=None,
            name=None,
            org=None,
            whois_server=None,
            ip_address=None,
            ssl_certified=False,
            ssl_info={}
        )

        # WHOIS information
        try:
            w = whois.whois(domain)
            info.domain_name = w.domain_name[0] if isinstance(w.domain_name, list) else w.domain_name
            info.registrar = w.registrar
            info.creation_date = w.creation_date
            info.emails = w.emails
            info.name = w.name
            info.org = w.org
            info.whois_server = w.whois_server
        except whois.parser.PywhoisError:
            pass

        # IP address
        if info.domain_name:
            try:
                info.ip_address = socket.gethostbyname(info.domain_name.lower())
            except socket.gaierror:
                pass

        # SSL certificate
        is_ssl, ssl_info = is_ssl_certified(url)
        info.ssl_certified = is_ssl
        info.ssl_info = ssl_info

        results.append(info)

    return {"predictions": prediction_dict, "url_info": results}
