# Synthetic extraction fixture; never execute.
import requests as client


def fetch(url):
    return client.get(url)


print("ready")
