
import urllib.request, urllib.error

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzgwODM4NzkwLCJpYXQiOjE3ODA4MzY5OTAsImp0aSI6Ijg5Zjc3NDJkMjY3NzRmMWJhMTlhZTM1MTE5YjU5NGVlIiwidXNlcl9pZCI6IjY4MTk4NjMwLTdlNGEtNDcyMS1hODdjLTM4NzI0OTU4Mjk5YiJ9.vh1Id8tNNRYtq2iTRRkreSILP-gDBOXGmpESgJhg34c"

req = urllib.request.Request(

    "http://localhost:8000/api/v1/analysis/reports/08f06463-ae8f-4df5-bc60-3230dc87e2f0/export/?format=pdf",

    headers={"Host": "api.descg.store", "Authorization": f"Bearer {TOKEN}"}

)

try:

    resp = urllib.request.urlopen(req, timeout=15)

    print("status:", resp.status)

    print("headers:", dict(resp.headers))

    print("body:", resp.read()[:200])

except urllib.error.HTTPError as e:

    print("status:", e.code)

    print("content-type:", e.headers.get("content-type"))

    body = e.read()

    print("body bytes:", body)

    print("body repr:", repr(body))

    print("body len:", len(body))

