
import urllib.request

TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzgwODM4NDg1LCJpYXQiOjE3ODA4MzY2ODUsImp0aSI6IjJkNGJhMDk1NTE5ZDQ2MGNhNzExMDZkMzEwYjg4Yzc0IiwidXNlcl9pZCI6IjY4MTk4NjMwLTdlNGEtNDcyMS1hODdjLTM4NzI0OTU4Mjk5YiJ9.Y3wK3FRhB8ijnZaHC_NkZltonan9TJEkUw67rlc-1LY'

req = urllib.request.Request(

    'http://localhost:8000/api/v1/analysis/reports/08f06463-ae8f-4df5-bc60-3230dc87e2f0/export/?format=pdf',

    headers={'Host': 'api.descg.store', 'Authorization': f'Bearer {TOKEN}'}

)

resp = urllib.request.urlopen(req, timeout=15)

print('status:', resp.status)

print('content-type:', resp.headers.get('content-type'))

data = resp.read()

print('first 8 bytes:', data[:8])

print('size:', len(data))

