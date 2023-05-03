#!/usr/bin/env python3
import requests, json, csv
from datetime import datetime, timedelta

url = 'http://localhost:9090/api/v1/query_range'
query = 'rate(mfplane_receive_pkts{netns=~"N.*"}[10s])'
end_time = datetime.now()
start_time = end_time - timedelta(seconds=10)
#start_time = end_time - timedelta(minutes=1)
start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
params = {
    'query': query,
    'start': start_time_str,
    'end': end_time_str,
    'step': '100ms'
}

response = requests.get(url, params=params)
result = json.loads(response.text)['data']['result']
print(json.dumps(result))

# import pprint
# pprint.pprint(result)

# with open('receive_pkts_rate.csv', mode='w', newline='') as f:
#     writer = csv.writer(f)
#     writer.writerow(['time', 'rate'])
#     for r in result[0]['values']:
#         writer.writerow([float(r[0]) / 1000, float(r[1])])
    

