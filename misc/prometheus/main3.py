import requests,csv,datetime,matplotlib.pyplot as plt,locale
locale.setlocale(locale.LC_TIME, '')

prometheus_url = 'http://localhost:9090/api/v1/query_range'
query = 'rate(mfplane_receive_pkts{netns=~"N.*"}[10s])'
end_time = datetime.datetime.now()
start_time = end_time - datetime.timedelta(minutes=1)
start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

params = {
    'query': query,
    'start': start_time_str,
    'end': end_time_str,
    'step': '15s'
}

response = requests.get(prometheus_url, params=params)
result = response.json()['data'].get('result', [])

if not result:
    print('No result found')
else:
    with open('up_metrics.csv', mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['time', 'value'])
        for r in result[0]['values']:
            timestamp = datetime.datetime.fromtimestamp(float(r[0]))
            time = (timestamp - start_time).total_seconds()
            value = r[1]
            writer.writerow([time, value])

    times = []
    values = []
    with open('up_metrics.csv', mode='r') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            times.append(float(row[0]))
            values.append(float(row[1]))

    plt.plot(times, values)
    plt.xlabel('Time (s)')
    plt.ylabel('up')
    plt.title('Up Metrics')
    plt.savefig('up_metrics.png')
