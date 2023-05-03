import requests
import csv
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

# PrometheusエンドポイントのURL
prometheus_url = 'http://localhost:9090/api/v1/query_range'

# クエリ
query = 'rate(mfplane_receive_pkts{netns=~"N.*"}[10s])'

# データの開始時刻と終了時刻（1分間）
end_time = datetime.now()
start_time = end_time - timedelta(minutes=1)

# PromQL形式の開始時刻と終了時刻
start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

# HTTPリクエストのパラメータ
params = {
    'query': query,
    'start': start_time_str,
    'end': end_time_str,
    'step': '100ms'
}

# HTTPリクエストを送信してレスポンスを取得
response = requests.get(prometheus_url, params=params)

# レスポンスから結果を取得
result = response.json()['data']['result']

# 結果をCSVファイルに書き込む
with open('up_metrics.csv', mode='w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp', 'value'])
    for r in result[0]['values']:
        timestamp = datetime.fromtimestamp(float(r[0])).strftime('%Y-%m-%d %H:%M:%S')
        value = r[1]
        writer.writerow([timestamp, value])

# CSVファイルからデータを読み込む
timestamps = []
values = []
with open('up_metrics.csv', mode='r') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        timestamps.append(row[0])
        values.append(float(row[1]))

# データをグラフに描画
plt.plot(timestamps, values)
plt.xlabel('Time')
plt.ylabel('up')
plt.title('Up Metrics')
plt.savefig('up_metrics.png')

