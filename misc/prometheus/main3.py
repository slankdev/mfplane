import csv, matplotlib.pyplot as plt, locale
locale.setlocale(locale.LC_TIME, '')
times = []
values = []
with open('up_metrics.csv', mode='r') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        times.append(float(row[0]))
        values.append(float(row[1]))

plt.plot(times, values, 'o-')
plt.xlabel('Time (s)')
plt.ylabel('up')
plt.title('Up Metrics')
plt.savefig('up_metrics.png')
