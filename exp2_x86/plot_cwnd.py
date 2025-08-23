import matplotlib.pyplot as plt
import numpy as np

f = open("cwnd.txt")
times = []
cwnds = []
count = 0
for line in f:
    time_us, cwnd, ssthresh, adv_wnd = map(int, line.split())
    times.append(time_us)
    cwnds.append(cwnd)
    count = count + 1
    if(count > 5000):
        break
f.close()
plt.plot(times, cwnds, marker='o', color='red')
plt.plot(times, cwnds, linestyle='-', color='blue')
plt.xlabel("Time (us)")
plt.ylabel("Congestion Window (bytes)")
plt.title("TCP Congestion Window over Time")
plt.show()
