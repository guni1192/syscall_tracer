#!/usr/bin/env python3

import matplotlib.pyplot as plt
import numpy as np
import json
import sys

line = input()
print(line)
data = json.loads(line)
print(data)
x = data["syscalls"].keys()
y = data["syscalls"].values()
plt.bar(x, y)
plt.show()
