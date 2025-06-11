import numpy as np

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def sigmoid_derivative(x):
    s = sigmoid(x)
    return s * (1 - s)

num_entries = 512
xmin, xmax = -8.0, 8.0  
x_values = np.linspace(xmin, xmax, num_entries)

scale = 1 << 16  

with open("table_main.txt", "w") as f_main, open("table_derivative.txt", "w") as f_der:
    for x in x_values:
        y = sigmoid(x)
        dy = sigmoid_derivative(x)
        fy = int(round(y * scale)) % (1 << 32)
        fdy = int(round(dy * scale)) % (1 << 32)
        f_main.write(str(fy) + "\n")
        f_der.write(str(fdy) + "\n")
