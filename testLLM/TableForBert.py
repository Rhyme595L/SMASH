import numpy as np
import os

FRACTIONAL_BITS = 16
TOTAL_BITS = 22
SCALE = 1 << FRACTIONAL_BITS
INT_MIN = -(1 << (TOTAL_BITS - 1))
INT_MAX = (1 << (TOTAL_BITS - 1)) - 1 
FIELD_SIZE = 1 << TOTAL_BITS
def encode_fixed(val):
    fixed = int(np.round(val * SCALE))
    fixed = max(INT_MIN, min(INT_MAX, fixed))
    if fixed < 0:
        fixed += FIELD_SIZE
    return np.int64(fixed & (FIELD_SIZE - 1))
def decode_fixed(val):
    if val >= (1 << (TOTAL_BITS - 1)):
        val -= FIELD_SIZE
    return val / SCALE
def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def tanh(x):
    return np.tanh(x)

def gelu(x):
    return 0.5 * x * (1 + np.tanh(np.sqrt(2/np.pi) * (x + 0.044715 * np.power(x, 3))))

def inv(x):
    with np.errstate(divide='ignore', invalid='ignore'):
        return np.where(x != 0, 1 / x, 0)

def sqrt(x):
    return np.sqrt(np.maximum(x, 0))

activation_functions = {
    "relu": relu,
    "sigmoid": sigmoid,
    "tanh": tanh,
    "gelu": gelu,
    "inverse": inv,
    "sqrt": sqrt,
}
activation_domains = {
    "relu": (-8.0, 8.0),
    "sigmoid": (-8.0, 8.0),
    "tanh": (-8.0, 8.0),
    "gelu": (-8.0, 8.0),
    "inverse": (1/64, 64.0),
    "sqrt": (0.0, 64.0),
}
STEPS = 2**22  
OUTPUT_DIR = "../bin"
os.makedirs(OUTPUT_DIR, exist_ok=True)
for name, func in activation_functions.items():
    xmin, xmax = activation_domains[name]
    delta = (xmax - xmin) / FIELD_SIZE

    base_table = np.zeros(FIELD_SIZE, dtype=np.uint64)
    
    for i in range(FIELD_SIZE):
        x_base = xmin + (i + 0.5) * delta
        y_base = func(x_base)
        base_enc = encode_fixed(y_base)
        base_table[i] = base_enc
    print(f"Function: {name}")
    print(f"  Base table: max = {np.max(base_table)}, min = {np.min(base_table)}")
    
    with open(os.path.join(OUTPUT_DIR, f'table_{name}.txt'), 'wb') as f:
        f.write(base_table.tobytes())