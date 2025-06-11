import numpy as np
import os

FRACTIONAL_BITS = 16
TOTAL_BITS = 24
SCALE = 1 << FRACTIONAL_BITS
INT_MIN = -(1 << (TOTAL_BITS - 1))
INT_MAX = (1 << (TOTAL_BITS - 1)) - 1

def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    with np.errstate(over='ignore'):
        return 1 / (1 + np.exp(-x))

def tanh_fn(x):
    return np.tanh(x)

def gelu(x):
    return 0.5 * x * (1 + np.tanh(np.sqrt(2/np.pi) * (x + 0.044715 * np.power(x, 3))))

def inv_fn(x):
    with np.errstate(divide='ignore', invalid='ignore'):
        return np.where(x != 0, 1 / x, 0)

def sqrt_fn(x):
    return np.sqrt(np.maximum(x, 0))

def exp_fn(x):
    with np.errstate(over='ignore'):
        return np.exp(x)

def log_fn(x):
    with np.errstate(divide='ignore', invalid='ignore'):
        return np.where(x > 0, np.log(x), 0)

def pow_fn(x):
    return np.power(x, 2)

activation_functions = {
    "relu": relu,
    "sigmoid": sigmoid,
    "tanh": tanh_fn,
    "gelu": gelu,
    "div": inv_fn,
    "sqrt": sqrt_fn,
    "exp": exp_fn,
    "log": log_fn,
    "pow": pow_fn,
}

activation_domains = {
    "relu": (-8.0, 8.0),
    "sigmoid": (-8.0, 8.0),
    "tanh": (-8.0, 8.0),
    "gelu": (-8.0, 8.0),
    "div": (1/64, 64.0),
    "sqrt": (0.0, 64.0),
    "exp": (-8.0, 8.0),
    "log": (1/64, 64.0),
    "pow": (-8.0, 8.0),
}

STEPS = 2**24

OUTPUT_DIR = "../bin"
os.makedirs(OUTPUT_DIR, exist_ok=True)

for name, func in activation_functions.items():
    domain = activation_domains[name]
    x = np.linspace(domain[0], domain[1], STEPS)
    y = func(x)

    y_fixed = np.round(y * SCALE).astype(np.int64)

    y_fixed = np.where(y_fixed < 0, (1 << TOTAL_BITS) + y_fixed, y_fixed)
    y_fixed = y_fixed & ((1 << TOTAL_BITS) - 1)

    table_path = os.path.join(OUTPUT_DIR, f"table_{name}.txt")
    with open(table_path, "w") as f:
        for val in y_fixed:
            f.write(f"{val}\n")

    print(f"[+] Generated: {table_path}")
