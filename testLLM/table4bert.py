import numpy as np
import os
FRACTIONAL_BITS = 16
TOTAL_BITS = 24
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

def encode_fixed_np(val):
    fixed = np.round(val * SCALE)
    fixed = np.clip(fixed, INT_MIN, INT_MAX)
    fixed = np.where(fixed < 0, fixed + FIELD_SIZE, fixed)
    fixed = fixed.astype(np.int64)
    return fixed & (FIELD_SIZE - 1)
def decode_fixed(val):
    if val >= (1 << (TOTAL_BITS - 1)):
        val -= FIELD_SIZE
    return val / SCALE

def decode_fixed_np(val):
    val_copy = val.copy()
    mask = val_copy >= (1 << (TOTAL_BITS - 1))
    val_copy[mask] -= FIELD_SIZE
    return val_copy / SCALE
def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def tanh(x):
    return np.tanh(x)

def gelu(x):
    return 0.5 * x * (1 + np.tanh(np.sqrt(2 / np.pi) * (x + 0.044715 * np.power(x, 3))))

def inv(x):
    with np.errstate(divide='ignore', invalid='ignore'):
        return np.where(x != 0, 1 / x, 0)

def sqrt(x):
    return np.sqrt(np.maximum(x, 0))

def silu(x):
    return x * sigmoid(x)

def softmax(x):
    return np.exp(x) / (np.exp(x) + 1)

activation_functions = {
    "relu": relu,
    "sigmoid": sigmoid,
    "tanh": tanh,
    "gelu": gelu,
    "inverse": inv,
    "sqrt": sqrt,
    "silu": silu,
    "softmax": softmax,
}

OUTPUT_DIR = "../bin"
os.makedirs(OUTPUT_DIR, exist_ok=True)

for name, func in activation_functions.items():
    print(f"为 BERT.py 生成 {name} 查找表 (lookup table)")
    print(f"Generating lookup table for: {name}")
    
    encoded_inputs = np.arange(FIELD_SIZE, dtype=np.int64)
    float_inputs = decode_fixed_np(encoded_inputs)
    
    a = -2
    print(a)
    aa = encode_fixed(a)
    print(aa)
    fa = func(a)
    print(fa)
    faa = encode_fixed(fa)
    print(faa)
    
    float_outputs = func(float_inputs)
    encoded_outputs = encode_fixed_np(float_outputs)
    print(f"  Output range: max = {np.max(encoded_outputs)}, min = {np.min(encoded_outputs)}")
    print(f"  Decoded float range: min = {np.min(float_inputs):.6f}, max = {np.max(float_inputs):.6f}")
    table_path = os.path.join(OUTPUT_DIR, f'table_{name}.txt')
    with open(table_path, 'wb') as f:
        f.write(encoded_outputs.tobytes())
    
    print(f"  Table saved to: {table_path}")
    print("--------------------------------------------------")