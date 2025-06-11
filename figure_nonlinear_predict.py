import matplotlib.pyplot as plt
import numpy as np
from scipy.optimize import curve_fit

# Enhanced color palette
colors = {
    'mascot': '#4C72B0',
    'spdz2k': '#DD8452',
    'lut': '#55A868',
    'prediction': '#C44E52'
}

# Data setup
parties = np.array([2, 4, 8])
pred_parties = np.array([2, 4, 8, 16, 32, 64])

# GeLU Function Data
# Online Phase
mascot_time_online = np.array([0.094592, 0.260378, 2.699784])
spdz2k_time_online = np.array([0.435504, 1.097729, 26.26254])
lut_time_online = np.array([2.301711, 4.76952, 11.561211])

mascot_comm_online = np.array([12.2207, 36.6622, 85.545])
spdz2k_comm_online = np.array([29.3453, 88.0383, 205.433])
lut_comm_online = np.array([1.187965, 3.563896, 8.315758])

# Offline Phase
mascot_time_offline = np.array([0.001914, 0.008959, 0.060028])
spdz2k_time_offline = np.array([0.004141, 0.009852, 0.631586])
lut_time_offline = np.array([0.001945, 0.002321, 0.004792])

mascot_comm_offline = np.array([0.00094, 0.00282, 0.00658])
spdz2k_comm_offline = np.array([0.001354, 0.004062, 0.009478])
lut_comm_offline = np.array([0.000313, 0.000938, 0.00219])

# Define exponential growth function for prediction
def exp_growth(x, a, b):
    return a * np.exp(b * x)

# Fit curves for predictions
# Online Time
popt_mascot_time_online, _ = curve_fit(exp_growth, parties, mascot_time_online)
popt_spdz2k_time_online, _ = curve_fit(exp_growth, parties, spdz2k_time_online)
popt_lut_time_online, _ = curve_fit(exp_growth, parties, lut_time_online)

# Online Comm
popt_mascot_comm_online, _ = curve_fit(exp_growth, parties, mascot_comm_online)
popt_spdz2k_comm_online, _ = curve_fit(exp_growth, parties, spdz2k_comm_online)
popt_lut_comm_online, _ = curve_fit(exp_growth, parties, lut_comm_online)

# Offline Time
popt_mascot_time_offline, _ = curve_fit(exp_growth, parties, mascot_time_offline)
popt_spdz2k_time_offline, _ = curve_fit(exp_growth, parties, spdz2k_time_offline)
popt_lut_time_offline, _ = curve_fit(exp_growth, parties, lut_time_offline)

# Offline Comm
popt_mascot_comm_offline, _ = curve_fit(exp_growth, parties, mascot_comm_offline)
popt_spdz2k_comm_offline, _ = curve_fit(exp_growth, parties, spdz2k_comm_offline)
popt_lut_comm_offline, _ = curve_fit(exp_growth, parties, lut_comm_offline)

# Create predictions
pred_mascot_time_online = exp_growth(pred_parties, *popt_mascot_time_online)
pred_spdz2k_time_online = exp_growth(pred_parties, *popt_spdz2k_time_online)
pred_lut_time_online = exp_growth(pred_parties, *popt_lut_time_online)

pred_mascot_comm_online = exp_growth(pred_parties, *popt_mascot_comm_online)
pred_spdz2k_comm_online = exp_growth(pred_parties, *popt_spdz2k_comm_online)
pred_lut_comm_online = exp_growth(pred_parties, *popt_lut_comm_online)

pred_mascot_time_offline = exp_growth(pred_parties, *popt_mascot_time_offline)
pred_spdz2k_time_offline = exp_growth(pred_parties, *popt_spdz2k_time_offline)
pred_lut_time_offline = exp_growth(pred_parties, *popt_lut_time_offline)

pred_mascot_comm_offline = exp_growth(pred_parties, *popt_mascot_comm_offline)
pred_spdz2k_comm_offline = exp_growth(pred_parties, *popt_spdz2k_comm_offline)
pred_lut_comm_offline = exp_growth(pred_parties, *popt_lut_comm_offline)

# Plotting function
def create_plot(x, y1, y2, y3, pred1, pred2, pred3, title, ylabel, logy=True):
    plt.figure(figsize=(10, 6))
    plt.plot(x[:3], y1, color=colors['mascot'], marker='o', linestyle='-', linewidth=2, label='MASCOT (Actual)')
    plt.plot(x[:3], y2, color=colors['spdz2k'], marker='s', linestyle='-', linewidth=2, label='SPDZ2K (Actual)')
    plt.plot(x[:3], y3, color=colors['lut'], marker='^', linestyle='-', linewidth=2, label='LUT (Actual)')
    
    plt.plot(x, pred1, color=colors['mascot'], linestyle='--', linewidth=1.5, alpha=0.7, label='MASCOT (Predicted)')
    plt.plot(x, pred2, color=colors['spdz2k'], linestyle='--', linewidth=1.5, alpha=0.7, label='SPDZ2K (Predicted)')
    plt.plot(x, pred3, color=colors['lut'], linestyle='--', linewidth=1.5, alpha=0.7, label='LUT (Predicted)')
    
    plt.xlabel('Number of Parties', fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.title(f'GeLU Function - {title}', fontsize=14, pad=20)
    
    if logy:
        plt.yscale('log')
    
    plt.grid(True, which="both", ls="--", alpha=0.3)
    plt.legend(fontsize=10)
    plt.xticks(x, fontsize=10)
    plt.yticks(fontsize=10)
    
    # Add vertical line to separate actual and predicted
    plt.axvline(x=8.5, color='gray', linestyle=':', linewidth=1)
    plt.text(8.7, plt.gca().get_ylim()[1]*0.1, 'Prediction', rotation=90, fontsize=10)
    
    plt.tight_layout()
    plt.show()

# Create all four plots
create_plot(pred_parties, mascot_time_online, spdz2k_time_online, lut_time_online,
            pred_mascot_time_online, pred_spdz2k_time_online, pred_lut_time_online,
            'Online Phase Computation Time', 'Time (s)')

create_plot(pred_parties, mascot_comm_online, spdz2k_comm_online, lut_comm_online,
            pred_mascot_comm_online, pred_spdz2k_comm_online, pred_lut_comm_online,
            'Online Phase Communication', 'Data (MB)')

create_plot(pred_parties, mascot_time_offline, spdz2k_time_offline, lut_time_offline,
            pred_mascot_time_offline, pred_spdz2k_time_offline, pred_lut_time_offline,
            'Offline Phase Computation Time', 'Time (s)')

create_plot(pred_parties, mascot_comm_offline, spdz2k_comm_offline, lut_comm_offline,
            pred_mascot_comm_offline, pred_spdz2k_comm_offline, pred_lut_comm_offline,
            'Offline Phase Communication', 'Data (MB)')