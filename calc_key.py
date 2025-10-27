#!/usr/bin/env python3
"""
RSSI-based Key Generation - Calculate Key
Generate binary key from RSSI measurements using statistical thresholding
"""

import json
import argparse
import numpy as np
import sys

def load_rssi_measurements(filename):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        # Convert string keys back to integers
        measurements = {int(k): v for k, v in data['measurements'].items()}
        role = data.get('role', 'UNKNOWN')
        
        return measurements, role
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {filename}")
        sys.exit(1)


def calculate_statistics(rssi_values):
    mean = np.mean(rssi_values)
    std_dev = np.std(rssi_values, ddof=1)  # Sample std dev (n-1)
    
    return mean, std_dev


def generate_key_bits(measurements, z_threshold):
    """
    Generate binary key from RSSI measurements.
    
    Returns:
        key_bits: dict mapping {index: bit_value} for indices used
        key_string: binary string representation of key
        stats: dictionary with statistics
    """
    # Get all RSSI values
    indices = sorted(measurements.keys())
    rssi_values = [measurements[idx] for idx in indices]
    
    mean, std_dev = calculate_statistics(rssi_values)
    upper_threshold = mean + (z_threshold * std_dev)
    lower_threshold = mean - (z_threshold * std_dev)
    
    key_bits = {}  
    key_string = ""
    
    indices_used = []
    indices_too_close_to_mean = []
    
    for idx in indices:
        rssi = measurements[idx]
        
        if rssi > upper_threshold:
            #strong
            key_bits[idx] = 1
            key_string += "1"
            indices_used.append(idx)
        elif rssi < lower_threshold:
            # Weak signal 
            key_bits[idx] = 0
            key_string += "0"
            indices_used.append(idx)
        else:
            #not enough strong or weak
            indices_too_close_to_mean.append(idx)
    
    stats = {
        'total_measurements': len(measurements),
        'mean_rssi': mean,
        'std_dev_rssi': std_dev,
        'z_threshold': z_threshold,
        'upper_threshold': upper_threshold,
        'lower_threshold': lower_threshold,
        'key_length': len(key_bits),
        'num_ones': sum(key_bits.values()),
        'num_zeros': len(key_bits) - sum(key_bits.values()),
        'indices_used': indices_used,
        'indices_discarded': indices_too_close_to_mean,
        'utilization_rate': len(key_bits) / len(measurements) if measurements else 0
    }
    
    return key_bits, key_string, stats


def save_key_data(key_bits, key_string, stats, role, filename):
    # Calculate balance ratio
    balance_ratio = stats['num_ones'] / stats['num_zeros'] if stats['num_zeros'] > 0 else float('inf')
    
    # Assess key quality
    quality, warnings = assess_key_quality(key_string, stats)
    
    output = {
        'role': role,
        'key_string': key_string,
        'key_length': len(key_string),
        'key_bits': {str(k): v for k, v in key_bits.items()},
        'key_quality': {
            'assessment': quality,
            'balance_ratio': float(balance_ratio) if balance_ratio != float('inf') else None,
            'warnings': warnings
        },
        'statistics': {
            'total_measurements': stats['total_measurements'],
            'mean_rssi': float(stats['mean_rssi']),
            'std_dev_rssi': float(stats['std_dev_rssi']),
            'z_threshold': stats['z_threshold'],
            'upper_threshold': float(stats['upper_threshold']),
            'lower_threshold': float(stats['lower_threshold']),
            'key_length': stats['key_length'],
            'num_ones': stats['num_ones'],
            'num_zeros': stats['num_zeros'],
            'utilization_rate': float(stats['utilization_rate'])
        },
        'indices_used': stats['indices_used'],
        'indices_discarded': stats['indices_discarded']
    }
    
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n✓ Key data saved to {filename}")
    
    # Save indices for bit reconciliation
    indices_file = filename.replace('.json', '_indices.json')
    reconciliation_data = {
        'role': role,
        'indices_used': stats['indices_used'],
        'key_bits_for_reconciliation': {str(k): v for k, v in key_bits.items()},
        'total_key_length': len(key_string)
    }
    
    with open(indices_file, 'w') as f:
        json.dump(reconciliation_data, f, indent=2)
    
    print(f"✓ Bit reconciliation data saved to {indices_file}")
    
    # Save indices used in text format as well
    indices_text_file = filename.replace('.json', '_indices.txt')
    with open(indices_text_file, 'w') as f:
        f.write(f"# Key Bits Used - Role: {role}\n")
        f.write(f"# Format: index,bit_value\n")
        f.write("#" + "=" * 30 + "\n\n")
        
        # Sort indices and write each index with its bit value
        sorted_key_indices = sorted(key_bits.keys())
        for idx in sorted_key_indices:
            bit_value = key_bits[idx]
            f.write(f"{idx},{bit_value}\n")
    
    print(f"✓ Key indices saved to {indices_text_file}")


def assess_key_quality(key_string, stats):
    """Assess the quality of the generated key"""
    if stats['key_length'] == 0:
        return "FAILED", ["No key bits generated"]
    
    warnings = []
    
    # Calculate balance ratio
    balance_ratio = stats['num_ones'] / stats['num_zeros'] if stats['num_zeros'] > 0 else float('inf')
    
    # Check key length
    if stats['key_length'] < 10:
        warnings.append(f"Very short key ({stats['key_length']} bits)")
    elif stats['key_length'] < 50:
        warnings.append(f"Short key ({stats['key_length']} bits)")
    
    # Check balance (should be close to 1.0 for good randomness)
    if balance_ratio < 0.3 or balance_ratio > 3.0:
        warnings.append(f"Unbalanced key (1s/0s ratio: {balance_ratio:.2f})")
    elif balance_ratio < 0.5 or balance_ratio > 2.0:
        warnings.append(f"Slightly unbalanced key (1s/0s ratio: {balance_ratio:.2f})")
    
    # Check utilization rate
    if stats['utilization_rate'] > 0.6:
        warnings.append(f"High utilization rate ({stats['utilization_rate']*100:.1f}%) - may include noise")
    elif stats['utilization_rate'] < 0.05:
        warnings.append(f"Very low utilization rate ({stats['utilization_rate']*100:.1f}%)")
    
    # Overall quality assessment
    if not warnings:
        quality = "EXCELLENT"
    elif len(warnings) == 1 and "Short key" in warnings[0]:
        quality = "GOOD"
    elif len(warnings) <= 2:
        quality = "FAIR"
    else:
        quality = "POOR"
    
    return quality, warnings


def display_results(key_string, stats, role):
    """Display key generation results"""
    print("\n" + "=" * 70)
    print(f"Key Generation Results - Role: {role}")
    print("=" * 70)
    
    print(f"\nRSSI Statistics:")
    print(f"  Total measurements: {stats['total_measurements']}")
    print(f"  Mean RSSI: {stats['mean_rssi']:.2f} dBm")
    print(f"  Std Dev: {stats['std_dev_rssi']:.2f} dBm")
    
    print(f"\nThreshold Parameters:")
    print(f"  Z-threshold: {stats['z_threshold']}")
    print(f"  Upper threshold (mean + z*σ): {stats['upper_threshold']:.2f} dBm")
    print(f"  Lower threshold (mean - z*σ): {stats['lower_threshold']:.2f} dBm")
    
    print(f"\nKey Generation Results:")
    print(f"  Key length: {stats['key_length']} bits")
    print(f"  Number of 1s: {stats['num_ones']}")
    print(f"  Number of 0s: {stats['num_zeros']}")
    print(f"  Utilization rate: {stats['utilization_rate']*100:.1f}%")
    print(f"  Discarded indices: {len(stats['indices_discarded'])}")
    
    # Calculate and display balance ratio
    if stats['num_zeros'] > 0:
        balance_ratio = stats['num_ones'] / stats['num_zeros']
        print(f"  Balance ratio (1s/0s): {balance_ratio:.3f}")
    else:
        print(f"  Balance ratio (1s/0s): ∞ (no zeros)")
    
    # Key quality assessment
    quality, warnings = assess_key_quality(key_string, stats)
    print(f"\nKey Quality: {quality}")
    if warnings:
        print(f"  Warnings:")
        for warning in warnings:
            print(f"    - {warning}")
    
    print(f"\nGenerated Key (first 100 bits):")
    if len(key_string) > 100:
        print(f"  {key_string[:100]}...")
    else:
        print(f"  {key_string}")
    
    print(f"\nFull key length: {len(key_string)} bits")
    print("=" * 70)


def analyze_z_threshold_impact(measurements):
    print("\n" + "=" * 70)
    print("Z-Threshold Impact Analysis")
    print("=" * 70)
    print("\nTesting different z-threshold values...\n")
    
    z_values = [0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5]
    
    print(f"{'z Value':<10} {'Key Length':<12} {'Utilization':<15} {'Balance (1s/0s)':<20}")
    print("-" * 70)
    
    for z in z_values:
        key_bits, key_string, stats = generate_key_bits(measurements, z)
        
        if stats['key_length'] > 0:
            balance = f"{stats['num_ones']}/{stats['num_zeros']}"
            balance_ratio = stats['num_ones'] / stats['num_zeros'] if stats['num_zeros'] > 0 else float('inf')
        else:
            balance = "N/A"
            balance_ratio = 0
        
        util_pct = stats['utilization_rate'] * 100
        
        print(f"{z:<10} {stats['key_length']:<12} {util_pct:<14.1f}% {balance:<20}")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='Generate binary key from RSSI measurements',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
  Recommended values:
  Assuming GAUSSIAN distributions
    z = 0.5  : 38% of data used
    z = 0.75 : 27% of data used
    z = 1.0  : ~16% of data used
    z = 1.5  : ~7% of data used
    z = 2.0  : ~2.5% of data used
        """
    )
    
    parser.add_argument('--input', type=str, default='rssi_measurements.json',
                        help='Input JSON file with RSSI measurements')
    parser.add_argument('--z', type=float, default=1.0,
                        help='Z-threshold (number of standard deviations, default: 1.0)')
    parser.add_argument('--output', type=str, default='key_data.json',
                        help='Output JSON file for key data')
    parser.add_argument('--analyze', action='store_true',
                        help='Analyze impact of different z-threshold values')
    
    args = parser.parse_args()
    
    print("\nRSSI-Based Key Generation - Calculate Key")
    print("=" * 70)
    
    print(f"\nLoading RSSI measurements from {args.input}...")
    measurements, role = load_rssi_measurements(args.input)
    print(f"Loaded {len(measurements)} RSSI measurements")
    print(f"Device role: {role}")
    
    # Analyze z-threshold impact if requested
    if args.analyze:
        analyze_z_threshold_impact(measurements)
        print("\nRecommendation: Use z=1.0 for a good balance of key length and reliability")
        return
    
    print(f"\nGenerating key with z-threshold = {args.z}...")
    key_bits, key_string, stats = generate_key_bits(measurements, args.z)
    
    display_results(key_string, stats, role)
    save_key_data(key_bits, key_string, stats, role, args.output)
    
    # Enhanced warnings and recommendations using quality assessment
    quality, warnings = assess_key_quality(key_string, stats)
    
    if quality == "FAILED":
        print("\n FAILED: No key bits generated!")
        print("  Recommendation: Try using a lower z-threshold value (e.g., --z 0.75)")
        return
    elif quality == "POOR":
        print("\n WARNING: Poor key quality detected!")
        for warning in warnings:
            print(f"    - {warning}")
        print("  Recommendation: Consider adjusting z-threshold or collecting more data")
    elif quality == "FAIR":
        print("\n NOTICE: Fair key quality - some issues detected")
        for warning in warnings:
            print(f"    - {warning}")
    elif quality == "GOOD":
        print("\n SUCCESS: Key generated successfully with minor issues")
    else:  # EXCELLENT
        print("\n SUCCESS: High-quality key generated!")
    
    # Validate key string for cryptographic use
    if len(key_string) >= 10:
        print(f"\n Key length adequate for uses ({len(key_string)} bits)")
    else:
        print(f"\n Key may be too short for secure cryptographic use ({len(key_string)} bits)")
    
    print(f"\nGenerated key string hash: {hash(key_string) & 0xFFFFFFFF:08x}")
    print(f"Key entropy estimate: ~{len(key_string)} bits (assuming uniform distribution)")
    
    print(f"\nNext step: Run bit reconciliation to find common indices")
    print(f"  Both devices should now run: python3 reconcile_bits.py")


if __name__ == "__main__":
    main()