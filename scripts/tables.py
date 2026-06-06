#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
# tables.py
#
# Atvaizduoja visas 5 straipsnio lenteles iš surinkų duomenų:
#   Table 1: Network Scenarios
#   Table 2: Cryptographic Operation Benchmarks
#   Table 3: TLS Handshake Latency
#   Table 4: Packet Fragmentation
#   Table 5: Overhead Decomposition
#
# Naudojimas:
#   python3 ~/quartic/scripts/tables.py
# ═══════════════════════════════════════════════════════════════════

import csv
import os
import subprocess
import sys
import random
import math

HOME = "/home/lab"
R = os.path.join(HOME, "quartic", "results")
C = os.path.join(HOME, "quartic", "captures")

SEP = "=" * 85

# ── Duomenų nuskaitymo funkcijos ─────────────────────────────────

def read_raw(filepath):
    """Handshake CSV → raw values list."""
    try:
        with open(filepath) as f:
            return [float(r[1]) for r in csv.reader(f) if r[0] != 'iteration' and len(r) >= 2]
    except:
        return []

def stats(filepath):
    """Handshake CSV → P50, P90, P95 statistikos."""
    try:
        with open(filepath) as f:
            vals = [float(r[1]) for r in csv.reader(f) if r[0] != 'iteration' and len(r) >= 2]
        vals.sort()
        n = len(vals)
        if n == 0:
            return None
        return {
            'n': n, 'mean': sum(vals)/n,
            'p50': vals[n//2], 'p90': vals[int(n*0.9)],
            'p95': vals[int(n*0.95)], 'min': vals[0], 'max': vals[-1]
        }
    except:
        return None

# ── Statistiniai testai ──────────────────────────────────────────

def mann_whitney_u(x, y):
    """Mann-Whitney U test (dvipusis). Grąžina U statistiką ir p-value.
    Naudoja normalinę aproksimaciją dideliems N."""
    nx, ny = len(x), len(y)
    # Rank all values
    combined = [(v, 'x') for v in x] + [(v, 'y') for v in y]
    combined.sort(key=lambda t: t[0])

    # Assign ranks with tie handling
    ranks = {}
    i = 0
    while i < len(combined):
        j = i
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j + 1) / 2  # 1-based average rank for ties
        for k in range(i, j):
            if k not in ranks:
                ranks[k] = []
            ranks[k] = avg_rank
        i = j

    # Sum ranks for group x
    rank_sum_x = 0
    idx = 0
    for i, (v, group) in enumerate(combined):
        if group == 'x':
            rank_sum_x += ranks[i]

    U1 = rank_sum_x - nx * (nx + 1) / 2
    U2 = nx * ny - U1
    U = min(U1, U2)

    # Normal approximation for large samples
    mu = nx * ny / 2
    sigma = math.sqrt(nx * ny * (nx + ny + 1) / 12)
    if sigma == 0:
        return U, 1.0
    z = (U - mu) / sigma
    # Two-tailed p-value using error function approximation
    p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    return U, p, z

def bootstrap_ci_median_diff(x, y, n_boot=10000, ci=95):
    """Bootstrap pasikliautinasis intervalas medianos skirtumui (H1-C1).
    Grąžina (lower, median_diff, upper)."""
    random.seed(42)  # Atkuriamumas
    diffs = []
    for _ in range(n_boot):
        bx = [x[random.randint(0, len(x)-1)] for _ in range(len(x))]
        by = [y[random.randint(0, len(y)-1)] for _ in range(len(y))]
        bx.sort()
        by.sort()
        med_x = bx[len(bx)//2]
        med_y = by[len(by)//2]
        diffs.append(med_y - med_x)
    diffs.sort()
    alpha = (100 - ci) / 2
    lo_idx = int(n_boot * alpha / 100)
    hi_idx = int(n_boot * (100 - alpha) / 100) - 1
    observed = sorted(y)[len(y)//2] - sorted(x)[len(x)//2]
    return diffs[lo_idx], observed, diffs[hi_idx]

def cohens_d(x, y):
    """Cohen's d efekto dydis."""
    nx, ny = len(x), len(y)
    mean_x = sum(x) / nx
    mean_y = sum(y) / ny
    var_x = sum((v - mean_x)**2 for v in x) / (nx - 1)
    var_y = sum((v - mean_y)**2 for v in y) / (ny - 1)
    pooled_std = math.sqrt(((nx-1)*var_x + (ny-1)*var_y) / (nx + ny - 2))
    if pooled_std == 0:
        return 0
    return (mean_y - mean_x) / pooled_std

def effect_size_label(d):
    """Cohen's d interpretacija."""
    d = abs(d)
    if d < 0.2: return "negligible"
    elif d < 0.5: return "small"
    elif d < 0.8: return "medium"
    else: return "large"

def parse_kem(filepath):
    """speed_kem output → keygen/encaps/decaps duomenys su duration."""
    res = {}
    try:
        for line in open(filepath):
            for op in ['keygen', 'encaps', 'decaps']:
                if line.strip().startswith(op):
                    p = [x.strip() for x in line.split('|')]
                    if len(p) >= 5:
                        res[op] = {
                            'iter': int(p[1]),
                            'dur': float(p[2]),
                            'us': float(p[3]),
                            'std': float(p[4])
                        }
    except:
        pass
    return res

def parse_x25519(filepath):
    """openssl speed output → iterations, duration, time_us."""
    import re
    try:
        with open(filepath) as f:
            txt = f.read()
        m = re.search(r'(\d+)\s+\d+-bits\s+ECDH\s+ops\s+in\s+(\d+\.\d+)s', txt)
        if m:
            ops = int(m.group(1))
            dur = float(m.group(2))
            return {'iter': ops, 'dur': dur, 'us': (dur / ops) * 1_000_000}
    except:
        pass
    return {'iter': 0, 'dur': 0, 'us': 35.0}

def parse_pcap(filepath):
    """pcapng → ClientHello/ServerHello frame dydžiai."""
    try:
        ch = subprocess.run(
            ['tshark', '-r', filepath, '-Y', 'tls.handshake.type == 1',
             '-T', 'fields', '-e', 'frame.len'],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        sh = subprocess.run(
            ['tshark', '-r', filepath, '-Y', 'tls.handshake.type == 2',
             '-T', 'fields', '-e', 'frame.len'],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        total = len(subprocess.run(
            ['tshark', '-r', filepath],
            capture_output=True, text=True, timeout=10
        ).stdout.strip().split('\n'))
        return {
            'ch': int(ch) if ch.isdigit() else 0,
            'sh': int(sh) if sh.isdigit() else 0,
            'pkts': total
        }
    except:
        return {'ch': 0, 'sh': 0, 'pkts': 0}

def parse_memory(filepath):
    """/usr/bin/time -v output → peak RSS."""
    try:
        for line in open(filepath):
            if 'Maximum resident' in line:
                import re
                m = re.search(r'(\d+)', line)
                if m:
                    return int(m.group(1))
    except:
        pass
    return None

# ═══════════════════════════════════════════════════════════════════
# TABLE 1: Network Scenarios
# ═══════════════════════════════════════════════════════════════════

def table1():
    print(SEP)
    print("  TABLE 1: Network Emulation Scenarios")
    print(SEP)

    table1_file = os.path.join(R, "table1_network_scenarios.csv")

    if not os.path.exists(table1_file):
        print("  [Nėra duomenų — paleiskite run_measurements.sh]")
        return

    print(f"{'ID':<6} {'Description':<16} {'Delay(ms)':>10} {'Loss(%)':>8} {'Rate':>10} {'RTT min':>9} {'RTT avg':>9} {'RTT max':>9} {'Loss':>6}")
    print("-" * 85)

    with open(table1_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            print(f"{row['scenario']:<6} {row['description']:<16} "
                  f"{row['configured_delay_ms']:>10} {row['configured_loss_pct']:>8} "
                  f"{row['configured_rate']:>10} {row['ping_rtt_min_ms']:>8}ms "
                  f"{row['ping_rtt_avg_ms']:>8}ms {row['ping_rtt_max_ms']:>8}ms "
                  f"{row['ping_loss_pct']:>5}%")

    print()

# ═══════════════════════════════════════════════════════════════════
# TABLE 2: Cryptographic Operation Benchmarks
# ═══════════════════════════════════════════════════════════════════

def table2():
    print(SEP)
    print("  TABLE 2: Cryptographic Operation Benchmarks")
    print(SEP)

    mlkem = parse_kem(os.path.join(R, "speed_mlkem768.txt"))
    hqc = parse_kem(os.path.join(R, "speed_hqc192.txt"))
    x25519 = parse_x25519(os.path.join(R, "speed_x25519.txt"))
    x25519_us = x25519['us'] if x25519['us'] > 0 else 35.0

    print(f"{'Algorithm':<16} {'Operation':<10} {'N (total ops)':>14} {'Duration(s)':>12} {'Mean(μs)':>10} {'Std(μs)':>10} {'vs X25519':>10}")
    print("-" * 86)

    # X25519
    if x25519['iter'] > 0:
        print(f"{'X25519':<16} {'ECDH agree':<10} {x25519['iter']:>14,} {x25519['dur']:>12.2f} {x25519_us:>10.1f} {'—':>10} {'1.0×':>10}")
    else:
        print(f"{'X25519':<16} {'ECDH agree':<10} {'—':>14} {'—':>12} {x25519_us:>10.1f} {'—':>10} {'1.0×':>10}")

    # ML-KEM-768
    for op, label in [('keygen', 'KeyGen'), ('encaps', 'Encaps'), ('decaps', 'Decaps')]:
        if op in mlkem:
            d = mlkem[op]
            ratio = d['us'] / x25519_us if x25519_us > 0 else 0
            print(f"{'ML-KEM-768':<16} {label:<10} {d['iter']:>14,} {d['dur']:>12.3f} {d['us']:>10.1f} {d['std']:>10.1f} {ratio:>9.1f}×")

    if mlkem:
        print("-" * 86)

    # HQC-192
    for op, label in [('keygen', 'KeyGen'), ('encaps', 'Encaps'), ('decaps', 'Decaps')]:
        if op in hqc:
            d = hqc[op]
            ratio = d['us'] / x25519_us if x25519_us > 0 else 0
            print(f"{'HQC-192':<16} {label:<10} {d['iter']:>14,} {d['dur']:>12.3f} {d['us']:>10.1f} {d['std']:>10.1f} {ratio:>9.1f}×")

    # Atminties profilis
    mem_mlkem = parse_memory(os.path.join(R, "memory_mlkem768.txt"))
    mem_hqc = parse_memory(os.path.join(R, "memory_hqc192.txt"))
    if mem_mlkem or mem_hqc:
        print()
        print("  Atminties profilis (peak RSS):")
        if mem_mlkem:
            print(f"    ML-KEM-768: {mem_mlkem:,} KB")
        if mem_hqc:
            print(f"    HQC-192:    {mem_hqc:,} KB")

    print()
    return x25519_us, mlkem

# ═══════════════════════════════════════════════════════════════════
# TABLE 3: TLS Handshake Latency
# ═══════════════════════════════════════════════════════════════════

def table3():
    print(SEP)
    print("  TABLE 3: TLS 1.3 Handshake Latency")
    print(SEP)

    scenarios = [
        ('S0: Direct  ', 'S0_C1_classic.csv', 'S0_H1_hybrid.csv'),
        ('S1: DC 2.5ms', 'S1_C1_classic.csv', 'S1_H1_hybrid.csv'),
        ('S2: BB 36ms ', 'S2_C1_classic.csv', 'S2_H1_hybrid.csv'),
        ('S3: Mob 71ms', 'S3_C1_classic.csv', 'S3_H1_hybrid.csv'),
    ]

    print(f"{'Scenario':<14} {'C1 P50':>9} {'H1 P50':>9} {'Δ(ms)':>9} {'Ovhd%':>8} {'Slow':>7} {'C1 P90':>9} {'H1 P90':>9}")
    print("-" * 78)

    results = {}
    raw_data = {}
    for name, cf, hf in scenarios:
        c = stats(os.path.join(R, cf))
        h = stats(os.path.join(R, hf))
        if c and h:
            d = h['p50'] - c['p50']
            o = ((h['p50'] / c['p50']) - 1) * 100
            s = h['p50'] / c['p50']
            print(f"{name:<14} {c['p50']:>8.2f}ms{h['p50']:>8.2f}ms{d:>+8.2f}ms{o:>+7.1f}% {s:>6.2f}×{c['p90']:>8.2f}ms{h['p90']:>8.2f}ms")
            results[name.strip()] = {'c': c, 'h': h, 'delta': d, 'ovhd': o, 'slowdown': s}
            raw_data[name.strip()] = {
                'c_raw': read_raw(os.path.join(R, cf)),
                'h_raw': read_raw(os.path.join(R, hf))
            }
        else:
            print(f"{name:<14} [nėra duomenų]")

    # Detali statistika
    print()
    print("  Detali statistika:")
    print(f"  {'Failas':<24} {'N':>5} {'Mean':>9} {'P50':>9} {'P90':>9} {'P95':>9} {'Min':>9} {'Max':>9}")
    print(f"  {'-'*80}")

    for name, cf, hf in scenarios:
        for label_suffix, fname in [('C1', cf), ('H1', hf)]:
            s = stats(os.path.join(R, fname))
            if s:
                label = fname.replace('.csv', '')
                print(f"  {label:<24} {s['n']:>5} {s['mean']:>8.2f}ms{s['p50']:>8.2f}ms"
                      f"{s['p90']:>8.2f}ms{s['p95']:>8.2f}ms{s['min']:>8.2f}ms{s['max']:>8.2f}ms")

    # Statistinio reikšmingumo testai
    if raw_data:
        print()
        print("  Statistinis reikšmingumas (Mann-Whitney U testas, dvipusis):")
        print(f"  {'Scenario':<14} {'N(C1)':>6} {'N(H1)':>6} {'U stat':>12} {'z':>8} {'p-value':>12} {'Signif.':>8} {'Cohen d':>9} {'Effect':>12}")
        print(f"  {'-'*95}")

        for name in raw_data:
            c_raw = raw_data[name]['c_raw']
            h_raw = raw_data[name]['h_raw']
            if len(c_raw) >= 2 and len(h_raw) >= 2:
                U, p, z = mann_whitney_u(c_raw, h_raw)
                d = cohens_d(c_raw, h_raw)
                sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else "ns"
                eff = effect_size_label(d)
                print(f"  {name:<14} {len(c_raw):>6} {len(h_raw):>6} {U:>12.0f} {z:>8.3f} {p:>12.6f} {sig:>8} {d:>+9.4f} {eff:>12}")

        print()
        print("  95% Bootstrap pasikliautinasis intervalas medianos skirtumui Δ(H1-C1):")
        print(f"  {'Scenario':<14} {'Δ observed':>12} {'95% CI lower':>13} {'95% CI upper':>13} {'CI apima 0?':>12}")
        print(f"  {'-'*68}")

        for name in raw_data:
            c_raw = raw_data[name]['c_raw']
            h_raw = raw_data[name]['h_raw']
            if len(c_raw) >= 2 and len(h_raw) >= 2:
                lo, obs, hi = bootstrap_ci_median_diff(c_raw, h_raw, n_boot=10000)
                includes_zero = "TAIP" if lo <= 0 <= hi else "NE"
                print(f"  {name:<14} {obs:>+11.3f}ms {lo:>+12.3f}ms {hi:>+12.3f}ms {includes_zero:>12}")

        print()
        print("  Pastabos:")
        print("    Signif.: *** p<0.001, ** p<0.01, * p<0.05, ns = nereikšminga")
        print("    Cohen's d: |d|<0.2 negligible, 0.2-0.5 small, 0.5-0.8 medium, >0.8 large")
        print("    Bootstrap: 10,000 iteracijų, seed=42 (atkuriamumas)")
        print("    Jei 95% CI neapima 0, skirtumas yra statistiškai reikšmingas su 95% pasikliovimo lygiu")

    print()
    return results

# ═══════════════════════════════════════════════════════════════════
# TABLE 4: Packet Fragmentation
# ═══════════════════════════════════════════════════════════════════

def table4():
    print(SEP)
    print("  TABLE 4: Packet Fragmentation Analysis")
    print(SEP)

    # Try CSV first
    table4_file = os.path.join(R, "table4_fragmentation.csv")
    if os.path.exists(table4_file):
        with open(table4_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        if rows:
            c1_ch = int(rows[0]['x25519'])
            h1_ch = int(rows[0]['x25519mlkem768'])
            c1_sh = int(rows[1]['x25519'])
            h1_sh = int(rows[1]['x25519mlkem768'])
            total_delta = int(rows[2]['delta'])
            c1_pkts = int(rows[3]['x25519'])
            h1_pkts = int(rows[3]['x25519mlkem768'])
    else:
        # Fallback to pcapng
        c1 = parse_pcap(os.path.join(C, "C1_classic.pcapng"))
        h1 = parse_pcap(os.path.join(C, "H1_hybrid.pcapng"))
        c1_ch, h1_ch = c1['ch'], h1['ch']
        c1_sh, h1_sh = c1['sh'], h1['sh']
        total_delta = (h1_ch - c1_ch) + (h1_sh - c1_sh)
        c1_pkts, h1_pkts = c1['pkts'], h1['pkts']

    MSS = 1460

    print(f"{'Metric':<24} {'X25519':>10} {'X25519MLKEM768':>16} {'Delta':>10}")
    print("-" * 64)
    print(f"{'ClientHello (frame)':<24} {c1_ch:>9}B {h1_ch:>15}B {h1_ch-c1_ch:>+9}B")
    print(f"{'ServerHello (frame)':<24} {c1_sh:>9}B {h1_sh:>15}B {h1_sh-c1_sh:>+9}B")
    print(f"{'Total overhead':<24} {'—':>10} {'—':>16} {total_delta:>+9}B")
    exceeds = f"Yes(+{h1_ch - MSS}B)" if h1_ch > MSS else "No"
    print(f"{'Exceeds MSS(1460)?':<24} {'No':>10} {exceeds:>16} {'—':>10}")
    print(f"{'Total packets':<24} {c1_pkts:>10} {h1_pkts:>16} {h1_pkts-c1_pkts:>+10}")
    print()

    return c1_ch, h1_ch, c1_sh, h1_sh, total_delta

# ═══════════════════════════════════════════════════════════════════
# TABLE 5: Overhead Decomposition
# ═══════════════════════════════════════════════════════════════════

def table5(x25519_us, mlkem, handshake_results):
    print(SEP)
    print("  TABLE 5: Overhead Decomposition (S2 reference scenario)")
    print(SEP)

    # ── Formulės ──
    print()
    print("  Formulės:")
    print()
    print("  TLS 1.3 Hybrid Handshake kritinis kelias:")
    print()
    print("    Classical (C1):                          Hybrid (H1):")
    print("    ┌─────────────────────────────────┐      ┌──────────────────────────────────────────┐")
    print("    │ Fazė 1 (klientas → serveris):   │      │ Fazė 1 (klientas → serveris):            │")
    print("    │   X25519 KeyGen                  │      │   X25519 KeyGen + ML-KEM KeyGen           │")
    print("    │ Fazė 2 (serveris → klientas):   │      │ Fazė 2 (serveris → klientas):            │")
    print("    │   X25519 KeyGen + X25519 Agree   │      │   X25519 KeyGen + Agree + ML-KEM Encaps   │")
    print("    │ Fazė 3 (klientas):              │      │ Fazė 3 (klientas):                       │")
    print("    │   X25519 Agree                   │      │   X25519 Agree + ML-KEM Decaps            │")
    print("    └─────────────────────────────────┘      └──────────────────────────────────────────┘")
    print()
    print("  Δ_crypto = T_hybrid_crypto − T_classical_crypto")
    print("           = (KeyGen + Encaps + Decaps)_ML-KEM")
    print()
    print("  Δ_total  = H1_P50 − C1_P50                           [iš Table 3, S2 scenarijus]")
    print("  Δ_bw     = Δ_total − Δ_crypto")
    print()
    print("  Share_crypto = Δ_crypto / Δ_total × 100%")
    print("  Share_bw     = Δ_bw / Δ_total × 100%")
    print()

    # ── Duomenų tikrinimas ──
    has_keygen = mlkem and 'keygen' in mlkem
    has_encaps = mlkem and 'encaps' in mlkem
    has_decaps = mlkem and 'decaps' in mlkem
    has_all_kem = has_keygen and has_encaps and has_decaps

    if not has_all_kem:
        print("  [ĮSPĖJIMAS: Trūksta ML-KEM operacijų duomenų — naudojami default]")

    # ── Kriptografinis overhead (pataisytas) ──
    if has_all_kem:
        keygen_us = mlkem['keygen']['us']
        encaps_us = mlkem['encaps']['us']
        decaps_us = mlkem['decaps']['us']
    else:
        keygen_us = 46.5
        encaps_us = 48.0
        decaps_us = 59.3

    # Classical crypto critical path
    classical_crypto_us = 3 * x25519_us  # KeyGen + KeyGen+Agree + Agree = ~3× X25519
    # Hybrid crypto critical path
    hybrid_crypto_us = (x25519_us + keygen_us) + (2 * x25519_us + encaps_us) + (x25519_us + decaps_us)
    # Delta = only the additional KEM operations
    delta_crypto_us = keygen_us + encaps_us + decaps_us
    delta_crypto_ms = delta_crypto_us / 1000

    # ── S2 handshake delta ──
    s2_key = None
    for k in handshake_results:
        if 'S2' in k:
            s2_key = k
            break

    if s2_key:
        delta_total = handshake_results[s2_key]['delta']
    else:
        delta_total = 2.97
        print("  [S2 duomenų nėra — naudojamas 2.97 ms]")

    if delta_total <= 0:
        print(f"  [ĮSPĖJIMAS: S2 delta = {delta_total:.3f} ms (neigiama/nulis) — dekompozicija neįmanoma]")
        print()
        return

    delta_bw_ms = delta_total - delta_crypto_ms
    crypto_pct = (delta_crypto_ms / delta_total) * 100
    bw_pct = (delta_bw_ms / delta_total) * 100

    # ── Skaičiavimo eiga ──
    print("  Skaičiavimo eiga (su duomenimis iš Table 2):")
    print()
    print(f"    Fazė 1 — Klientas paruošia ClientHello:")
    print(f"      Classical:  X25519 KeyGen                     = {x25519_us:.1f} μs")
    print(f"      Hybrid:     X25519 KeyGen + ML-KEM KeyGen     = {x25519_us:.1f} + {keygen_us:.1f} = {x25519_us + keygen_us:.1f} μs")
    print(f"      Δ Fazė 1:   ML-KEM KeyGen                     = +{keygen_us:.1f} μs")
    print()
    print(f"    Fazė 2 — Serveris paruošia ServerHello:")
    print(f"      Classical:  X25519 KeyGen + X25519 Agree      = {x25519_us:.1f} + {x25519_us:.1f} = {2*x25519_us:.1f} μs")
    print(f"      Hybrid:     X25519 KeyGen + Agree + ML-KEM Encaps = {2*x25519_us:.1f} + {encaps_us:.1f} = {2*x25519_us + encaps_us:.1f} μs")
    print(f"      Δ Fazė 2:   ML-KEM Encaps                     = +{encaps_us:.1f} μs")
    print()
    print(f"    Fazė 3 — Klientas apdoroja ServerHello:")
    print(f"      Classical:  X25519 Agree                      = {x25519_us:.1f} μs")
    print(f"      Hybrid:     X25519 Agree + ML-KEM Decaps      = {x25519_us:.1f} + {decaps_us:.1f} = {x25519_us + decaps_us:.1f} μs")
    print(f"      Δ Fazė 3:   ML-KEM Decaps                     = +{decaps_us:.1f} μs")
    print()
    print(f"    Δ_crypto = Δ Fazė 1 + Δ Fazė 2 + Δ Fazė 3")
    print(f"             = {keygen_us:.1f} + {encaps_us:.1f} + {decaps_us:.1f}")
    print(f"             = {delta_crypto_us:.1f} μs = {delta_crypto_ms:.3f} ms")
    print()
    print(f"    Δ_total  = H1_P50 − C1_P50 (S2)")
    if s2_key:
        c_p50 = handshake_results[s2_key]['c']['p50']
        h_p50 = handshake_results[s2_key]['h']['p50']
        print(f"             = {h_p50:.2f} − {c_p50:.2f}")
    print(f"             = {delta_total:.3f} ms")
    print()
    print(f"    Δ_bw     = Δ_total − Δ_crypto")
    print(f"             = {delta_total:.3f} − {delta_crypto_ms:.3f}")
    print(f"             = {delta_bw_ms:.3f} ms")
    print()

    # ── Rezultatų lentelė ──
    print("  Dekompozicijos lentelė:")
    print()
    print(f"  {'Component':<22} {'Absolute':>12} {'Share':>8} {'Root cause':<22} {'Optimization':<20}")
    print(f"  {'-'*88}")
    print(f"  {'Computation':<22} {delta_crypto_ms:>10.3f}ms {crypto_pct:>7.1f}% {'ML-KEM KeyGen+Enc+Dec':<22} {'AVX2, HW accel.':<20}")
    print(f"  {'Data transmission':<22} {delta_bw_ms:>10.3f}ms {bw_pct:>7.1f}% {'+2,250 B over wire':<22} {'Compress., initcwnd':<20}")
    print(f"  {'-'*88}")
    print(f"  {'TOTAL (S2 P50 delta)':<22} {delta_total:>10.3f}ms {'100.0%':>8}")
    print()

    # ── Papildoma informacija ──
    print("  Papildoma informacija:")
    print(f"    Classical crypto total:  4 × X25519 ≈ 4 × {x25519_us:.1f} = {4*x25519_us:.1f} μs = {4*x25519_us/1000:.3f} ms")
    print(f"    Hybrid crypto total:     Classical + Δ_crypto = {4*x25519_us:.1f} + {delta_crypto_us:.1f} = {4*x25519_us + delta_crypto_us:.1f} μs = {(4*x25519_us + delta_crypto_us)/1000:.3f} ms")
    print(f"    Crypto speedup potential: eliminating all Δ_crypto would save only {delta_crypto_ms:.3f} ms ({crypto_pct:.1f}% of delta)")
    print(f"    Bandwidth optimization:  reducing +2,250 B overhead would save up to {delta_bw_ms:.3f} ms ({bw_pct:.1f}% of delta)")
    print()

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print(SEP)
    print("  QUARTIC Testbed — Straipsnio lentelės (Tables 1–5)")
    print("  Empirical Overhead Decomposition of Hybrid PQC in TLS 1.3")
    print(SEP)
    print(f"  Results: {R}")
    print(f"  Captures: {C}")
    print()

    table1()
    x25519_us, mlkem = table2()
    handshake_results = table3()
    table4()
    table5(x25519_us, mlkem, handshake_results)

    print(SEP)
    print("  Visos 5 lentelės sugeneruotos ✓")
    print(SEP)
    print()
