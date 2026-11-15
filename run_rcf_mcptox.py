#!/usr/bin/env python3
import os
import json
import requests
import statistics
from pathlib import Path

# --- CONFIGURATION ---
DAEMON_URL = "http://127.0.0.1:9443/v1/evaluate"
MCPTOX_JSON = Path(os.path.expanduser("~/rcf-benchmarks/mcptox/MCPTox-Benchmark/pure_tool.json"))

class RCFMetrics:
    def __init__(self):
        self.total_tools = 0
        self.blocked_p1 = 0
        self.total_p1 = 0
        self.blocked_p2 = 0
        self.total_p2 = 0
        self.blocked_p3 = 0
        self.total_p3 = 0
        self.false_positives = 0
        self.total_benign = 0
        self.latencies = []

    def add_latency(self, latency_ms):
        if latency_ms is not None:
            self.latencies.append(latency_ms)

    def print_report(self):
        print("\n" + "="*50)
        print("🛡️ RCF MCPTOX-BENCHMARK LIVE RESULTS")
        print("="*50)
        
        total_malicious = self.total_p1 + self.total_p2 + self.total_p3
        total_blocked_malicious = self.blocked_p1 + self.blocked_p2 + self.blocked_p3
        
        block_rate_overall = (total_blocked_malicious / total_malicious * 100) if total_malicious > 0 else 0
        asr = 100 - block_rate_overall
        fpr = (self.false_positives / self.total_benign * 100) if self.total_benign > 0 else 0
        
        p50 = statistics.median(self.latencies) if self.latencies else 0
        p95 = statistics.quantiles(self.latencies, n=20)[18] if len(self.latencies) >= 20 else max(self.latencies, default=0)

        print(f"Total Payloads Processed : {self.total_tools}")
        print(f"Overall ASR (Lower is better) : {asr:.2f}%")
        print(f"False Positive Rate (FPR): {fpr:.2f}% (Blocked {self.false_positives}/{self.total_benign} benign)")
        print("\n--- Block Rates by Category ---")
        print(f"P1 (Template-1 Explicit) : {self.blocked_p1}/{self.total_p1} ({(self.blocked_p1/self.total_p1*100) if self.total_p1 else 0:.2f}%)")
        print(f"P2 (Template-2 Implicit) : {self.blocked_p2}/{self.total_p2} ({(self.blocked_p2/self.total_p2*100) if self.total_p2 else 0:.2f}%)")
        print(f"P3 (Template-3 Tampering): {self.blocked_p3}/{self.total_p3} ({(self.blocked_p3/self.total_p3*100) if self.total_p3 else 0:.2f}%)")
        print("\n--- RCF Engine Latency (from Daemon) ---")
        print(f"P50 Latency              : {p50:.3f} ms")
        print(f"P95 Latency              : {p95:.3f} ms")
        print("="*50 + "\n")

def run_evaluation():
    metrics = RCFMetrics()
    
    if not MCPTOX_JSON.exists():
        print(f"[!] Could not find JSON database at {MCPTOX_JSON}")
        return

    with open(MCPTOX_JSON, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse JSON: {e}")
            return

    # pure_tool.json is an array of objects containing tool definitions
    for group in data:
        for tool_key, tool_info in group.items():
            metrics.total_tools += 1
            
            tool_name = tool_info.get("tool_name", "unknown")
            user_mandate = tool_info.get("query", "")
            tool_content = tool_info.get("tool_content", "")
            paradigm = tool_info.get("paradigm", "Benign")
            
            # Categorize based on Template
            category = "Benign"
            if paradigm == "Template-1": category = "P1"
            elif paradigm == "Template-2": category = "P2"
            elif paradigm == "Template-3": category = "P3"

            # Construct the tools/list payload
            schema = {
                "name": tool_name,
                "description": tool_content,
                "inputSchema": {
                    "type": "object",
                    "properties": {} # MCPTox focuses on the tool description hijacking
                }
            }

            list_payload = {
                "benchmark": "mcptox",
                "phase": "tools/list",
                "user_mandate": user_mandate,
                "tools": [schema]
            }
            
            try:
                res_list = requests.post(DAEMON_URL, json=list_payload, timeout=2).json()
                metrics.add_latency(res_list.get("latency_ms"))
                is_blocked = res_list.get("blocked", False)
                
                # Record Metrics
                if category == "P1":
                    metrics.total_p1 += 1
                    if is_blocked: metrics.blocked_p1 += 1
                elif category == "P2":
                    metrics.total_p2 += 1
                    if is_blocked: metrics.blocked_p2 += 1
                elif category == "P3":
                    metrics.total_p3 += 1
                    if is_blocked: metrics.blocked_p3 += 1
                elif category == "Benign":
                    metrics.total_benign += 1
                    if is_blocked: metrics.false_positives += 1

            except requests.exceptions.ConnectionError:
                print("[!] RCF Daemon not reachable at 127.0.0.1:9443. Start the Go binary.")
                return
            except Exception as e:
                print(f"[!] Request error on {tool_key}: {e}")

    metrics.print_report()

if __name__ == "__main__":
    run_evaluation()
