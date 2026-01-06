#!/usr/bin/env python3
"""
AutoFuzzer - Intelligent Fuzzing Framework for C Programs
Automatically discovers buffer overflows and generates crash reports
Author: Your Name
"""

import os
import sys
import subprocess
import random
import string
import struct
import signal
from pathlib import Path
import tempfile
import re

class AutoFuzzer:
    def __init__(self, target_binary, timeout=5):
        self.target = target_binary
        self.timeout = timeout
        self.crashes = []
        self.unique_crashes = set()
        self.iteration = 0
        
        if not os.path.exists(target_binary):
            raise FileNotFoundError(f"Target binary not found: {target_binary}")
    
    def generate_random_input(self, size=None):
        """Generate random input for fuzzing"""
        if size is None:
            size = random.randint(1, 8192)
        
        # Mix of different input types
        strategies = [
            lambda: bytes(random.choices(range(256), k=size)),  # Random bytes
            lambda: (string.ascii_letters * (size // 52 + 1))[:size].encode(),  # ASCII
            lambda: b'A' * size,  # Pattern
            lambda: struct.pack(f'<{size}B', *[0xff] * size),  # Max values
            lambda: b'\x00' * size,  # Null bytes
            lambda: b'%s' * (size // 2),  # Format string
            lambda: b'../../../' * (size // 9),  # Path traversal
            lambda: b'\x90' * size,  # NOP sled
        ]
        
        strategy = random.choice(strategies)
        return strategy()
    
    def run_target(self, input_data):
        """Execute target with input and detect crashes"""
        try:
            # Create temporary input file
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(input_data)
                input_file = f.name
            
            # Run target
            proc = subprocess.Popen(
                [self.target, input_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            try:
                stdout, stderr = proc.communicate(timeout=self.timeout)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                os.unlink(input_file)
                return {'crashed': False, 'reason': 'timeout'}
            
            os.unlink(input_file)
            
            # Check for crash (segfault, abort, etc)
            if returncode < 0:
                signal_num = -returncode
                signal_name = signal.Signals(signal_num).name
                
                return {
                    'crashed': True,
                    'signal': signal_name,
                    'signal_num': signal_num,
                    'input': input_data,
                    'input_size': len(input_data),
                    'stdout': stdout,
                    'stderr': stderr
                }
            
            return {'crashed': False}
            
        except Exception as e:
            return {'crashed': False, 'error': str(e)}
    
    def analyze_crash_gdb(self, input_data):
        """Analyze crash with GDB to get stack trace and registers"""
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write(input_data.decode('latin-1'))
            input_file = f.name
        
        # Create GDB commands
        gdb_commands = f"""
set pagination off
set confirm off
run {input_file}
info registers
backtrace
quit
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(gdb_commands)
            gdb_script = f.name
        
        try:
            result = subprocess.run(
                ['gdb', '-batch', '-x', gdb_script, self.target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            os.unlink(input_file)
            os.unlink(gdb_script)
            
            # Parse output for instruction pointer
            output = result.stdout + result.stderr
            
            # Extract RIP/EIP
            rip_match = re.search(r'rip\s+0x([0-9a-f]+)', output, re.I)
            eip_match = re.search(r'eip\s+0x([0-9a-f]+)', output, re.I)
            
            crash_addr = None
            if rip_match:
                crash_addr = rip_match.group(1)
            elif eip_match:
                crash_addr = eip_match.group(1)
            
            return {
                'gdb_output': output,
                'crash_address': crash_addr,
                'exploitable': self.is_exploitable(output)
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def is_exploitable(self, gdb_output):
        """Heuristic check if crash is exploitable"""
        exploitable_indicators = [
            'SIGSEGV',
            '0x41414141',  # AAAA pattern
            'ret',  # Return instruction
            'call',  # Call instruction
            'jmp',  # Jump instruction
        ]
        
        for indicator in exploitable_indicators:
            if indicator in gdb_output:
                return True
        return False
    
    def save_crash(self, crash_info):
        """Save crash input to file for reproduction"""
        crash_dir = Path("crashes")
        crash_dir.mkdir(exist_ok=True)
        
        crash_hash = hash(crash_info['input']) % 100000
        
        # Avoid duplicate crashes
        if crash_hash in self.unique_crashes:
            return
        
        self.unique_crashes.add(crash_hash)
        
        filename = crash_dir / f"crash_{crash_hash}_{crash_info['signal']}.bin"
        
        with open(filename, 'wb') as f:
            f.write(crash_info['input'])
        
        # Save analysis
        report_file = crash_dir / f"crash_{crash_hash}_report.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write(f"CRASH REPORT #{len(self.unique_crashes)}\n")
            f.write("="*60 + "\n")
            f.write(f"Signal: {crash_info['signal']} ({crash_info['signal_num']})\n")
            f.write(f"Input Size: {crash_info['input_size']} bytes\n")
            f.write(f"Input File: {filename}\n")
            
            if 'gdb_analysis' in crash_info:
                f.write(f"\nCrash Address: {crash_info['gdb_analysis']['crash_address']}\n")
                f.write(f"Exploitable: {crash_info['gdb_analysis']['exploitable']}\n")
                f.write(f"\nGDB Output:\n{crash_info['gdb_analysis']['gdb_output']}\n")
        
        print(f"[!] Crash saved to {filename}")
        print(f"[!] Report saved to {report_file}")
    
    def fuzz(self, iterations=10000):
        """Main fuzzing loop"""
        print(f"[*] Starting AutoFuzzer on {self.target}")
        print(f"[*] Running {iterations} iterations...")
        print("-" * 60)
        
        for i in range(iterations):
            self.iteration = i + 1
            
            # Generate input
            input_data = self.generate_random_input()
            
            # Test target
            result = self.run_target(input_data)
            
            if result.get('crashed'):
                print(f"\n[+] CRASH FOUND at iteration {self.iteration}!")
                print(f"[+] Signal: {result['signal']}")
                print(f"[+] Input size: {result['input_size']} bytes")
                
                # Analyze with GDB
                if os.path.exists('/usr/bin/gdb'):
                    print("[*] Analyzing crash with GDB...")
                    result['gdb_analysis'] = self.analyze_crash_gdb(result['input'])
                
                # Save crash
                self.save_crash(result)
                self.crashes.append(result)
            
            # Progress
            if (i + 1) % 100 == 0:
                print(f"[*] Progress: {i+1}/{iterations} - Crashes: {len(self.unique_crashes)}")
        
        print("\n" + "="*60)
        print(f"[*] Fuzzing complete!")
        print(f"[*] Total iterations: {iterations}")
        print(f"[*] Unique crashes: {len(self.unique_crashes)}")
        print("="*60)


class VulnerableTargetGenerator:
    """Generate vulnerable C programs for testing"""
    
    @staticmethod
    def create_vulnerable_program(output_file="vulnerable.c"):
        """Create a simple buffer overflow vulnerability"""
        code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Buffer overflow!
    printf("Input: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    char input[4096];
    size_t n = fread(input, 1, sizeof(input), f);
    input[n] = '\\0';
    fclose(f);
    
    vulnerable_function(input);
    
    return 0;
}
"""
        with open(output_file, 'w') as f:
            f.write(code)
        
        print(f"[+] Created vulnerable program: {output_file}")
        print(f"[*] Compile with: gcc -g -fno-stack-protector -z execstack {output_file} -o vulnerable")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AutoFuzzer - Intelligent Fuzzing Framework")
    parser.add_argument("target", nargs='?', help="Target binary to fuzz")
    parser.add_argument("-i", "--iterations", type=int, default=10000, help="Number of iterations")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout per execution")
    parser.add_argument("--generate", action="store_true", help="Generate vulnerable test program")
    
    args = parser.parse_args()
    
    if args.generate:
        VulnerableTargetGenerator.create_vulnerable_program()
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    fuzzer = AutoFuzzer(args.target, timeout=args.timeout)
    fuzzer.fuzz(iterations=args.iterations)
