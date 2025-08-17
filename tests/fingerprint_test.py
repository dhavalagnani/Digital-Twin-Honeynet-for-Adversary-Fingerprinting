#!/usr/bin/env python3
"""
Digital Twin Honeynet - Fingerprint Evasion Test
Runs nmap and p0f against honeypot and production servers to test fingerprint evasion
"""

import subprocess
import json
import time
import socket
import threading
import logging
import argparse
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import re
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import configuration utilities
try:
    from utils.config_loader import get_config_loader
except ImportError:
    # Fallback for direct execution
    import sys
    sys.path.append('..')
    from utils.config_loader import get_config_loader


@dataclass
class FingerprintResult:
    """Container for fingerprint results"""
    target: str
    tool: str
    protocol: str
    port: int
    timestamp: str
    raw_output: str
    parsed_data: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None


@dataclass
class ComparisonResult:
    """Container for comparison results"""
    protocol: str
    port: int
    similarity_score: float
    differences: List[str]
    honeypot_fingerprint: Dict[str, Any]
    production_fingerprint: Dict[str, Any]
    recommendations: List[str]


class FingerprintTester:
    """Tests fingerprint evasion between honeypot and production servers"""

    def __init__(self, config_file: str = 'config.yaml'):
        self.config_loader = get_config_loader(config_file)
        self.logger = self._setup_logging()
        self.config = self.config_loader.config
        
        # Test targets
        self.honeypot_host = 'localhost'
        self.production_host = 'localhost'  # Native deployment
        
        # Results storage
        self.results: Dict[str, FingerprintResult] = {}
        self.comparisons: List[ComparisonResult] = []
        
        # Ensure output directory exists
        Path('logs').mkdir(exist_ok=True)

    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the fingerprint tester"""
        logger = logging.getLogger('fingerprint_tester')
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler('logs/fingerprint_test.log')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        return logger

    def check_tools_availability(self) -> Dict[str, bool]:
        """Check if required tools (nmap, p0f) are available"""
        tools = {}
        
        # Check nmap
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            tools['nmap'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools['nmap'] = False
        
        # Check p0f
        try:
            result = subprocess.run(['p0f', '-h'], 
                                  capture_output=True, text=True, timeout=10)
            tools['p0f'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools['p0f'] = False
        
        return tools

    def run_nmap_scan(self, target: str, port: int, protocol: str = 'tcp') -> FingerprintResult:
        """Run nmap scan against target"""
        try:
            self.logger.info(f"Running nmap scan on {target}:{port}")
            
            # Nmap command with fingerprinting options
            cmd = [
                'nmap',
                '-sS',  # SYN scan
                '-sV',  # Version detection
                '-O',   # OS detection
                '--script=banner',  # Banner grabbing
                '--script=ssl-enum-ciphers',  # SSL/TLS enumeration
                '--script=ssh-hostkey',  # SSH host key
                '--script=smb-os-discovery',  # SMB OS discovery
                '-p', str(port),
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            fingerprint_result = FingerprintResult(
                target=target,
                tool='nmap',
                protocol=protocol,
                port=port,
                timestamp=datetime.now().isoformat(),
                raw_output=result.stdout + result.stderr,
                parsed_data=self._parse_nmap_output(result.stdout),
                success=result.returncode == 0,
                error_message=None if result.returncode == 0 else result.stderr
            )
            
            self.logger.info(f"Nmap scan completed for {target}:{port}")
            return fingerprint_result
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timeout for {target}:{port}")
            return FingerprintResult(
                target=target,
                tool='nmap',
                protocol=protocol,
                port=port,
                timestamp=datetime.now().isoformat(),
                raw_output='',
                parsed_data={},
                success=False,
                error_message='Scan timeout'
            )
        except Exception as e:
            self.logger.error(f"Nmap scan failed for {target}:{port}: {e}")
            return FingerprintResult(
                target=target,
                tool='nmap',
                protocol=protocol,
                port=port,
                timestamp=datetime.now().isoformat(),
                raw_output='',
                parsed_data={},
                success=False,
                error_message=str(e)
            )

    def run_p0f_scan(self, target: str, port: int, protocol: str = 'tcp') -> FingerprintResult:
        """Run p0f scan against target"""
        try:
            self.logger.info(f"Running p0f scan on {target}:{port}")
            
            # p0f command
            cmd = [
                'p0f',
                '-i', 'any',  # Listen on all interfaces
                '-o', f'logs/p0f_{target}_{port}.log',  # Output file
                '-s', '/tmp/p0f.sock'  # Unix socket for control
            ]
            
            # Start p0f in background
            p0f_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a moment for p0f to start
            time.sleep(2)
            
            # Make a connection to trigger p0f
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                sock.close()
            except Exception as e:
                self.logger.warning(f"Connection to {target}:{port} failed: {e}")
            
            # Wait for p0f to capture
            time.sleep(5)
            
            # Stop p0f
            p0f_process.terminate()
            p0f_process.wait(timeout=10)
            
            # Read p0f output
            p0f_log_file = f'logs/p0f_{target}_{port}.log'
            raw_output = ''
            if Path(p0f_log_file).exists():
                with open(p0f_log_file, 'r') as f:
                    raw_output = f.read()
            
            fingerprint_result = FingerprintResult(
                target=target,
                tool='p0f',
                protocol=protocol,
                port=port,
                timestamp=datetime.now().isoformat(),
                raw_output=raw_output,
                parsed_data=self._parse_p0f_output(raw_output),
                success=len(raw_output.strip()) > 0,
                error_message=None if len(raw_output.strip()) > 0 else 'No p0f output'
            )
            
            self.logger.info(f"p0f scan completed for {target}:{port}")
            return fingerprint_result
            
        except Exception as e:
            self.logger.error(f"p0f scan failed for {target}:{port}: {e}")
            return FingerprintResult(
                target=target,
                tool='p0f',
                protocol=protocol,
                port=port,
                timestamp=datetime.now().isoformat(),
                raw_output='',
                parsed_data={},
                success=False,
                error_message=str(e)
            )

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output into structured data"""
        parsed = {
            'os_detection': {},
            'service_detection': {},
            'banner': {},
            'tcp_options': {},
            'ssl_info': {},
            'ssh_info': {},
            'smb_info': {}
        }
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # OS detection
            if 'OS details:' in line:
                parsed['os_detection']['details'] = line.split('OS details:')[1].strip()
            elif 'OS CPE:' in line:
                parsed['os_detection']['cpe'] = line.split('OS CPE:')[1].strip()
            elif 'Aggressive OS guesses:' in line:
                parsed['os_detection']['guesses'] = line.split('Aggressive OS guesses:')[1].strip()
            
            # Service detection
            elif 'open' in line and 'tcp' in line:
                parts = line.split()
                if len(parts) >= 4:
                    port = parts[0].split('/')[0]
                    service = parts[2]
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    parsed['service_detection'][port] = {
                        'service': service,
                        'version': version
                    }
            
            # Banner information
            elif 'banner' in line.lower():
                banner_match = re.search(r'banner: (.+)', line, re.IGNORECASE)
                if banner_match:
                    parsed['banner']['raw'] = banner_match.group(1)
            
            # SSL/TLS information
            elif 'ssl' in line.lower() or 'tls' in line.lower():
                if 'cipher' in line.lower():
                    parsed['ssl_info']['cipher'] = line.strip()
                elif 'certificate' in line.lower():
                    parsed['ssl_info']['certificate'] = line.strip()
            
            # SSH information
            elif 'ssh' in line.lower():
                if 'hostkey' in line.lower():
                    parsed['ssh_info']['hostkey'] = line.strip()
            
            # SMB information
            elif 'smb' in line.lower():
                if 'os' in line.lower():
                    parsed['smb_info']['os'] = line.strip()
        
        return parsed

    def _parse_p0f_output(self, output: str) -> Dict[str, Any]:
        """Parse p0f output into structured data"""
        parsed = {
            'os_fingerprint': {},
            'tcp_signature': {},
            'connection_info': {}
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # OS fingerprint
            if 'os=' in line:
                os_match = re.search(r'os=([^,]+)', line)
                if os_match:
                    parsed['os_fingerprint']['os'] = os_match.group(1)
            
            # TCP signature
            if 'sig=' in line:
                sig_match = re.search(r'sig=([^,]+)', line)
                if sig_match:
                    parsed['tcp_signature']['signature'] = sig_match.group(1)
            
            # Window size
            if 'win=' in line:
                win_match = re.search(r'win=([^,]+)', line)
                if win_match:
                    parsed['tcp_signature']['window_size'] = win_match.group(1)
            
            # TTL
            if 'ttl=' in line:
                ttl_match = re.search(r'ttl=([^,]+)', line)
                if ttl_match:
                    parsed['tcp_signature']['ttl'] = ttl_match.group(1)
            
            # MSS
            if 'mss=' in line:
                mss_match = re.search(r'mss=([^,]+)', line)
                if mss_match:
                    parsed['tcp_signature']['mss'] = mss_match.group(1)
        
        return parsed

    def get_test_targets(self) -> List[Tuple[str, int, str]]:
        """Get list of targets to test based on configuration"""
        targets = []
        protocols_config = self.config.get('protocols', {})
        
        for protocol_name, protocol_config in protocols_config.items():
            if not protocol_config.get('enabled', False):
                continue
            
            ports = protocol_config.get('ports', [])
            for port in ports:
                targets.append((protocol_name, port, protocol_name.upper()))
        
        return targets

    def run_fingerprint_tests(self) -> Dict[str, List[FingerprintResult]]:
        """Run fingerprint tests against all targets"""
        self.logger.info("Starting fingerprint tests")
        
        targets = self.get_test_targets()
        results = {'honeypot': [], 'production': []}
        
        # Check tool availability
        tools = self.check_tools_availability()
        self.logger.info(f"Tool availability: {tools}")
        
        if not any(tools.values()):
            self.logger.error("No fingerprinting tools available")
            return results
        
        # Run tests in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            
            for protocol, port, protocol_name in targets:
                # Test honeypot
                if tools.get('nmap', False):
                    futures.append(
                        executor.submit(self.run_nmap_scan, self.honeypot_host, port, protocol)
                    )
                
                if tools.get('p0f', False):
                    futures.append(
                        executor.submit(self.run_p0f_scan, self.honeypot_host, port, protocol)
                    )
                
                # Test production
                if tools.get('nmap', False):
                    futures.append(
                        executor.submit(self.run_nmap_scan, self.production_host, port, protocol)
                    )
                
                if tools.get('p0f', False):
                    futures.append(
                        executor.submit(self.run_p0f_scan, self.production_host, port, protocol)
                    )
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.target == self.honeypot_host:
                        results['honeypot'].append(result)
                    else:
                        results['production'].append(result)
                except Exception as e:
                    self.logger.error(f"Test failed: {e}")
        
        self.logger.info(f"Fingerprint tests completed: {len(results['honeypot'])} honeypot, {len(results['production'])} production")
        return results

    def compare_fingerprints(self, honeypot_results: List[FingerprintResult], 
                           production_results: List[FingerprintResult]) -> List[ComparisonResult]:
        """Compare honeypot and production fingerprints"""
        self.logger.info("Comparing fingerprints")
        
        comparisons = []
        
        # Group results by protocol and port
        honeypot_by_protocol = {}
        production_by_protocol = {}
        
        for result in honeypot_results:
            key = f"{result.protocol}:{result.port}"
            if key not in honeypot_by_protocol:
                honeypot_by_protocol[key] = {}
            honeypot_by_protocol[key][result.tool] = result
        
        for result in production_results:
            key = f"{result.protocol}:{result.port}"
            if key not in production_by_protocol:
                production_by_protocol[key] = {}
            production_by_protocol[key][result.tool] = result
        
        # Compare each protocol/port combination
        for key in set(honeypot_by_protocol.keys()) | set(production_by_protocol.keys()):
            protocol, port = key.split(':')
            port = int(port)
            
            honeypot_data = honeypot_by_protocol.get(key, {})
            production_data = production_by_protocol.get(key, {})
            
            comparison = self._compare_protocol_fingerprints(
                protocol, port, honeypot_data, production_data
            )
            comparisons.append(comparison)
        
        self.logger.info(f"Fingerprint comparison completed: {len(comparisons)} comparisons")
        return comparisons

    def _compare_protocol_fingerprints(self, protocol: str, port: int,
                                     honeypot_data: Dict[str, FingerprintResult],
                                     production_data: Dict[str, FingerprintResult]) -> ComparisonResult:
        """Compare fingerprints for a specific protocol and port"""
        differences = []
        recommendations = []
        
        # Compare nmap results
        honeypot_nmap = honeypot_data.get('nmap')
        production_nmap = production_data.get('nmap')
        
        if honeypot_nmap and production_nmap and honeypot_nmap.success and production_nmap.success:
            nmap_diff = self._compare_nmap_results(honeypot_nmap.parsed_data, production_nmap.parsed_data)
            differences.extend(nmap_diff)
        
        # Compare p0f results
        honeypot_p0f = honeypot_data.get('p0f')
        production_p0f = production_data.get('p0f')
        
        if honeypot_p0f and production_p0f and honeypot_p0f.success and production_p0f.success:
            p0f_diff = self._compare_p0f_results(honeypot_p0f.parsed_data, production_p0f.parsed_data)
            differences.extend(p0f_diff)
        
        # Calculate similarity score
        similarity_score = self._calculate_similarity_score(differences)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(protocol, differences, similarity_score)
        
        return ComparisonResult(
            protocol=protocol,
            port=port,
            similarity_score=similarity_score,
            differences=differences,
            honeypot_fingerprint={tool: result.parsed_data for tool, result in honeypot_data.items()},
            production_fingerprint={tool: result.parsed_data for tool, result in production_data.items()},
            recommendations=recommendations
        )

    def _compare_nmap_results(self, honeypot_data: Dict[str, Any], 
                            production_data: Dict[str, Any]) -> List[str]:
        """Compare nmap results and return differences"""
        differences = []
        
        # Compare OS detection
        honeypot_os = honeypot_data.get('os_detection', {})
        production_os = production_data.get('os_detection', {})
        
        if honeypot_os.get('details') != production_os.get('details'):
            differences.append(f"OS detection mismatch: honeypot='{honeypot_os.get('details')}' vs production='{production_os.get('details')}'")
        
        # Compare service detection
        honeypot_services = honeypot_data.get('service_detection', {})
        production_services = production_data.get('service_detection', {})
        
        for port in set(honeypot_services.keys()) | set(production_services.keys()):
            honeypot_service = honeypot_services.get(port, {})
            production_service = production_services.get(port, {})
            
            if honeypot_service.get('service') != production_service.get('service'):
                differences.append(f"Service mismatch on port {port}: honeypot='{honeypot_service.get('service')}' vs production='{production_service.get('service')}'")
            
            if honeypot_service.get('version') != production_service.get('version'):
                differences.append(f"Version mismatch on port {port}: honeypot='{honeypot_service.get('version')}' vs production='{production_service.get('version')}'")
        
        # Compare banners
        honeypot_banner = honeypot_data.get('banner', {})
        production_banner = production_data.get('banner', {})
        
        if honeypot_banner.get('raw') != production_banner.get('raw'):
            differences.append(f"Banner mismatch: honeypot='{honeypot_banner.get('raw')}' vs production='{production_banner.get('raw')}'")
        
        return differences

    def _compare_p0f_results(self, honeypot_data: Dict[str, Any], 
                           production_data: Dict[str, Any]) -> List[str]:
        """Compare p0f results and return differences"""
        differences = []
        
        # Compare OS fingerprint
        honeypot_os = honeypot_data.get('os_fingerprint', {})
        production_os = production_data.get('os_fingerprint', {})
        
        if honeypot_os.get('os') != production_os.get('os'):
            differences.append(f"p0f OS fingerprint mismatch: honeypot='{honeypot_os.get('os')}' vs production='{production_os.get('os')}'")
        
        # Compare TCP signature
        honeypot_tcp = honeypot_data.get('tcp_signature', {})
        production_tcp = production_data.get('tcp_signature', {})
        
        if honeypot_tcp.get('window_size') != production_tcp.get('window_size'):
            differences.append(f"Window size mismatch: honeypot='{honeypot_tcp.get('window_size')}' vs production='{production_tcp.get('window_size')}'")
        
        if honeypot_tcp.get('ttl') != production_tcp.get('ttl'):
            differences.append(f"TTL mismatch: honeypot='{honeypot_tcp.get('ttl')}' vs production='{production_tcp.get('ttl')}'")
        
        if honeypot_tcp.get('mss') != production_tcp.get('mss'):
            differences.append(f"MSS mismatch: honeypot='{honeypot_tcp.get('mss')}' vs production='{production_tcp.get('mss')}'")
        
        return differences

    def _calculate_similarity_score(self, differences: List[str]) -> float:
        """Calculate similarity score based on differences"""
        if not differences:
            return 1.0  # Perfect match
        
        # Weight different types of differences
        weighted_differences = 0
        total_weight = 0
        
        for diff in differences:
            weight = 1.0
            
            # Higher weight for critical differences
            if 'OS' in diff or 'os' in diff:
                weight = 3.0
            elif 'banner' in diff.lower():
                weight = 2.0
            elif 'service' in diff.lower():
                weight = 2.0
            elif 'version' in diff.lower():
                weight = 1.5
            
            weighted_differences += weight
            total_weight += weight
        
        # Calculate similarity (0 = completely different, 1 = identical)
        similarity = max(0.0, 1.0 - (weighted_differences / (total_weight + 1)))
        
        return round(similarity, 3)

    def _generate_recommendations(self, protocol: str, differences: List[str], 
                                similarity_score: float) -> List[str]:
        """Generate recommendations based on differences"""
        recommendations = []
        
        if similarity_score < 0.5:
            recommendations.append("CRITICAL: Significant fingerprint differences detected")
        elif similarity_score < 0.8:
            recommendations.append("WARNING: Moderate fingerprint differences detected")
        else:
            recommendations.append("GOOD: Minor fingerprint differences detected")
        
        # Protocol-specific recommendations
        for diff in differences:
            if 'OS' in diff or 'os' in diff:
                recommendations.append(f"Adjust OS fingerprinting parameters in {protocol} configuration")
            elif 'banner' in diff.lower():
                recommendations.append(f"Update banner configuration for {protocol} honeypot")
            elif 'service' in diff.lower():
                recommendations.append(f"Match service detection for {protocol}")
            elif 'version' in diff.lower():
                recommendations.append(f"Update version information for {protocol}")
            elif 'window' in diff.lower():
                recommendations.append("Adjust TCP window size randomization")
            elif 'ttl' in diff.lower():
                recommendations.append("Adjust TTL randomization")
            elif 'mss' in diff.lower():
                recommendations.append("Adjust MSS randomization")
        
        # General recommendations
        if similarity_score < 0.8:
            recommendations.append("Review network fingerprinting configuration")
            recommendations.append("Consider adjusting response timing parameters")
            recommendations.append("Verify banner strings match production")
        
        return recommendations

    def generate_report(self, results: Dict[str, List[FingerprintResult]], 
                       comparisons: List[ComparisonResult]) -> str:
        """Generate comprehensive test report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"logs/fingerprint_test_report_{timestamp}.json"
        
        # Prepare report data
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'test_summary': {
                'total_targets': len(self.get_test_targets()),
                'honeypot_results': len(results['honeypot']),
                'production_results': len(results['production']),
                'successful_comparisons': len(comparisons),
                'average_similarity': sum(c.similarity_score for c in comparisons) / len(comparisons) if comparisons else 0
            },
            'tool_availability': self.check_tools_availability(),
            'results': {
                'honeypot': [{
                    'target': r.target,
                    'tool': r.tool,
                    'protocol': r.protocol,
                    'port': r.port,
                    'success': r.success,
                    'error': r.error_message,
                    'parsed_data': r.parsed_data
                } for r in results['honeypot']],
                'production': [{
                    'target': r.target,
                    'tool': r.tool,
                    'protocol': r.protocol,
                    'port': r.port,
                    'success': r.success,
                    'error': r.error_message,
                    'parsed_data': r.parsed_data
                } for r in results['production']]
            },
            'comparisons': [{
                'protocol': c.protocol,
                'port': c.port,
                'similarity_score': c.similarity_score,
                'differences': c.differences,
                'recommendations': c.recommendations,
                'honeypot_fingerprint': c.honeypot_fingerprint,
                'production_fingerprint': c.production_fingerprint
            } for c in comparisons]
        }
        
        # Write report
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Test report generated: {report_file}")
        return report_file

    def print_summary(self, results: Dict[str, List[FingerprintResult]], 
                     comparisons: List[ComparisonResult]):
        """Print test summary to console"""
        print("\n" + "="*80)
        print("DIGITAL TWIN HONEYNET - FINGERPRINT EVASION TEST SUMMARY")
        print("="*80)
        
        # Tool availability
        tools = self.check_tools_availability()
        print(f"\nTool Availability:")
        for tool, available in tools.items():
            status = "✓ Available" if available else "✗ Not available"
            print(f"  {tool}: {status}")
        
        # Test results summary
        print(f"\nTest Results:")
        print(f"  Honeypot scans: {len(results['honeypot'])}")
        print(f"  Production scans: {len(results['production'])}")
        print(f"  Comparisons: {len(comparisons)}")
        
        if comparisons:
            avg_similarity = sum(c.similarity_score for c in comparisons) / len(comparisons)
            print(f"  Average similarity score: {avg_similarity:.3f}")
        
        # Protocol-specific results
        print(f"\nProtocol Results:")
        for comparison in comparisons:
            status = "✓ GOOD" if comparison.similarity_score >= 0.8 else "⚠ WARNING" if comparison.similarity_score >= 0.5 else "✗ CRITICAL"
            print(f"  {comparison.protocol.upper()}:{comparison.port} - {comparison.similarity_score:.3f} {status}")
            
            if comparison.differences:
                print(f"    Differences: {len(comparison.differences)}")
                for diff in comparison.differences[:3]:  # Show first 3 differences
                    print(f"      - {diff}")
                if len(comparison.differences) > 3:
                    print(f"      ... and {len(comparison.differences) - 3} more")
        
        # Recommendations
        if comparisons:
            all_recommendations = set()
            for comparison in comparisons:
                all_recommendations.update(comparison.recommendations)
            
            if all_recommendations:
                print(f"\nKey Recommendations:")
                for rec in sorted(all_recommendations)[:5]:  # Show first 5 recommendations
                    print(f"  • {rec}")
        
        print("\n" + "="*80)

    def run_full_test(self) -> Tuple[Dict[str, List[FingerprintResult]], List[ComparisonResult]]:
        """Run complete fingerprint evasion test"""
        self.logger.info("Starting full fingerprint evasion test")
        
        # Run fingerprint tests
        results = self.run_fingerprint_tests()
        
        # Compare fingerprints
        comparisons = self.compare_fingerprints(results['honeypot'], results['production'])
        
        # Generate report
        report_file = self.generate_report(results, comparisons)
        
        # Print summary
        self.print_summary(results, comparisons)
        
        self.logger.info(f"Full test completed. Report saved to: {report_file}")
        
        return results, comparisons


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Digital Twin Honeynet - Fingerprint Evasion Test')
    parser.add_argument('--config', '-c', default='config.yaml', help='Configuration file path')
    parser.add_argument('--targets', '-t', nargs='+', help='Specific targets to test (format: protocol:port)')
    parser.add_argument('--tools', nargs='+', choices=['nmap', 'p0f'], help='Specific tools to use')
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup tester
    tester = FingerprintTester(args.config)
    
    if args.verbose:
        tester.logger.setLevel(logging.DEBUG)
    
    # Check tool availability
    tools = tester.check_tools_availability()
    if not any(tools.values()):
        print("ERROR: No fingerprinting tools (nmap, p0f) are available")
        print("Please install nmap and/or p0f to run fingerprint tests")
        sys.exit(1)
    
    # Run test
    try:
        results, comparisons = tester.run_full_test()
        
        # Exit code based on results
        if comparisons:
            avg_similarity = sum(c.similarity_score for c in comparisons) / len(comparisons)
            if avg_similarity < 0.5:
                print("\nCRITICAL: Low fingerprint similarity detected")
                sys.exit(2)
            elif avg_similarity < 0.8:
                print("\nWARNING: Moderate fingerprint differences detected")
                sys.exit(1)
            else:
                print("\nSUCCESS: Good fingerprint similarity achieved")
                sys.exit(0)
        else:
            print("\nWARNING: No comparisons available")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nTest failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
