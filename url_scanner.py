#!/usr/bin/env python3
#By r0otk3r

"""
Enhanced HTTP URL Scanner
A high-performance, asynchronous URL scanner for checking HTTP availability
"""

import argparse
import asyncio
import aiohttp
import sys
import time
import logging
import re
import json
import csv
from pathlib import Path
from dataclasses import dataclass
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse
import signal

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Container for scan results"""
    url: str
    status: int
    error: Optional[str] = None
    response_time: Optional[float] = None
    headers: Optional[Dict[str, str]] = None
    content_length: Optional[int] = None

class Config:
    """Configuration constants and validation"""
    MAX_CONCURRENT = 500
    MAX_TIMEOUT = 30
    DEFAULT_PORTS = [80, 443, 8080, 8000, 8443, 8888, 3000, 5000, 7001, 9200]
    DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; URL-Scanner/1.0)"
    
    @staticmethod
    def validate_port(port: str) -> bool:
        """Validate port number"""
        return port.isdigit() and 1 <= int(port) <= 65535
    
    @staticmethod
    def validate_host(host: str) -> bool:
        """Basic host validation"""
        if not host or host.strip() != host:
            return False
            
        # IPv4 pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        # IPv6 pattern (basic)
        ipv6_pattern = r'^[0-9a-fA-F:]+$'
        
        if re.match(ip_pattern, host):
            # Validate IPv4 octets
            octets = host.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        elif re.match(hostname_pattern, host) and len(host) <= 253:
            return True
        elif re.match(ipv6_pattern, host) and '::' in host:
            return True
            
        return False

class ProgressTracker:
    """Track and display scan progress"""
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.start_time = time.time()
        self.last_update = 0

    def update(self, increment: int = 1):
        """Update progress counter"""
        self.completed += increment
        current_time = time.time()
        
        # Update every 2 seconds or when complete
        if current_time - self.last_update >= 2 or self.completed == self.total:
            elapsed = current_time - self.start_time
            rate = self.completed / elapsed if elapsed > 0 else 0
            eta = (self.total - self.completed) / rate if rate > 0 else 0
            
            logger.info(f"Progress: {self.completed}/{self.total} "
                       f"({self.completed/self.total*100:.1f}%) - "
                       f"Rate: {rate:.1f} req/sec - ETA: {eta:.1f}s")
            self.last_update = current_time

class EnhancedURLScanner:
    """Enhanced URL scanner with detailed results and statistics"""
    
    def __init__(self, 
                 timeout: int = 5, 
                 concurrency: int = 100, 
                 user_agent: str = None,
                 follow_redirects: bool = True,
                 verify_ssl: bool = False):
        
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.concurrency = min(concurrency, Config.MAX_CONCURRENT)
        self.semaphore = asyncio.Semaphore(self.concurrency)
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        
        self.user_agent = user_agent or Config.DEFAULT_USER_AGENT
        
        # Statistics
        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'errors': 0,
            'status_codes': {}
        }
        
        self.progress_tracker = None

    async def check_url(self, session: aiohttp.ClientSession, url: str) -> ScanResult:
        """Enhanced URL checking with detailed results"""
        async with self.semaphore:
            start_time = time.time()
            self.stats['total'] += 1
            
            try:
                headers = {
                    'User-Agent': self.user_agent,
                    'Accept': '*/*'
                }
                
                async with session.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=self.follow_redirects,
                    headers=headers,
                    ssl=self.verify_ssl
                ) as response:
                    
                    response_time = time.time() - start_time
                    
                    # Read partial content for efficiency (first 1KB)
                    content = await response.content.read(1024)
                    
                    # Update statistics
                    self.stats['success'] += 1
                    status_group = f"{response.status // 100}xx"
                    self.stats['status_codes'][status_group] = self.stats['status_codes'].get(status_group, 0) + 1
                    self.stats['status_codes'][str(response.status)] = self.stats['status_codes'].get(str(response.status), 0) + 1
                    
                    result = ScanResult(
                        url=url,
                        status=response.status,
                        response_time=response_time,
                        headers=dict(response.headers),
                        content_length=len(content)
                    )
                    
                    return result
                    
            except asyncio.TimeoutError:
                self.stats['errors'] += 1
                return ScanResult(url=url, status=0, error="Timeout")
                
            except aiohttp.ClientConnectorError as e:
                self.stats['errors'] += 1
                return ScanResult(url=url, status=0, error=f"Connection error: {e}")
                
            except aiohttp.ClientResponseError as e:
                self.stats['errors'] += 1
                return ScanResult(url=url, status=e.status, error=str(e))
                
            except aiohttp.ClientError as e:
                self.stats['errors'] += 1
                return ScanResult(url=url, status=0, error=f"Client error: {e}")
                
            except Exception as e:
                self.stats['errors'] += 1
                return ScanResult(url=url, status=0, error=f"Unexpected error: {e}")
            finally:
                if self.progress_tracker:
                    self.progress_tracker.update()

    def _build_url(self, scheme: str, target: str) -> str:
        """Build URL from scheme and target"""
        # Remove any existing scheme if present
        target = target.replace('http://', '').replace('https://', '')
        
        if ':' in target and not target.endswith(']'):
            # Target already has port
            return f"{scheme}://{target}"
        else:
            # Use default port based on scheme (don't include default ports in URL)
            if (scheme == 'https' and not target.endswith(':443')) or \
               (scheme == 'http' and not target.endswith(':80')):
                default_port = 443 if scheme == 'https' else 80
                return f"{scheme}://{target}:{default_port}"
            else:
                return f"{scheme}://{target}"

    async def scan_with_details(self, targets: List[str], schemes: List[str] = None) -> List[ScanResult]:
        """Scan with detailed results"""
        if schemes is None:
            schemes = ['http', 'https']
        
        # Setup progress tracker
        total_tasks = len(targets) * len(schemes)
        self.progress_tracker = ProgressTracker(total_tasks)
        
        logger.info(f"Starting scan of {len(targets)} targets with {len(schemes)} schemes "
                   f"(total: {total_tasks} URLs)")
        
        connector = aiohttp.TCPConnector(
            limit=self.concurrency, 
            verify_ssl=self.verify_ssl,
            use_dns_cache=True,
            ttl_dns_cache=300
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            headers={'User-Agent': self.user_agent},
            raise_for_status=False
        ) as session:
            
            tasks = []
            for target in targets:
                target = target.strip()
                if not target:
                    continue
                
                # Extract host for validation
                host = target.split(':')[0] if ':' in target and not target.endswith(']') else target
                
                if not Config.validate_host(host):
                    logger.warning(f"Skipping invalid host: {target}")
                    continue
                
                for scheme in schemes:
                    url = self._build_url(scheme, target)
                    tasks.append(self.check_url(session, url))
            
            # Run all checks concurrently
            results = await asyncio.gather(*tasks)
            
            # Filter out None results
            valid_results = [r for r in results if r is not None]
            return valid_results

    def print_statistics(self):
        """Print scan statistics"""
        logger.info("=== Scan Statistics ===")
        logger.info(f"Total requests: {self.stats['total']}")
        logger.info(f"Successful: {self.stats['success']}")
        logger.info(f"Errors: {self.stats['errors']}")
        logger.info(f"Success rate: {self.stats['success']/self.stats['total']*100:.1f}%")
        
        if self.stats['status_codes']:
            logger.info("Status codes:")
            for code, count in sorted(self.stats['status_codes'].items()):
                logger.info(f"  {code}: {count}")

class RateLimitedScanner(EnhancedURLScanner):
    """Scanner with rate limiting and retry mechanism"""
    
    def __init__(self, requests_per_second: int = 50, max_retries: int = 2, **kwargs):
        super().__init__(**kwargs)
        self.requests_per_second = requests_per_second
        self.max_retries = max_retries
        self.delay = 1.0 / requests_per_second

    async def check_url_with_retry(self, session: aiohttp.ClientSession, url: str) -> ScanResult:
        """Check URL with retry mechanism and rate limiting"""
        for attempt in range(self.max_retries + 1):
            # Rate limiting
            if attempt > 0:
                await asyncio.sleep(self.delay * (2 ** attempt))  # Exponential backoff
            
            result = await self.check_url(session, url)
            
            # If successful or not a retryable error, return
            if result.status < 500 or attempt == self.max_retries:
                return result
            
            # Only retry on server errors (5xx) or timeouts
            if result.status >= 500 or "Timeout" in str(result.error):
                logger.debug(f"Retrying {url} (attempt {attempt + 1}/{self.max_retries + 1})")
                continue
                
            break
        
        return result

class OutputManager:
    """Manage output in different formats"""
    
    @staticmethod
    def save_results(results: List[ScanResult], output_file: str, format: str = 'txt'):
        """Save results in different formats"""
        try:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            if format == 'json':
                OutputManager._save_json(results, output_file)
            elif format == 'csv':
                OutputManager._save_csv(results, output_file)
            else:
                OutputManager._save_txt(results, output_file)
                
            logger.info(f"Results saved to {output_file} in {format.upper()} format")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            raise

    @staticmethod
    def _save_txt(results: List[ScanResult], output_file: str):
        """Save as simple text file (URLs only)"""
        with open(output_file, 'w') as f:
            for result in sorted(results, key=lambda x: x.url):
                if result.status < 400 and not result.error:
                    f.write(f"{result.url}\n")

    @staticmethod
    def _save_json(results: List[ScanResult], output_file: str):
        """Save as JSON with full details"""
        data = [
            {
                'url': r.url,
                'status': r.status,
                'response_time': r.response_time,
                'error': r.error,
                'content_length': r.content_length,
                'headers': r.headers
            }
            for r in results
        ]
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    @staticmethod
    def _save_csv(results: List[ScanResult], output_file: str):
        """Save as CSV"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Status', 'Response Time', 'Error', 'Content Length'])
            for result in sorted(results, key=lambda x: x.url):
                writer.writerow([
                    result.url,
                    result.status,
                    f"{result.response_time:.3f}" if result.response_time else '',
                    result.error or '',
                    result.content_length or ''
                ])

def read_targets(file_path: str) -> List[str]:
    """Read targets from file with validation"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        if not targets:
            logger.error(f"No valid targets found in {file_path}")
            sys.exit(1)
            
        logger.info(f"Loaded {len(targets)} targets from {file_path}")
        return targets
    except FileNotFoundError:
        logger.error(f"Input file '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading input file: {e}")
        sys.exit(1)

def read_ports(ports_arg: str = None, ports_file: str = None) -> List[str]:
    """Read ports from argument or file"""
    if ports_file:
        try:
            with open(ports_file, 'r') as f:
                ports = [line.strip() for line in f if line.strip()]
            ports = [port for port in ports if Config.validate_port(port)]
            if not ports:
                logger.error("No valid ports found in ports file")
                sys.exit(1)
            logger.info(f"Loaded {len(ports)} ports from {ports_file}")
            return ports
        except FileNotFoundError:
            logger.error(f"Ports file '{ports_file}' not found.")
            sys.exit(1)
    elif ports_arg:
        ports = [port.strip() for port in ports_arg.split(',')]
        ports = [port for port in ports if Config.validate_port(port)]
        if not ports:
            logger.error("No valid ports provided")
            sys.exit(1)
        return ports
    else:
        return [str(port) for port in Config.DEFAULT_PORTS]

def generate_targets(hosts: List[str], ports: List[str]) -> List[str]:
    """Generate target:port combinations"""
    targets = []
    for host in hosts:
        host = host.strip()
        if not host:
            continue
        
        # If host already has a port, use it as is
        if ':' in host and not host.endswith(']'):  # Skip IPv6 with ports
            targets.append(host)
        else:
            # Add all ports to host
            for port in ports:
                targets.append(f"{host}:{port}")
    return targets

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Enhanced HTTP URL Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i ips.txt
  %(prog)s -i hosts.txt -o results.json --format json
  %(prog)s -i targets.txt -p 80,443,8080 --concurrency 200
  %(prog)s -i list.txt -f ports.txt --rate-limit 50 --max-retries 2
        """
    )
    
    parser.add_argument('-i', '--input', required=True, 
                       help='File containing IPs or hosts to scan')
    parser.add_argument('-o', '--output', default='valid-urls.txt', 
                       help='File to save results to (default: valid-urls.txt)')
    parser.add_argument('-p', '--ports', 
                       help='Comma-separated port list (e.g., 80,443,3000)')
    parser.add_argument('-f', '--ports-file', 
                       help='File with one port per line')
    parser.add_argument('--format', choices=['txt', 'json', 'csv'], default='txt', 
                       help='Output format (default: txt)')
    parser.add_argument('--timeout', type=int, default=5, 
                       help='Request timeout in seconds (default: 5)')
    parser.add_argument('--concurrency', type=int, default=100, 
                       help='Number of concurrent requests (default: 100)')
    parser.add_argument('--rate-limit', type=int, 
                       help='Requests per second limit')
    parser.add_argument('--max-retries', type=int, default=0, 
                       help='Maximum retry attempts (default: 0)')
    parser.add_argument('--no-https', action='store_true', 
                       help='Skip HTTPS checks')
    parser.add_argument('--verify-ssl', action='store_true', 
                       help='Verify SSL certificates (default: False)')
    parser.add_argument('--verbose', action='store_true', 
                       help='Enable verbose logging')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Validate arguments
    if args.timeout > Config.MAX_TIMEOUT:
        logger.warning(f"Timeout reduced from {args.timeout} to {Config.MAX_TIMEOUT} seconds")
        args.timeout = Config.MAX_TIMEOUT
    
    if args.concurrency > Config.MAX_CONCURRENT:
        logger.warning(f"Concurrency reduced from {args.concurrency} to {Config.MAX_CONCURRENT}")
        args.concurrency = Config.MAX_CONCURRENT
    
    try:
        # Read inputs
        hosts = read_targets(args.input)
        ports = read_ports(args.ports, args.ports_file)
        
        # Generate targets with ports
        targets = generate_targets(hosts, ports)
        
        if not targets:
            logger.error("No valid targets to scan")
            sys.exit(1)
        
        logger.info(f"Scanning {len(hosts)} hosts with {len(ports)} ports each "
                   f"(total: {len(targets)} targets)")
        logger.info(f"Ports: {', '.join(ports)}")
        
        # Initialize scanner
        scanner_kwargs = {
            'timeout': args.timeout,
            'concurrency': args.concurrency,
            'verify_ssl': args.verify_ssl
        }
        
        if args.rate_limit or args.max_retries > 0:
            scanner = RateLimitedScanner(
                requests_per_second=args.rate_limit or 50,
                max_retries=args.max_retries,
                **scanner_kwargs
            )
        else:
            scanner = EnhancedURLScanner(**scanner_kwargs)
        
        # Determine schemes to scan
        schemes = ['http'] if args.no_https else ['http', 'https']
        
        # Scan targets
        start_time = time.time()
        results = await scanner.scan_with_details(targets, schemes)
        end_time = time.time()
        
        # Save results
        OutputManager.save_results(results, args.output, args.format)
        
        # Print summary
        scanner.print_statistics()
        logger.info(f"Scan completed in {end_time - start_time:.2f} seconds")
        logger.info(f"Results saved to {args.output}")
        
        # Print valid URLs count
        valid_urls = [r for r in results if r.status < 400 and not r.error]
        logger.info(f"Found {len(valid_urls)} valid URLs")
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.debug:
            logger.exception("Detailed error:")
        sys.exit(1)

if __name__ == "__main__":
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(1))
    
    # Run main function
    asyncio.run(main())
