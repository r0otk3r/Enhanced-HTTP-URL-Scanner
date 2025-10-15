# Enhanced HTTP URL Scanner

## Project overview

`Enhanced HTTP URL Scanner` is a fast, asynchronous tool for checking HTTP(S) endpoints across many hosts and ports. It is designed for authorized scanning, quick reconnaissance, and collecting basic response metadata (status code, response time, partial content length, and headers).

Key features

* Asynchronous scanning using `aiohttp` and `asyncio`
* Configurable concurrency, timeouts, rate limiting and retries
* Host validation for IPv4/IPv6 and hostnames
* Save results to `txt`, `json`, or `csv`
* Progress reporting with ETA and rate

---

## Requirements

* Python 3.8+
* `aiohttp`

Install dependency:

```bash
pip install aiohttp
```

---

## Files

* `README.md` — this documentation file
* `url_scanner.py` — the Python script (source code)
* `examples/` — suggested place to store sample input files and example outputs

---

## Quick start

1. Place target hosts in a file (one per line), e.g. `targets.txt`.
2. Run the scanner (basic example):

```bash
python url_scanner.py -i targets.txt
```

3. Save JSON output:

```bash
python url_scanner.py -i targets.txt -o results.json --format json
```

---

## Common options

* `-i, --input` : required — file with hosts or IPs
* `-o, --output` : output file (default: `valid-urls.txt`)
* `-p, --ports` : comma-separated ports (e.g., `80,443`)
* `-f, --ports-file` : file with one port per line
* `--format` : `txt`, `json`, or `csv` (default `txt`)
* `--timeout` : request timeout in seconds (default: 5)
* `--concurrency` : number of concurrent requests (default: 100)
* `--rate-limit` : requests per second limit
* `--max-retries` : maximum retry attempts (default: 0)
* `--no-https` : skip HTTPS checks
* `--verify-ssl` : verify SSL certificates
* `--verbose` / `--debug` : increase logging verbosity

---

## Best practices & safety

* **Only scan targets you own or have explicit permission to test.** Unauthorized scanning may be illegal.
* Use conservative `--concurrency` and `--rate-limit` values against production services to avoid causing outages or triggering WAFs.
* Enable `--verify-ssl` when accuracy for HTTPS hosts matters.
* Consider running from a controlled environment (VPN, jump host) and log scans for auditing.

---

## Contributing

Contributions welcome. Create feature branches, include tests or example input, and open a PR with a clear description.

---

## License

MIT — use responsibly and only on authorized targets.

---

## Official Channels

- [Telegram @r0otk3r](https://t.me/r0otk3r)
- [X @r0otk3r](https://x.com/r0otk3r)
