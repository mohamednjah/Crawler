from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlsplit

import pandas as pd
from lxml import html
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# ========== CONFIGURATION ==========
# NAV_TIMEOUT_MS: Maximum time (in milliseconds) to wait for each page navigation.
# HEADLESS: Run browser in headless mode (no GUI) if True.
# MAX_HOSTS: Limit the number of hosts to process (useful for testing). None = all hosts.
# MAX_CONCURRENT: Maximum number of hosts to scan simultaneously.
# ====================================
INPUT_CSV = "../Top list generator/data/merged_global_country_superlist.csv"
OUTPUT_CSV = "csp_scan_results.csv"
NAV_TIMEOUT_MS = 30000
HEADLESS = True
MAX_HOSTS = 500
MAX_CONCURRENT = 20

csv_write_lock = asyncio.Lock()


def normalize_host(host: str) -> str:
    """
    Normalize a hostname: strip whitespace, convert to lowercase, remove trailing dot.
    
    Input: host (str) – raw hostname from CSV.
    Returns: Cleaned hostname as string.
    Raises: ValueError if input is empty after normalisation.
    """
    s = str(host).strip().lower().rstrip(".")
    if not s:
        raise ValueError("empty host")
    return s


def is_probably_html_path(url: str) -> bool:
    """
    Determine whether a URL path likely points to an HTML page (not a binary file).
    
    Input: url (str) – full URL.
    Returns: True if the path has no extension or ends with a common HTML‑related extension,
             False if it ends with a known binary / non‑HTML extension (e.g. .jpg, .pdf, .js).
    """
    path = urlsplit(url).path.lower()
    if not path or path.endswith("/"):
        return True
    bad_exts = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
        ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar",
        ".mp4", ".mp3", ".avi", ".mov", ".mkv",
        ".css", ".js", ".json", ".xml", ".txt",
        ".woff", ".woff2", ".ttf", ".otf",
    }
    return not any(path.endswith(ext) for ext in bad_exts)


def extract_meta_csp(html_text: str) -> tuple[Optional[str], Optional[str]]:
    """
    Extract CSP and CSP‑report‑only from <meta http-equiv> tags in the HTML.
    
    Input:
      - html_text (str): The HTML source.
    Returns:
      Tuple (csp, csp_report_only) where each is the content attribute value or None.
    """
    try:
        tree = html.fromstring(html_text)
    except Exception:
        return None, None
    
    csp = None
    csp_report_only = None
    
    # Find all meta tags with http-equiv attribute
    for meta in tree.xpath("//meta[@http-equiv]"):
        equiv = meta.get("http-equiv", "").lower()
        content = meta.get("content")
        if not content:
            continue
        if equiv == "content-security-policy":
            csp = content
        elif equiv == "content-security-policy-report-only":
            csp_report_only = content
    return csp, csp_report_only


def extract_first_same_host_internal_html_link(page_url: str, html_text: str) -> Optional[str]:
    """
    Extract the first internal HTML link that belongs to the same host as the page URL.
    
    Input:
      - page_url (str): The URL of the page being parsed.
      - html_text (str): The HTML source of that page.
    Returns:
      The absolute URL of the first suitable internal link, or None if none found.
    """
    try:
        tree = html.fromstring(html_text)
    except Exception:
        return None
    page_host = urlsplit(page_url).hostname
    if not page_host:
        return None
    seen = set()
    current_no_frag = urlsplit(page_url)._replace(fragment="").geturl()
    for href in tree.xpath("//a[@href]/@href"):
        if not href:
            continue
        href = href.strip()
        if not href or href.startswith("#"):
            continue
        lower = href.lower()
        if lower.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        abs_url = urljoin(page_url, href)
        parsed = urlsplit(abs_url)
        if parsed.scheme not in {"http", "https"}:
            continue
        if parsed.hostname != page_host:
            continue
        if not is_probably_html_path(abs_url):
            continue
        path_lower = parsed.path.lower()
        if any(x in path_lower for x in ["/logout", "/signout", "/cart", "/checkout"]):
            continue
        cleaned = parsed._replace(fragment="").geturl()
        if cleaned in seen:
            continue
        seen.add(cleaned)
        if cleaned == current_no_frag:
            continue
        return cleaned
    return None


async def nav_and_collect(page, url: str) -> Dict[str, Any]:
    """
    Navigate to a URL and collect response data.
    
    Input:
      - page: Playwright Page object.
      - url (str): The URL to navigate to.
    Returns:
      Dict containing:
        - requested_url
        - final_url (after redirects)
        - status (HTTP status code)
        - headers (all response headers as dict)
        - html (full page HTML source)
    Raises: RuntimeError if no main document response is received.
    """
    response = await page.goto(url, wait_until="load", timeout=NAV_TIMEOUT_MS)
    if response is None:
        raise RuntimeError(f"No main-document response for {url!r}")
    headers = await response.all_headers()
    final_url = page.url
    body_html = await page.content()
    return {
        "requested_url": url,
        "final_url": final_url,
        "status": response.status,
        "headers": headers,
        "html": body_html,
    }


async def try_homepage(page, host: str) -> Dict[str, Any]:
    """
    Attempt to load the homepage of a host, trying HTTPS first, then HTTP.
    
    Input:
      - page: Playwright Page object.
      - host (str): The hostname (e.g. "example.com").
    Returns:
      The dictionary returned by nav_and_collect() for the successful scheme,
      plus an extra key "homepage_attempt_scheme" indicating which scheme worked.
    Raises: RuntimeError if both HTTPS and HTTP attempts fail.
    """
    errors = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            result = await nav_and_collect(page, url)
            result["homepage_attempt_scheme"] = scheme
            return result
        except Exception as e:
            errors.append(f"{scheme}: {type(e).__name__}: {e}")
    raise RuntimeError(" ; ".join(errors))


async def scan_one_host(browser, host: str, rank: Optional[int] = None, country: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan a single host: load homepage, find an internal link, load that internal page.

    Input:
      - browser: Playwright Browser object.
      - host (str): Hostname to scan.
      - rank (int, optional): Rank from input CSV.
      - country (str, optional): Country from input CSV.
    Returns:
      Dict with keys that match the current `output_headers` defined in main().
    """
    context = await browser.new_context(ignore_https_errors=False)
    page = await context.new_page()
    try:
        homepage = await try_homepage(page, host)

        # Extract meta CSP from homepage HTML
        homepage_meta_csp, homepage_meta_csp_report_only = extract_meta_csp(homepage["html"])

        first_internal = extract_first_same_host_internal_html_link(
            homepage["final_url"],
            homepage["html"],
        )

        internal = None
        internal_meta_csp = None
        internal_meta_csp_report_only = None
        if first_internal:
            try:
                internal = await nav_and_collect(page, first_internal)
                internal_meta_csp, internal_meta_csp_report_only = extract_meta_csp(internal["html"])
            except Exception as e:
                internal = {
                    "requested_url": first_internal,
                    "final_url": None,
                    "status": None,
                    "headers": {},
                    "html": None,
                    "error": f"{type(e).__name__}: {e}",
                }
                # meta CSP remains None

        return {
            "rank": rank,
            "host": host,
            "country": country,
            "homepage_final_url": homepage["final_url"],
            "homepage_status": homepage["status"],
            "homepage_all_headers": json.dumps(homepage["headers"]),
            "homepage_meta_csp": homepage_meta_csp,
            "homepage_meta_csp_report_only": homepage_meta_csp_report_only,
            "first_internal_final_url": None if internal is None else internal["final_url"],
            "first_internal_status": None if internal is None else internal["status"],
            "first_internal_all_headers": json.dumps(internal["headers"]) if internal else None,
            "first_internal_meta_csp": internal_meta_csp,
            "first_internal_meta_csp_report_only": internal_meta_csp_report_only,
            "error": None,
        }
    except Exception as e:
        return {
            "rank": rank,
            "host": host,
            "country": country,
            "homepage_final_url": None,
            "homepage_status": None,
            "homepage_all_headers": None,
            "homepage_meta_csp": None,
            "homepage_meta_csp_report_only": None,
            "first_internal_final_url": None,
            "first_internal_status": None,
            "first_internal_all_headers": None,
            "first_internal_meta_csp": None,
            "first_internal_meta_csp_report_only": None,
            "error": f"{type(e).__name__}: {e}",
        }
    finally:
        await context.close()


async def write_result_row(result: Dict[str, Any], headers: list):
    """
    Append one result row to the output CSV file in a thread‑safe manner.
    
    Input:
      - result (dict): The result dictionary for a single host.
      - headers (list): The column names (order) to use in the CSV.
    Returns: None.
    """
    async with csv_write_lock:
        file_exists = Path(OUTPUT_CSV).is_file()
        if not file_exists or Path(OUTPUT_CSV).stat().st_size == 0:
            with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
        with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writerow(result)


def get_successful_hosts() -> set:
    """
    Read the existing output CSV and return a set of hosts that have at least one successful scan.
    
    A scan is considered successful if the 'error' column is empty.
    
    Input: None.
    Returns: set of hostnames (strings) that have a successful entry in the CSV.
    """
    if not Path(OUTPUT_CSV).is_file():
        return set()
    successful = set()
    with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            host = row.get("host")
            if not host:
                continue
            if not row.get("error"):
                successful.add(host)
    return successful


async def main():
    """
    Main asynchronous entry point.
    
    Workflow:
      1. Read input CSV and normalise hostnames.
      2. Determine which hosts have already been successfully scanned (skip them).
      3. Prepare output CSV headers (JSON of all headers, no separate CSP header columns).
      4. Launch Playwright browser.
      5. Use a semaphore to limit concurrency (MAX_CONCURRENT).
      6. Create tasks for each pending host and run them concurrently.
      7. Handle graceful shutdown on Ctrl+C.
      8. Print final summary.
    """
    df = pd.read_csv(INPUT_CSV)
    if MAX_HOSTS is not None:
        df = df.head(MAX_HOSTS).copy()
    df["host"] = df["host"].map(normalize_host)

    successful_hosts = get_successful_hosts()
    df = df[~df["host"].isin(successful_hosts)]
    if len(df) == 0:
        print("All hosts already successfully scanned. Nothing to do.")
        return

    output_headers = [
        "rank", "host", "country",
        "homepage_final_url", "homepage_status",
        "homepage_all_headers", "homepage_meta_csp", "homepage_meta_csp_report_only",
        "first_internal_final_url", "first_internal_status",
        "first_internal_all_headers", "first_internal_meta_csp", "first_internal_meta_csp_report_only",
        "error"
    ]

    total = len(df)
    print(f"Hosts to scan (pending): {total} (already successful: {len(successful_hosts)})")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=HEADLESS)
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        async def bounded_scan(row):
            async with semaphore:
                host = row["host"]
                rank = row.get("rank")
                country = row.get("country")
                print(f"Starting scan: {host}")
                result = await scan_one_host(browser, host, rank=rank, country=country)
                await write_result_row(result, output_headers)
                print(f"Finished: {host} (success={result['error'] is None})")
                return result

        tasks = [asyncio.create_task(bounded_scan(row)) for _, row in df.iterrows()]

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            print("\nInterrupt received – shutting down gracefully...")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await browser.close()
            print("Partial results saved to", OUTPUT_CSV)

    print(f"All scans complete. Results saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    asyncio.run(main())