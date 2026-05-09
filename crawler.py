from __future__ import annotations

import asyncio
import csv
import gzip
import json
from collections import deque
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlsplit

import pandas as pd
from lxml import html
from playwright.async_api import async_playwright

# ========== CONFIGURATION ==========
INPUT_CSV = "superlist/merged_global_country_superlist.csv"
OUTPUT_CSV = "csp_scan_results.csv"
HTML_DIR = Path("html_pages")
NAV_TIMEOUT_MS = 30000
HEADLESS = True
MAX_HOSTS = None
MAX_CONCURRENT = 30
BROWSER_RESTART_INTERVAL = 500        # restart browser after this many hosts

# Hard outer timeout (seconds) applied per host via asyncio.wait_for.
# Should be larger than NAV_TIMEOUT_MS * 2 to allow for homepage + internal page.
HOST_HARD_TIMEOUT_S = 90

# Realistic User-Agent for Chrome on Windows
REAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

# Extra headers to look more like a real browser
EXTRA_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

csv_write_lock = asyncio.Lock()
HTML_DIR.mkdir(exist_ok=True)

# ---------- Progress tracking ----------
total_scanned = 0
total_success = 0
total_failed = 0
last_errors = deque(maxlen=500)      # store last 500 error messages
progress_lock = asyncio.Lock()

def update_progress(success: bool, host: str, error_msg: str = ""):
    global total_scanned, total_success, total_failed, last_errors
    total_scanned += 1
    if success:
        total_success += 1
    else:
        total_failed += 1
        if error_msg:
            last_errors.append(f"{host}: {error_msg}")
    print(f"[{total_scanned}] Success: {total_success} | Failed: {total_failed} | Last host: {host}")

# --------------------------------------

def save_html_gz(host: str, page_type: str, html_content: str) -> str:
    if not html_content:
        return ""
    safe_host = host.replace(".", "_").replace("/", "_")
    filename = f"{safe_host}_{page_type}.html.gz"
    filepath = HTML_DIR / filename
    with gzip.open(filepath, "wt", encoding="utf-8") as f:
        f.write(html_content)
    return str(filepath)


def normalize_host(host: str) -> str:
    s = str(host).strip().lower().rstrip(".")
    if not s:
        raise ValueError("empty host")
    return s


def is_probably_html_path(url: str) -> bool:
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


def extract_first_same_host_internal_html_link(page_url: str, html_text: str) -> Optional[str]:
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
    # Use domcontentloaded instead of load — fires reliably even on pages
    # that never finish loading all resources (which can stall "load" forever).
    response = await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
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


def _make_error_result(rank, host, country, error_msg: str) -> Dict[str, Any]:
    return {
        "rank": rank,
        "host": host,
        "country": country,
        "homepage_final_url": None,
        "homepage_status": None,
        "homepage_all_headers": None,
        "homepage_html_file": "",
        "first_internal_final_url": None,
        "first_internal_status": None,
        "first_internal_all_headers": None,
        "first_internal_html_file": "",
        "error": error_msg,
    }


async def scan_one_host(browser, host: str, rank: Optional[int] = None, country: Optional[str] = None) -> Dict[str, Any]:
    context = await browser.new_context(
        ignore_https_errors=False,
        user_agent=REAL_UA,
        viewport={"width": 1920, "height": 1080},
        extra_http_headers=EXTRA_HEADERS,
    )
    page = await context.new_page()
    await page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
        window.chrome = {runtime: {}};
    """)

    try:
        homepage = await try_homepage(page, host)
        homepage_html_file = save_html_gz(host, "home", homepage["html"])

        first_internal = extract_first_same_host_internal_html_link(
            homepage["final_url"],
            homepage["html"],
        )

        internal = None
        internal_html_file = ""
        if first_internal:
            try:
                internal = await nav_and_collect(page, first_internal)
                internal_html_file = save_html_gz(host, "internal", internal["html"])
            except Exception as e:
                internal = {
                    "requested_url": first_internal,
                    "final_url": None,
                    "status": None,
                    "headers": {},
                    "html": None,
                    "error": f"{type(e).__name__}: {e}",
                }

        return {
            "rank": rank,
            "host": host,
            "country": country,
            "homepage_final_url": homepage["final_url"],
            "homepage_status": homepage["status"],
            "homepage_all_headers": json.dumps(homepage["headers"]),
            "homepage_html_file": homepage_html_file,
            "first_internal_final_url": None if internal is None else internal["final_url"],
            "first_internal_status": None if internal is None else internal["status"],
            "first_internal_all_headers": json.dumps(internal["headers"]) if internal else None,
            "first_internal_html_file": internal_html_file,
            "error": None,
        }
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        return _make_error_result(rank, host, country, error_msg)
    finally:
        try:
            await context.close()
        except Exception:
            pass


async def write_result_row(result: Dict[str, Any], headers: list):
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
    if not Path(OUTPUT_CSV).is_file():
        return set()

    hosts_with_success = set()          # hosts with at least one error-free row
    error_attempt_counts = {}           # host -> number of attempts that ended in an error

    with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            host = row.get("host")
            if not host:
                continue
            if not row.get("error"):
                hosts_with_success.add(host)
            else:
                error_attempt_counts[host] = error_attempt_counts.get(host, 0) + 1

    # Also treat hosts with 3+ failed attempts as done to stop retrying them
    for host, count in error_attempt_counts.items():
        if host not in hosts_with_success and count >= 3:
            hosts_with_success.add(host)

    return hosts_with_success


async def main():
    global total_scanned, total_success, total_failed, last_errors

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
        "homepage_all_headers",
        "homepage_html_file",
        "first_internal_final_url", "first_internal_status",
        "first_internal_all_headers",
        "first_internal_html_file",
        "error"
    ]

    total_to_scan = len(df)
    print(f"Hosts to scan (pending): {total_to_scan} (already successful: {len(successful_hosts)})")
    print(f"Starting scan with concurrency {MAX_CONCURRENT}, "
          f"browser restarts every {BROWSER_RESTART_INTERVAL} hosts...\n")

    async with async_playwright() as p:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        for chunk_start in range(0, len(df), BROWSER_RESTART_INTERVAL):
            chunk_df = df.iloc[chunk_start:chunk_start + BROWSER_RESTART_INTERVAL]
            print(f"\n--- Processing chunk {chunk_start // BROWSER_RESTART_INTERVAL + 1} "
                  f"({len(chunk_df)} hosts) ---")

            browser = await p.chromium.launch(
                headless=HEADLESS,
                executable_path="/snap/bin/chromium",
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--no-sandbox",
                    "--disable-dev-shm-usage"
                ]
            )

            async def bounded_scan(row):
                async with semaphore:
                    host = row["host"]
                    rank = row.get("rank")
                    country = row.get("country")
                    try:
                        # Hard outer timeout — guards against Playwright's own
                        # timeout silently failing on certain stuck pages.
                        result = await asyncio.wait_for(
                            scan_one_host(browser, host, rank=rank, country=country),
                            timeout=HOST_HARD_TIMEOUT_S,
                        )
                        await write_result_row(result, output_headers)
                        is_success = (result["error"] is None)
                        update_progress(is_success, host, result["error"] if not is_success else "")
                    except asyncio.TimeoutError:
                        error_msg = f"HardTimeout: host did not complete within {HOST_HARD_TIMEOUT_S}s"
                        print(f"⚠️  {host}: {error_msg}")
                        update_progress(False, host, error_msg)
                        await write_result_row(_make_error_result(rank, host, country, error_msg), output_headers)
                    except Exception as e:
                        error_msg = f"UNHANDLED: {type(e).__name__}: {e}"
                        update_progress(False, host, error_msg)
                        await write_result_row(_make_error_result(rank, host, country, error_msg), output_headers)
                    return

            tasks = [asyncio.create_task(bounded_scan(row)) for _, row in chunk_df.iterrows()]
            try:
                await asyncio.gather(*tasks)
            except Exception as e:
                print(f"⚠️  Chunk gather error: {type(e).__name__}: {e}")

            try:
                await browser.close()
            except Exception:
                pass
            print(f"--- Finished chunk, browser closed. ---")

    print("\n========== SCAN COMPLETE ==========")
    print(f"Total scanned: {total_scanned}")
    print(f"Successful: {total_success}")
    print(f"Failed: {total_failed}")
    if last_errors:
        print("\n--- Last 500 errors ---")
        for err in last_errors:
            print(err)
    print(f"All results saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    asyncio.run(main())