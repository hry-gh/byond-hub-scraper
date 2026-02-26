import asyncio
import html
import logging
import os
import re
import time
import psycopg2
import requests
import zendriver as zd
from bs4 import BeautifulSoup

logging.getLogger("websockets").setLevel(logging.ERROR)
logging.getLogger("zendriver").setLevel(logging.ERROR)

URL = "https://www.byond.com/games/Exadv1/SpaceStation13"
TEXT_URL = "https://www.byond.com/games/Exadv1/SpaceStation13?format=text"

def find_chrome():
    """Find Chrome/Chromium executable."""
    paths = [
        # GitHub Actions runner
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        # Linux - common locations
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        # macOS
        os.path.expanduser("~/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ]
    for path in paths:
        if os.path.exists(path):
            return path
    return None


async def scrape_servers():
    chrome_path = find_chrome()
    browser_args = [
        "--password-store=basic",
        "--use-mock-keychain",
        "--disable-background-networking",
        # Move window off-screen
        "--window-position=-2000,-2000",
        # Required for running as root/in containers
        "--no-sandbox",
        # Overcome limited /dev/shm in containers
        "--disable-dev-shm-usage",
    ]

    if chrome_path:
        browser = await zd.start(
            browser_executable_path=chrome_path,
            browser_args=browser_args,
        )
    else:
        browser = await zd.start(browser_args=browser_args)

    page = await browser.get(URL)
    await asyncio.sleep(10)
    html = await page.get_content()

    try:
        await browser.stop()
    except Exception:
        pass

    resp = requests.get(TEXT_URL, headers={"User-Agent": "Mozilla/5.0"})
    text_data = resp.text

    html_data = parse_html_data(html)
    servers = parse_text_format(text_data)

    for server in servers:
        url = server["connection_url"]
        if url in html_data:
            server["players"] = html_data[url]["players"]
            server["status"] = html_data[url]["status"]

    return servers


def parse_html_data(html):
    data = {}
    soup = BeautifulSoup(html, "html.parser")
    entries = soup.select(".live_game_entry")

    for entry in entries:
        entry_html = str(entry)
        entry_text = entry.get_text()

        # Extract byond:// URL
        url = None
        link = entry.select_one('a[href^="byond://"]')
        if link:
            url = link.get("href")
        else:
            url_match = re.search(r"byond://[^\s<\"']+", entry_html)
            if url_match:
                url = url_match.group(0)

        if not url:
            continue

        players = 0
        player_match = re.search(r"Logged in:\s*(\d+)", entry_text)
        if player_match:
            players = int(player_match.group(1))

        status = ""
        status_div = entry.select_one(".live_game_status")
        if status_div:
            status_html = str(status_div)
            status_html = re.sub(r'^<div[^>]*>', '', status_html)
            status_html = re.sub(r'</div>$', '', status_html)
            status_html = re.sub(r'\s*<br\s*/?>\s*<br\s*/?>.*$', '', status_html, flags=re.DOTALL)
            status_html = re.sub(r'(\s*<br\s*/?>)+\s*$', '', status_html)
            status_html = re.sub(r'<span[^>]*class="smaller"[^>]*>.*?</span>', '', status_html, flags=re.DOTALL)
            status_html = re.sub(
                r'(<a\s[^>]*>)([^<\]\)]+)([\]\)]+)([^<]*</a>)',
                r'\1\2</a>\3\4',
                status_html
            )
            status_html = re.sub(
                r'(<a\s[^>]*>)(\w+)([\]\)]+)(.*?)(</a>)',
                r'\1\2</a>\3\4',
                status_html,
                flags=re.DOTALL
            )
            status_html = status_html.strip()
            status = status_html

        data[url] = {"players": players, "status": status}

    return data


def parse_text_format(text):
    servers = []

    text = text.replace('\r\n', '\n')

    world_pattern = re.compile(r'^world/\d+$', re.MULTILINE)
    sections = world_pattern.split(text)

    for section in sections[1:]:
        lines = section.strip().split('\n')

        url = None
        status = None

        for line in lines:
            line = line.strip()
            if line.startswith('url = '):
                url = line[7:-1]
            elif line.startswith('status = '):
                status = line[10:-1]
                status = status.replace('\\"', '"').replace('\\n', '\n').replace('\\[', '[').replace('\\]', ']')
                status = html.unescape(status)

        if not url:
            continue

        name = url
        description = ""

        if status:
            status_soup = BeautifulSoup(status, "html.parser")

            bold = status_soup.find("b")
            if bold:
                name = bold.get_text(strip=True)

            for br in status_soup.find_all("br"):
                br.replace_with(" | ")
            desc = status_soup.get_text(separator=" ").strip()
            desc = re.sub(r'\s+', ' ', desc)

            if desc.startswith(name):
                desc = desc[len(name):].strip()

            desc = re.sub(r'^[\s—\-:]+', '', desc)
            desc = re.sub(r'^\(\s*Discord\s*\)\]?\s*', '', desc)  # Remove (Discord)] prefix
            desc = re.sub(r'^\[\s*', '', desc)  # Remove leading [
            desc = re.sub(r'\s*\]$', '', desc)  # Remove trailing ]
            desc = re.sub(r'\|\s*\|', '|', desc)  # Remove double pipes
            desc = desc.strip(' |')
            description = desc

        servers.append({
            "connection_url": url,
            "players": 0,
            "name": name,
            "description": description,
            "status": ""
        })

    return servers


DATABASE_URL = os.environ.get("DATABASE_URL", "")


def init_db(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                world_id BIGINT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT,
                players INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS player_history (
                id SERIAL PRIMARY KEY,
                world_id BIGINT NOT NULL,
                players INTEGER NOT NULL,
                recorded_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_player_history_world_id
            ON player_history(world_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_player_history_recorded_at
            ON player_history(recorded_at)
        """)
    conn.commit()


def extract_world_id(url):
    match = re.search(r'BYOND\.world\.(\d+)', url)
    return int(match.group(1)) if match else None

def save_to_db(conn, servers):
    with conn.cursor() as cur:
        for server in servers:
            world_id = extract_world_id(server["connection_url"])
            if not world_id:
                continue

            cur.execute("""
                INSERT INTO servers (world_id, name, description, status, players, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (world_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    status = EXCLUDED.status,
                    players = EXCLUDED.players,
                    updated_at = NOW()
            """, (world_id, server["name"], server["description"], server["status"], server["players"]))

            cur.execute("""
                INSERT INTO player_history (world_id, players)
                VALUES (%s, %s)
            """, (world_id, server["players"]))

    conn.commit()


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def run_once():
    log("Scraping BYOND SS13 servers...")

    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda loop, ctx: None)
    asyncio.set_event_loop(loop)

    servers = loop.run_until_complete(scrape_servers())
    loop.close()

    log(f"Found {len(servers)} servers")

    if not DATABASE_URL:
        log("DATABASE_URL not set, skipping database save")
        return

    conn = psycopg2.connect(DATABASE_URL)
    init_db(conn)
    save_to_db(conn, servers)
    conn.close()

    log("Saved to database")


def main():
    log("Starting scraper loop...")
    while True:
        try:
            run_once()
        except Exception as e:
            log(f"Error: {e}")
            import traceback
            traceback.print_exc()
        log("Sleeping 30 seconds...")
        time.sleep(30)


if __name__ == "__main__":
    main()
