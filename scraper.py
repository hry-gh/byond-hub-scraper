import argparse
import asyncio
import html
import json
import logging
import os
import re
import time
import requests
import zendriver as zd
from bs4 import BeautifulSoup

TEST_MODE = False

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
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'servers' AND column_name = 'world_id'
            )
        """)
        old_schema_exists = cur.fetchone()[0]

        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE table_name = 'servers' AND constraint_type = 'PRIMARY KEY'
                AND constraint_name = 'servers_pkey'
            )
        """)

        if old_schema_exists:
            cur.execute("""
                SELECT column_name FROM information_schema.key_column_usage
                WHERE table_name = 'servers' AND constraint_name = 'servers_pkey'
            """)
            pk_col = cur.fetchone()
            if pk_col and pk_col[0] == 'world_id':
                cur.execute("DROP TABLE IF EXISTS player_history")
                cur.execute("DROP TABLE IF EXISTS servers")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                address TEXT PRIMARY KEY,
                world_id BIGINT,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT,
                topic_status JSONB,
                players INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS player_history (
                id SERIAL PRIMARY KEY,
                address TEXT NOT NULL,
                players INTEGER NOT NULL,
                recorded_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_player_history_address
            ON player_history(address)
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
    from psycopg2.extras import Json

    with conn.cursor() as cur:
        for server in servers:
            world_id = extract_world_id(server["connection_url"])

            address = server.get("address")
            if not address:
                continue
            topic_status = server.get("topic_status")

            if not isinstance(topic_status, dict):
                topic_status = None

            cur.execute("""
                INSERT INTO servers (address, world_id, name, description, status, topic_status, players, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (address) DO UPDATE SET
                    world_id = EXCLUDED.world_id,
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    status = EXCLUDED.status,
                    topic_status = EXCLUDED.topic_status,
                    players = EXCLUDED.players,
                    updated_at = NOW()
            """, (address, world_id, server["name"], server["description"], server["status"], Json(topic_status) if topic_status else None, server["players"]))

            cur.execute("""
                INSERT INTO player_history (address, players)
                VALUES (%s, %s)
            """, (address, server["players"]))

    conn.commit()


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def resolve_addresses(servers):
    try:
        from hub_lookup import lookup_worlds
    except ImportError:
        log("hub_lookup module not available - using connection URLs as addresses")
        for server in servers:
            server["address"] = server["connection_url"]
        return True

    world_ids = []
    id_to_server = {}

    for server in servers:
        world_id = extract_world_id(server["connection_url"])
        if world_id:
            world_ids.append(str(world_id))
            id_to_server[str(world_id)] = server

    if not world_ids:
        return False

    try:
        results = lookup_worlds(world_ids)
        resolved = 0
        for world_id, result in zip(world_ids, results):
            if result.address:
                id_to_server[world_id]["address"] = result.address
                resolved += 1
        log(f"Resolved {resolved}/{len(world_ids)} addresses")
    except Exception as e:
        log(f"Address resolution failed: {e}")

    return False


def ping_servers(servers, timeout=5):
    import socket
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from byond.topic import queryStatus, send, TOPIC_RESPONSE_STRING

    def parse_topic_result(result):
        if not result or not isinstance(result, dict):
            return result

        keys = list(result.keys())

        # Check if the only key looks like JSON
        if len(keys) == 1 and keys[0].startswith("{"):
            try:
                parsed = json.loads(keys[0])
                # If it has a "data" field, extract that
                if isinstance(parsed, dict) and "data" in parsed:
                    return parsed["data"]
                return parsed
            except json.JSONDecodeError:
                pass

        # Handle query parameter format: {"key": ["value"], ...}
        # Flatten single-item lists and parse numeric values
        cleaned = {}
        for key, value in result.items():
            if isinstance(value, list) and len(value) == 1:
                value = value[0]

            if isinstance(value, str):
                try:
                    if '.' in value:
                        value = float(value)
                    else:
                        value = int(value)
                except ValueError:
                    pass
            cleaned[key] = value

        return cleaned

    def ping_one(server):
        address = server.get("address")
        if not address:
            return None
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                host, port_str = address.split(":")
                port = int(port_str)
                result = queryStatus(host, port)

                # If response only has "players", try JSON query for more detail
                if result and list(result.keys()) == ["players"]:
                    try:
                        json_query = '{"query":"status","auth":"anonymous","source":"byond-hub-scraper"}'
                        response_type, response_data = send(host, port, json_query)
                        if response_type == TOPIC_RESPONSE_STRING:
                            result = response_data
                    except Exception:
                        pass

                return parse_topic_result(result)
            finally:
                socket.setdefaulttimeout(old_timeout)
        except Exception:
            return None

    servers_with_addr = [s for s in servers if s.get("address")]
    if not servers_with_addr:
        return

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_one, s): s for s in servers_with_addr}
        pinged = 0
        for future in futures:
            server = futures[future]
            try:
                result = future.result(timeout=timeout)
                server["topic_status"] = result
                if result is not None:
                    pinged += 1
            except TimeoutError:
                server["topic_status"] = None
            except Exception:
                server["topic_status"] = None

    log(f"Pinged {pinged}/{len(servers_with_addr)} servers")


def run_once():
    log("Scraping BYOND SS13 servers...")

    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda _loop, _ctx: None)
    asyncio.set_event_loop(loop)

    servers = loop.run_until_complete(scrape_servers())
    loop.close()

    log(f"Found {len(servers)} servers")

    resolve_addresses(servers)
    ping_servers(servers)

    if TEST_MODE:
        print(json.dumps(servers, indent=2))
        return servers

    if not DATABASE_URL:
        log("DATABASE_URL not set, skipping database save")
        return servers

    import psycopg2
    conn = psycopg2.connect(DATABASE_URL)
    init_db(conn)
    save_to_db(conn, servers)
    conn.close()

    log("Saved to database")
    return servers


def main():
    global TEST_MODE

    parser = argparse.ArgumentParser(description="BYOND SS13 server scraper")
    parser.add_argument("--test", action="store_true", help="Test mode: scrape once and print JSON output")
    args = parser.parse_args()

    if args.test:
        TEST_MODE = True
        run_once()
        return

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
