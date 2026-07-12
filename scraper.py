import argparse
import ctypes
import json
import os
import re
import time

TEST_MODE = False

LIBRARY_PATH = os.environ.get("HUB_LIBRARY_PATH", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
HUB_TIMEOUT_MS = int(os.environ.get("HUB_TIMEOUT_MS", "15000"))


def find_hub_library():
    if LIBRARY_PATH:
        return LIBRARY_PATH
    import sys
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if sys.platform == "darwin":
        names = ["libhub_client_rs.dylib", "libhub_client_rs.so"]
    elif sys.platform == "win32":
        names = ["hub_client_rs.dll"]
    else:
        names = ["libhub_client_rs.so", "libhub_client_rs.dylib"]
    candidates = [os.path.join(script_dir, n) for n in names]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def parse_status_html(status_html):
    import html as html_mod
    from re import sub

    decoded = html_mod.unescape(status_html)

    name_match = re.search(r'<b>([^<]+)</b>', decoded)
    name = name_match.group(1).strip() if name_match else ""

    text = re.sub(r'<[^>]+>', ' ', decoded)
    text = re.sub(r'\s+', ' ', text).strip()

    desc = text
    if name and desc.startswith(name):
        desc = desc[len(name):].strip()
    desc = re.sub(r'^[\s—\-:]+', '', desc)
    desc = re.sub(r'^\(\s*Discord\s*\)\]?\s*', '', desc)
    desc = re.sub(r'^\[\s*', '', desc)
    desc = re.sub(r'\s*\]$', '', desc)
    desc = desc.strip(' |')

    return name, desc


def fetch_servers():
    lib_path = find_hub_library()
    if not lib_path:
        raise RuntimeError("hub-client-rs library not found. Set HUB_LIBRARY_PATH.")

    lib = ctypes.CDLL(lib_path)
    lib.get_servers.argtypes = [ctypes.c_uint64]
    lib.get_servers.restype = ctypes.c_char_p

    result = lib.get_servers(HUB_TIMEOUT_MS)
    if not result:
        raise RuntimeError("hub-client returned null (timeout or error)")

    response = json.loads(result.decode("utf-8"))
    if response.get("error"):
        raise RuntimeError(f"hub-client error: {response['error']}")

    hub_servers = response.get("servers") or []
    servers = []
    for hs in hub_servers:
        address = None
        if hs.get("ip") and hs.get("port"):
            address = f"{hs['ip']}:{hs['port']}"

        status_html = hs.get("name", "")
        name, description = parse_status_html(status_html)
        world_id = hs["url"]
        connection_url = f"byond://BYOND.world.{world_id}"

        servers.append({
            "connection_url": connection_url,
            "players": hs.get("players", 0),
            "name": name or connection_url,
            "description": description,
            "status": status_html,
            "address": address,
        })

    return servers


def extract_world_id(url):
    match = re.search(r'BYOND\.world\.(\d+)', url)
    return int(match.group(1)) if match else None


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


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
                online BOOLEAN DEFAULT FALSE,
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            ALTER TABLE servers ADD COLUMN IF NOT EXISTS online BOOLEAN DEFAULT FALSE
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS time_dilation_history (
                id SERIAL PRIMARY KEY,
                address TEXT NOT NULL,
                time_dilation_current REAL NOT NULL,
                time_dilation_avg REAL,
                time_dilation_avg_fast REAL,
                time_dilation_avg_slow REAL,
                recorded_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_time_dilation_history_address
            ON time_dilation_history(address)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_time_dilation_history_recorded_at
            ON time_dilation_history(recorded_at)
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS address_cache (
                world_id BIGINT PRIMARY KEY,
                address TEXT NOT NULL,
                cached_at TIMESTAMP DEFAULT NOW()
            )
        """)
    conn.commit()


def mark_all_offline(conn):
    with conn.cursor() as cur:
        cur.execute("UPDATE servers SET online = FALSE")
    conn.commit()


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

            players = server["players"] or 0

            cur.execute("""
                INSERT INTO servers (address, world_id, name, description, status, topic_status, players, online, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, NOW())
                ON CONFLICT (address) DO UPDATE SET
                    world_id = EXCLUDED.world_id,
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    status = EXCLUDED.status,
                    topic_status = EXCLUDED.topic_status,
                    players = COALESCE(EXCLUDED.players, servers.players),
                    online = TRUE,
                    updated_at = NOW()
            """, (address, world_id, server["name"], server["description"], server["status"], Json(topic_status) if topic_status else None, players))

            if players is not None:
                cur.execute("""
                    INSERT INTO player_history (address, players)
                    VALUES (%s, %s)
                """, (address, players))

            if topic_status and "time_dilation_current" in topic_status:
                cur.execute("""
                    INSERT INTO time_dilation_history (address, time_dilation_current, time_dilation_avg, time_dilation_avg_fast, time_dilation_avg_slow)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    address,
                    topic_status.get("time_dilation_current"),
                    topic_status.get("time_dilation_avg"),
                    topic_status.get("time_dilation_avg_fast"),
                    topic_status.get("time_dilation_avg_slow")
                ))

    conn.commit()


def ping_servers(servers, timeout=5):
    import socket
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from byond.topic import queryStatus, send, TOPIC_RESPONSE_STRING

    def parse_topic_result(result):
        if not result or not isinstance(result, dict):
            return result

        keys = list(result.keys())

        if len(keys) == 1 and keys[0].startswith("{"):
            try:
                parsed = json.loads(keys[0])
                if isinstance(parsed, dict) and "data" in parsed:
                    return parsed["data"]
                return parsed
            except json.JSONDecodeError:
                pass

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
    log("Fetching servers from BYOND hub...")

    servers = fetch_servers()
    log(f"Found {len(servers)} servers")

    conn = None
    if DATABASE_URL and not TEST_MODE:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        init_db(conn)

    ping_servers(servers)

    if TEST_MODE:
        print(json.dumps(servers, indent=2))
        return servers

    if not conn:
        log("DATABASE_URL not set, skipping database save")
        return servers

    total_players = sum(s.get("players") or 0 for s in servers)
    if total_players == 0:
        log("All servers reporting 0 players, skipping database save")
        conn.close()
        return servers

    mark_all_offline(conn)
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
