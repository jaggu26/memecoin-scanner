"""
Memecoin Breakout Scanner — DexScreener API
Scans for high-momentum tokens and scores them 0-10
Includes GoPlus Security API for scam detection

Rate limit fix:
  - Leaky-bucket rate limiter (45 req/min, well under DexScreener's 60/min cap)
  - 20-min pair cache so the same token is never re-fetched every 30s
  - WebSocket listener for real-time boost events (replaces 3 REST polls)
"""
import requests
import time
import json
import threading
from collections import deque
from datetime import datetime

try:
    import websocket as _ws_lib
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False
    print("[Warning] websocket-client not installed; WS discovery disabled")


# ── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Leaky-bucket: allows at most max_per_minute requests per 60-second window."""
    def __init__(self, max_per_minute=45):
        self.max_per_minute = max_per_minute
        self._ts = deque()
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.time()
            cutoff = now - 60.0
            while self._ts and self._ts[0] < cutoff:
                self._ts.popleft()
            if len(self._ts) >= self.max_per_minute:
                wait_sec = 60.0 - (now - self._ts[0]) + 0.05
                if wait_sec > 0:
                    time.sleep(wait_sec)
                now = time.time()
                cutoff = now - 60.0
                while self._ts and self._ts[0] < cutoff:
                    self._ts.popleft()
            self._ts.append(time.time())


# ── Scanner ───────────────────────────────────────────────────────────────────

class BreakoutScanner:
    DEXSCREENER_BASE = "https://api.dexscreener.com"
    GOPLUS_BASE = "https://api.gopluslabs.io/api/v1"

    # Breakout score thresholds
    BREAKOUT_MIN_SCORE = 5   # Score >= 5 → Alert
    STRONG_BREAKOUT    = 7   # Score >= 7 → Strong Alert

    # ── Basic sanity filters (applied at scan time — cannot be toggled off) ────
    MIN_AGE_HOURS    = 1          # Skip tokens younger than 1h
    MIN_MARKET_CAP   = 50_000    # Skip tokens with MC below $50K
    MIN_LIQ_MC_RATIO = 0.005     # Skip if liquidity < 0.5% of market cap (rug risk)

    # ── Strict volume / activity filters — used by frontend toggle & API ──────
    # These values are returned in /api/config so the UI can apply them client-side.
    STRICT_MIN_VOL_5M       = 50_000   # Strict: 5m volume ≥ $50K
    STRICT_MIN_VOL_MC_RATIO = 0.025    # Strict: 5m vol ≥ 2.5% of MC
    STRICT_MIN_TXNS_5M      = 120      # Strict: ≥ 120 txns in 5m
    STRICT_MIN_AVG_TRADE    = 50       # Strict: avg trade ≥ $50
    STRICT_MAX_AVG_TRADE    = 800      # Strict: avg trade ≤ $800

    # ── Pair cache TTL ────────────────────────────────────────────────────────
    PAIR_CACHE_TTL   = 20 * 60  # Re-fetch pair data after 20 minutes

    # Chain ID mapping: DexScreener → GoPlus
    CHAIN_MAP = {
        "ethereum": "1",
        "bsc": "56",
        "polygon": "137",
        "arbitrum": "42161",
        "base": "8453",
        "solana": "solana",
        "avalanche": "43114",
        "fantom": "250",
        "optimism": "10",
    }

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; MemeScanner/1.0)',
            'Accept': 'application/json',
        })
        self.scan_history = []
        self._safety_cache = {}       # token_address → (timestamp, result)
        self._prev_liquidity = {}     # pair_address → liquidity from last scan
        self._pair_cache = {}         # "chain:address" → (timestamp, pairs_list)
        self._rate_limiter = RateLimiter(max_per_minute=45)

        # WebSocket: queue of (chain, tokenAddress) tuples from real-time push
        self._ws_token_queue = deque()
        self._ws_known_addresses = set()  # addresses already enqueued/processed

        if HAS_WEBSOCKET:
            self._start_ws_boost_listener()

    # ── API helpers ──────────────────────────────────────────────────────────

    _USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    ]
    _ua_index = 0

    def _get(self, url, params=None, timeout=20, retries=3):
        for attempt in range(retries):
            self._rate_limiter.wait()   # enforce 45 req/min before every call
            try:
                ua = self._USER_AGENTS[(self._ua_index + attempt) % len(self._USER_AGENTS)]
                headers = {'User-Agent': ua, 'Accept': 'application/json'}
                r = self.session.get(url, params=params, timeout=timeout, headers=headers)
                if r.status_code == 429:
                    wait = 10 + 5 * attempt   # 10s, 15s, 20s on rate-limit hits
                    print(f"  [429 rate-limit] {url[:50]}… waiting {wait}s")
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                self._ua_index = (self._ua_index + 1) % len(self._USER_AGENTS)
                return r.json()
            except Exception as e:
                print(f"  [API error attempt {attempt+1}/{retries}] {url[:60]}… → {e}")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)  # 1s, 2s, 4s backoff
        return None

    # ── WebSocket listener ───────────────────────────────────────────────────

    def _start_ws_boost_listener(self):
        """Background thread: connects to DexScreener WS and pushes new boost tokens into queue."""
        def run():
            while True:
                try:
                    def on_message(ws, message):
                        try:
                            data = json.loads(message)
                            items = data if isinstance(data, list) else data.get("data", [])
                            for item in items:
                                addr  = item.get("tokenAddress", "")
                                chain = item.get("chainId", "")
                                if addr and chain and addr not in self._ws_known_addresses:
                                    self._ws_known_addresses.add(addr)
                                    self._ws_token_queue.append((chain, addr))
                        except Exception:
                            pass

                    def on_error(ws, error):
                        print(f"[WS boost] error: {error}")

                    def on_open(ws):
                        print("[WS boost] Connected to DexScreener real-time boost stream")

                    ws = _ws_lib.WebSocketApp(
                        "wss://api.dexscreener.com/token-boosts/latest/v1",
                        on_message=on_message,
                        on_error=on_error,
                        on_open=on_open,
                    )
                    ws.run_forever(ping_interval=30, ping_timeout=10)
                except Exception as e:
                    print(f"[WS boost] crashed: {e}")
                print("[WS boost] Reconnecting in 10s…")
                time.sleep(10)

        t = threading.Thread(target=run, daemon=True)
        t.start()

    # ── Pair cache ───────────────────────────────────────────────────────────

    def _get_pairs_cached(self, chain, address):
        """Return pairs from cache if fresh, otherwise fetch from REST and cache."""
        key = f"{chain}:{address}"
        entry = self._pair_cache.get(key)
        if entry:
            cached_at, pairs = entry
            if time.time() - cached_at < self.PAIR_CACHE_TTL:
                return pairs
        pairs = self.get_token_pairs(chain, address)
        self._pair_cache[key] = (time.time(), pairs)
        return pairs

    # ── DexScreener REST wrappers ─────────────────────────────────────────────

    def test_connectivity(self):
        results = {}
        endpoints = {
            "boosted": f"{self.DEXSCREENER_BASE}/token-boosts/latest/v1",
            "search":  f"{self.DEXSCREENER_BASE}/latest/dex/search?q=pepe",
        }
        for name, url in endpoints.items():
            try:
                r = self.session.get(url, timeout=15, headers={
                    'User-Agent': self._USER_AGENTS[0],
                    'Accept': 'application/json',
                })
                results[name] = {"status": r.status_code, "ok": r.status_code == 200, "size": len(r.text)}
            except Exception as e:
                results[name] = {"status": 0, "ok": False, "error": str(e)}
        return results

    def get_boosted_tokens(self):
        data = self._get(f"{self.DEXSCREENER_BASE}/token-boosts/latest/v1")
        return data if isinstance(data, list) else []

    def get_token_pairs(self, chain, token_address):
        data = self._get(f"{self.DEXSCREENER_BASE}/token-pairs/v1/{chain}/{token_address}")
        return data if isinstance(data, list) else []

    def search_pairs(self, query):
        data = self._get(f"{self.DEXSCREENER_BASE}/latest/dex/search", params={"q": query})
        return (data or {}).get("pairs", [])

    def search_pairs_fanout(self, name):
        import concurrent.futures
        queries = [
            name,
            f"{name} solana",
            f"{name} ethereum",
            f"{name} bsc",
            f"{name} base",
            f"{name} polygon",
            f"{name} arbitrum",
        ]
        all_pairs = []
        seen = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
            futures = {executor.submit(self.search_pairs, q): q for q in queries}
            for future in concurrent.futures.as_completed(futures):
                try:
                    for p in future.result():
                        pid = p.get("pairAddress", "")
                        if pid and pid not in seen:
                            seen.add(pid)
                            all_pairs.append(p)
                except Exception:
                    pass
        return all_pairs

    def search_by_address(self, token_address):
        pairs = []
        seen = set()
        for p in self.search_pairs(token_address):
            pid = p.get("pairAddress", "")
            if pid and pid not in seen:
                seen.add(pid)
                pairs.append(p)

        import re
        if re.match(r'^0x[0-9a-fA-F]{40}$', token_address):
            for chain in ["ethereum", "bsc", "base", "polygon", "arbitrum", "avalanche", "optimism"]:
                for p in self.get_token_pairs(chain, token_address):
                    pid = p.get("pairAddress", "")
                    if pid and pid not in seen:
                        seen.add(pid)
                        pairs.append(p)
                time.sleep(0.1)
        elif len(token_address) >= 32 and not token_address.startswith("0x"):
            for p in self.get_token_pairs("solana", token_address):
                pid = p.get("pairAddress", "")
                if pid and pid not in seen:
                    seen.add(pid)
                    pairs.append(p)

        return pairs

    # ── Strategy Values ───────────────────────────────────────────────────────

    def compute_strategy_values(self, price_usd, chg_5m, chg_1h, chg_24h, vol_5m, vol_24h):
        entry_price = price_usd
        atr_pct = min(max(abs(chg_24h) / 100.0 * 0.3, 0.10), 0.30)
        atr = atr_pct * entry_price
        stop_loss   = entry_price - 1.5 * atr
        take_profit = entry_price + 2.0 * (entry_price - stop_loss)
        breakout_level = entry_price / (1.0 + chg_5m / 100.0) if chg_5m > 0 else entry_price
        rsi = round(min(95.0, max(15.0, 50.0 + chg_1h * 0.5 + chg_5m * 0.2)), 2)
        avg_5m = vol_24h / 288.0 if vol_24h > 0 else (vol_5m or 1)
        vol_z  = round((vol_5m - avg_5m) / avg_5m, 2) if avg_5m > 0 else 0.0
        return entry_price, stop_loss, take_profit, breakout_level, rsi, vol_z

    # ── Technical Score ───────────────────────────────────────────────────────

    def score_technical(self, pair, rsi_low=55, rsi_high=75, volume_mult=2, atr_mult=1):
        score = 0
        signals = []
        try:
            chg_1h  = float(pair.get("priceChange", {}).get("h1",  0) or 0)
            chg_6h  = float(pair.get("priceChange", {}).get("h6",  0) or 0)
            chg_24h = float(pair.get("priceChange", {}).get("h24", 0) or 0)
            chg_5m  = float(pair.get("priceChange", {}).get("m5",  0) or 0)
            vol_1h  = float(pair.get("volume", {}).get("h1",  0) or 0)
            vol_24h = float(pair.get("volume", {}).get("h24", 0) or 0)

            if chg_1h > 0 and chg_24h > -5:
                score += 2
                signals.append(f"📈 Trend UP: 1h={chg_1h:+.1f}% 24h={chg_24h:+.1f}%")

            approx_rsi = max(0, min(100, 50 + chg_1h * 1.5))
            if rsi_low < approx_rsi < rsi_high:
                score += 2
                signals.append(f"📊 RSI ~{approx_rsi:.0f} (optimal {rsi_low}–{rsi_high})")
            elif approx_rsi >= rsi_high:
                signals.append(f"🔴 RSI ~{approx_rsi:.0f} (overbought)")

            avg_1h_vol = vol_24h / 24 if vol_24h > 0 else 0
            if avg_1h_vol > 0 and vol_1h > volume_mult * avg_1h_vol:
                score += 3
                signals.append(f"🔥 Vol surge: ${vol_1h:,.0f}/1h vs ${avg_1h_vol:,.0f} avg")
            elif avg_1h_vol > 0 and vol_1h > avg_1h_vol:
                score += 1
                signals.append(f"📊 Vol above avg: ${vol_1h:,.0f}/1h")

            if chg_24h > 5 and chg_1h > 0:
                score += 3
                signals.append(f"🚀 Breakout: +{chg_24h:.1f}%/24h momentum")
            elif chg_6h > 3 and chg_1h > 0:
                score += 1
                signals.append(f"↗️ Soft breakout: +{chg_6h:.1f}%/6h")

            atr_proxy = abs(chg_5m)
            if atr_proxy > 5:
                score += 2
                signals.append(f"💥 High ATR: {atr_proxy:.1f}%/5m move")
            elif atr_proxy > 2:
                score += 1
                signals.append(f"⚡ Moderate ATR: {atr_proxy:.1f}%/5m")

        except Exception as e:
            signals.append(f"⚠️ Tech score error: {e}")

        return max(0, score), signals

    # ── Safety Check (GoPlus Security) ───────────────────────────────────────

    def check_token_safety(self, chain, token_address):
        if not token_address or len(token_address) < 10:
            return {"safety_score": 3, "is_safe": None, "safety_flags": [], "top_holder_pct": 0, "is_honeypot": None}

        cache_key = token_address.lower()
        now = time.time()
        if cache_key in self._safety_cache:
            cached_at, cached_result = self._safety_cache[cache_key]
            if now - cached_at < 300:
                return cached_result

        chain_id = self.CHAIN_MAP.get(chain.lower())
        if not chain_id:
            result = {"safety_score": 3, "is_safe": None, "safety_flags": [f"⚠️ Chain '{chain}' not checked"], "top_holder_pct": 0, "is_honeypot": None}
            self._safety_cache[cache_key] = (now, result)
            return result

        try:
            url = f"{self.GOPLUS_BASE}/token_security/{chain_id}"
            response = self.session.get(url, params={"contract_addresses": token_address}, timeout=2)
            response.raise_for_status()
            data = response.json()
            token_data = (data.get("result", {}) or {}).get(token_address.lower(), {})
            safety_score = 5
            safety_flags = []

            is_honeypot = token_data.get("is_honeypot")
            if is_honeypot == "1" or is_honeypot is True:
                safety_score = 0
                safety_flags.append("❌ HONEYPOT DETECTED")

            top_holder_pct = 0
            holder_list = token_data.get("holders", [])
            if holder_list:
                top_holder_pct = float(holder_list[0].get("percentage", 0) or 0) * 100
                if top_holder_pct > 30:
                    safety_score -= 1
                    safety_flags.append(f"⚠️ Top holder: {top_holder_pct:.1f}%")

            lp_holders = token_data.get("lp_holders", [])
            is_locked = any(h.get("percentage", 0) == 100 for h in lp_holders)
            if is_locked:
                safety_score += 1
                safety_flags.append("✅ Liquidity locked")

            owner_can_mint = token_data.get("owner_change_balance")
            if owner_can_mint == "1" or owner_can_mint is True:
                safety_flags.append("⚠️ Owner can mint tokens")
                if safety_score > 0:
                    safety_score -= 1

            result = {
                "safety_score": max(0, min(5, safety_score)),
                "is_safe": safety_score >= 3 if is_honeypot != "1" else False,
                "safety_flags": safety_flags,
                "top_holder_pct": top_holder_pct,
                "is_honeypot": is_honeypot == "1" if is_honeypot else None,
            }
        except Exception as e:
            print(f"  [GoPlus API error] {token_address[:12]}… → {e}")
            result = {"safety_score": 3, "is_safe": None, "safety_flags": ["⚠️ Safety check unavailable"], "top_holder_pct": 0, "is_honeypot": None}

        self._safety_cache[cache_key] = (now, result)
        return result

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score_pair(self, pair, prev_liquidity=None):
        """Hybrid breakout score 0-10."""
        score = 0
        signals = []

        try:
            vol_5m  = float(pair.get("volume", {}).get("m5",  0) or 0)
            vol_1h  = float(pair.get("volume", {}).get("h1",  0) or 0)
            vol_24h = float(pair.get("volume", {}).get("h24", 0) or 0)
            chg_5m  = float(pair.get("priceChange", {}).get("m5",  0) or 0)
            chg_1h  = float(pair.get("priceChange", {}).get("h1",  0) or 0)
            liquidity  = float(pair.get("liquidity", {}).get("usd", 0) or 0)
            market_cap = float(pair.get("marketCap", 0) or pair.get("fdv", 0) or 0)
            txns_5m  = pair.get("txns", {}).get("m5", {})
            buys_5m  = int(txns_5m.get("buys",  0) or 0)
            sells_5m = int(txns_5m.get("sells", 0) or 0)
            total_txns = buys_5m + sells_5m
            created_at = pair.get("pairCreatedAt", 0)
            age_hours  = (time.time() * 1000 - created_at) / 3_600_000 if created_at else 9999

            if buys_5m == 0 and sells_5m == 0:
                signals.append("⛔ No 5m transactions — skip")
                return 0, signals

            if chg_1h <= -15:
                score -= 2; signals.append(f"🔻 1h dump: {chg_1h:.1f}% — avoid")
            if total_txns >= 10 and sells_5m / total_txns >= 0.65:
                score -= 1; signals.append(f"🔴 Sell-dominant: {buys_5m}B/{sells_5m}S")

            avg_5m = (vol_1h / 12) if vol_1h > 0 else (vol_24h / 288 if vol_24h > 0 else 0)
            if avg_5m > 0 and total_txns >= 3:
                vol_ratio = vol_5m / avg_5m
                if vol_ratio >= 4:
                    score += 3; signals.append(f"🔥 Huge vol: {vol_ratio:.1f}x recent avg")
                elif vol_ratio >= 2:
                    score += 2; signals.append(f"📈 Vol spike: {vol_ratio:.1f}x recent avg")
                elif vol_ratio >= 1.2:
                    score += 1; signals.append(f"📊 Vol rising: {vol_ratio:.1f}x recent avg")

            if chg_5m >= 15:
                score += 3; signals.append(f"🚀 Price +{chg_5m:.1f}% in 5m (very strong)")
            elif chg_5m >= 8:
                score += 2; signals.append(f"↗️ Price +{chg_5m:.1f}% in 5m")
            elif chg_5m >= 3:
                score += 1; signals.append(f"📊 Price +{chg_5m:.1f}% in 5m")
            elif chg_5m <= -10:
                score -= 2; signals.append(f"🔻 Price {chg_5m:.1f}% in 5m (avoid)")

            if chg_5m > 0 and chg_1h > 0:
                score += 1; signals.append(f"📈 Both TFs up: 5m={chg_5m:+.1f}% 1h={chg_1h:+.1f}%")
                if chg_5m > chg_1h:
                    score += 1; signals.append(f"⚡ Accelerating: 5m > 1h (momentum building)")

            liq_ratio = liquidity / market_cap if market_cap > 0 else 0
            if liquidity < 5_000:
                score -= 3; signals.append(f"🚨 Near-zero liq: ${liquidity:,.0f} (rug!)")
            elif liq_ratio >= 0.05:
                score += 2; signals.append(f"✅ Liq/MC {liq_ratio*100:.1f}% — ${liquidity:,.0f} (safe)")
            elif liq_ratio >= 0.02:
                score += 1; signals.append(f"⚠️ Liq/MC {liq_ratio*100:.1f}% — ${liquidity:,.0f} (OK)")
            elif liq_ratio < 0.01 and liquidity < 30_000:
                score -= 2; signals.append(f"❌ Liq/MC {liq_ratio*100:.2f}% — rug risk!")

            if prev_liquidity and prev_liquidity > 0 and liquidity > 0:
                drain_pct = (prev_liquidity - liquidity) / prev_liquidity * 100
                if drain_pct >= 30:
                    score -= 3; signals.append(f"🚨 LIQ DRAIN: -{drain_pct:.0f}% since last scan!")
                elif drain_pct >= 15:
                    score -= 1; signals.append(f"⚠️ Liq dropping: -{drain_pct:.0f}% vs last scan")

            if 300_000 <= market_cap <= 5_000_000:
                score += 2; signals.append(f"🎯 MC ${market_cap/1e6:.2f}M (best 10x zone)")
            elif 5_000_000 < market_cap <= 15_000_000:
                score += 1; signals.append(f"🎯 MC ${market_cap/1e6:.2f}M (still has room)")
            elif 150_000 <= market_cap < 300_000:
                score += 1; signals.append(f"🎯 MC ${market_cap:,.0f} (early stage)")
            elif 0 < market_cap < 150_000:
                score -= 2; signals.append(f"⚠️ MC ${market_cap:,.0f} — too small, danger zone")
            elif market_cap > 100_000_000:
                signals.append(f"📦 MC ${market_cap/1e6:.1f}M — too large for big moves")

            if sells_5m == 0 and buys_5m > 0:
                score -= 2; signals.append(f"🚨 No sells: {buys_5m}B/0S (honeypot risk)")
            elif total_txns > 0:
                buy_ratio = buys_5m / total_txns
                if total_txns >= 100 and buy_ratio >= 0.65:
                    score += 2; signals.append(f"💚 Strong buys: {buys_5m}B/{sells_5m}S ({buy_ratio*100:.0f}%)")
                elif total_txns >= 30 and buy_ratio >= 0.55:
                    score += 1; signals.append(f"👍 Buys lead: {buys_5m}B/{sells_5m}S")

            if chg_1h >= 20:
                score += 1; signals.append(f"📈 1h trend: +{chg_1h:.1f}% (confirmed)")

            if 6 <= age_hours <= 48:
                score += 1; signals.append(f"🕐 Prime age: {age_hours:.1f}h old")
            elif age_hours < 1:
                score -= 1; signals.append(f"🆕 Very new: {age_hours*60:.0f}min (unverified)")

        except Exception as e:
            signals.append(f"⚠️ Scoring error: {e}")

        return max(0, min(10, score)), signals

    # ── Collection helpers ────────────────────────────────────────────────────

    def get_top_boosted_tokens(self):
        data = self._get(f"{self.DEXSCREENER_BASE}/token-boosts/top/v1")
        return data if isinstance(data, list) else []

    def get_latest_profiles(self):
        data = self._get(f"{self.DEXSCREENER_BASE}/token-profiles/latest/v1")
        return data if isinstance(data, list) else []

    def _collect_from_token_list(self, token_list, seen, all_pairs, pairs_per_token=3):
        """Fetch pairs for each token, using cache to avoid redundant REST calls."""
        for item in token_list:
            chain   = item.get("chainId", "solana")
            address = item.get("tokenAddress", "")
            if not address:
                continue
            pairs = self._get_pairs_cached(chain, address)
            for p in pairs[:pairs_per_token]:
                pid = p.get("pairAddress", "")
                if pid and pid not in seen:
                    seen.add(pid)
                    all_pairs.append(p)

    # ── Main scan ─────────────────────────────────────────────────────────────

    def scan_once(self):
        """Run one complete scan. Returns list of scored pairs."""
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{ts}] 🔍 Scanning DexScreener…")

        all_pairs = []
        seen = set()

        # 1. Drain WebSocket queue — process up to 15 new tokens per scan
        #    (remaining stay in queue for the next scan cycle)
        ws_new = []
        while self._ws_token_queue and len(ws_new) < 15:
            ws_new.append(self._ws_token_queue.popleft())

        if ws_new:
            print(f"  WS new tokens: {len(ws_new)}")
            self._collect_from_token_list(
                [{"chainId": c, "tokenAddress": a} for c, a in ws_new],
                seen, all_pairs,
            )
        else:
            # Fallback: REST poll if WS not connected yet or nothing new
            latest_boosted = self.get_boosted_tokens()
            print(f"  Latest boosted (REST fallback): {len(latest_boosted)}")
            self._collect_from_token_list(latest_boosted, seen, all_pairs)

            top_boosted = self.get_top_boosted_tokens()
            print(f"  Top boosted: {len(top_boosted)}")
            self._collect_from_token_list(top_boosted, seen, all_pairs)

            profiles = self.get_latest_profiles()
            print(f"  Latest profiles: {len(profiles)}")
            self._collect_from_token_list(profiles, seen, all_pairs)

        # 2. Chain-specific trending — top 3 chains only to limit rate usage
        chain_terms = ["meme", "trending", "new", "pump"]
        for chain in ["solana", "bsc", "base"]:
            for term in chain_terms:
                pairs = self.search_pairs(f"{chain} {term}")
                for p in pairs:
                    pid = p.get("pairAddress", "")
                    if pid and pid not in seen:
                        seen.add(pid)
                        all_pairs.append(p)

        # 3. Core keyword searches — trimmed to highest-signal keywords
        keywords = [
            "pepe", "doge", "cat", "moon", "pump",
            "wif", "bonk", "inu", "shib", "floki",
            "wojak", "chad", "ape", "frog", "goat",
        ]
        for kw in keywords:
            pairs = self.search_pairs(kw)
            for p in pairs:
                pid = p.get("pairAddress", "")
                if pid and pid not in seen:
                    seen.add(pid)
                    all_pairs.append(p)

        print(f"  Total pairs collected: {len(all_pairs)}")

        # ── Apply basic sanity filters (age, MC, liq/MC only) ───────────────
        # Strict vol/txns filtering is done client-side via the UI "Vol Filter" toggle.
        filtered = []
        for pair in all_pairs:
            liq = float(pair.get("liquidity", {}).get("usd", 0) or 0)
            mc  = float(pair.get("marketCap", 0) or pair.get("fdv", 0) or 0)
            ca  = pair.get("pairCreatedAt", 0)
            age = (time.time() * 1000 - ca) / 3_600_000 if ca else 0
            liq_mc = liq / mc if mc > 0 else 0

            if age    < self.MIN_AGE_HOURS:    continue
            if mc     < self.MIN_MARKET_CAP:   continue
            if liq_mc < self.MIN_LIQ_MC_RATIO: continue
            filtered.append(pair)

        print(f"  After basic filter: {len(filtered)} / {len(all_pairs)} passed")
        all_pairs = filtered

        # Score every pair
        results = []
        new_liquidity_map = {}
        for pair in all_pairs:
            pair_addr = pair.get("pairAddress", "")
            prev_liq  = self._prev_liquidity.get(pair_addr)
            breakout_score, breakout_signals = self.score_pair(pair, prev_liquidity=prev_liq)
            cur_liq = float(pair.get("liquidity", {}).get("usd", 0) or 0)
            if pair_addr:
                new_liquidity_map[pair_addr] = cur_liq

            token_address = pair.get("baseToken", {}).get("address", "")
            chain = pair.get("chainId", "")
            price  = float(pair.get("priceUsd", 0) or 0)
            c5m    = float(pair.get("priceChange", {}).get("m5",  0) or 0)
            c1h    = float(pair.get("priceChange", {}).get("h1",  0) or 0)
            c24h   = float(pair.get("priceChange", {}).get("h24", 0) or 0)
            v5m    = float(pair.get("volume", {}).get("m5",  0) or 0)
            v24h   = float(pair.get("volume", {}).get("h24", 0) or 0)
            entry, sl, tp, bl, rsi, vol_z = self.compute_strategy_values(price, c5m, c1h, c24h, v5m, v24h)

            if breakout_score >= 4:
                safety_info = self.check_token_safety(chain, token_address)
            else:
                safety_info = {"safety_score": 3, "is_safe": None, "safety_flags": [], "top_holder_pct": 0}

            created_at = pair.get("pairCreatedAt", 0)
            age_hours  = (time.time() * 1000 - created_at) / 3_600_000 if created_at else 0
            txns_h24   = pair.get("txns", {}).get("h24", {})
            txns_24h   = int(txns_h24.get("buys", 0) or 0) + int(txns_h24.get("sells", 0) or 0)
            makers     = int(pair.get("makers", 0) or 0)
            buys_5m_n  = int(pair.get("txns", {}).get("m5", {}).get("buys",  0) or 0)
            sells_5m_n = int(pair.get("txns", {}).get("m5", {}).get("sells", 0) or 0)
            total_5m_n = buys_5m_n + sells_5m_n
            buy_ratio_pct = round(buys_5m_n / total_5m_n * 100, 1) if total_5m_n > 0 else 0

            results.append({
                "name":           pair.get("baseToken", {}).get("name", "?"),
                "symbol":         pair.get("baseToken", {}).get("symbol", "?"),
                "chain":          pair.get("chainId", "?"),
                "dex":            pair.get("dexId", "?"),
                "price_usd":      price,
                "chg_5m":         c5m,
                "chg_1h":         c1h,
                "chg_24h":        c24h,
                "vol_5m":         v5m,
                "vol_24h":        v24h,
                "liquidity":      float(pair.get("liquidity", {}).get("usd", 0) or 0),
                "market_cap":     float(pair.get("marketCap", 0) or pair.get("fdv", 0) or 0),
                "buys_5m":        buys_5m_n,
                "sells_5m":       sells_5m_n,
                "buy_ratio_pct":  buy_ratio_pct,
                "age_hours":      round(age_hours, 1),
                "txns_24h":       txns_24h,
                "makers":         makers,
                "score":          breakout_score,
                "is_breakout":    breakout_score >= self.BREAKOUT_MIN_SCORE,
                "is_strong":      breakout_score >= self.STRONG_BREAKOUT,
                "signals":        breakout_signals,
                "entry_price":    entry,
                "stop_loss":      sl,
                "take_profit":    tp,
                "breakout_level": bl,
                "rsi":            rsi,
                "vol_z":          vol_z,
                "pair_address":   pair.get("pairAddress", ""),
                "token_address":  token_address,
                "safety_score":   safety_info.get("safety_score", 3),
                "is_safe":        safety_info.get("is_safe"),
                "safety_flags":   safety_info.get("safety_flags", []),
                "url":            pair.get("url", ""),
                "scanned_at":     datetime.now().isoformat(),
            })

        self._prev_liquidity.update(new_liquidity_map)
        results.sort(key=lambda x: x["score"], reverse=True)

        top = [r for r in results if r["is_breakout"]]
        print(f"  🎯 Breakout alerts: {len(top)} / {len(results)}")
        for r in top[:5]:
            tag = "🔥 STRONG" if r["is_strong"] else "🎯 BREAKOUT"
            print(f"  {tag} [{r['score']}/10] {r['symbol']} ({r['chain']}) | "
                  f"+{r['chg_5m']:.1f}%/5m | ${r['liquidity']:,.0f} liq | MC ${r['market_cap']:,.0f}")

        self.scan_history = (results + self.scan_history)[:200]
        return results