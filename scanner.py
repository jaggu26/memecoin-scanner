"""
Memecoin Breakout Scanner — DexScreener API
Scans for high-momentum tokens and scores them 0-10
Includes GoPlus Security API for scam detection
"""
import requests
import time
from datetime import datetime


class BreakoutScanner:
    DEXSCREENER_BASE = "https://api.dexscreener.com"
    GOPLUS_BASE = "https://api.gopluslabs.io/api/v1"

    # Breakout score thresholds
    BREAKOUT_MIN_SCORE = 5   # Score >= 5 → Alert
    STRONG_BREAKOUT    = 7   # Score >= 7 → Strong Alert

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
        self.scan_history = []   # last 200 results
        self._safety_cache = {}  # token_address → (timestamp, result)

    # ── API helpers ──────────────────────────────────────────────────────────

    def _get(self, url, params=None, timeout=10):
        try:
            r = self.session.get(url, params=params, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"  [API error] {url[:60]}… → {e}")
            return None

    def get_boosted_tokens(self):
        data = self._get(f"{self.DEXSCREENER_BASE}/token-boosts/latest/v1")
        return data if isinstance(data, list) else []

    def get_token_pairs(self, chain, token_address):
        data = self._get(f"{self.DEXSCREENER_BASE}/token-pairs/v1/{chain}/{token_address}")
        return data if isinstance(data, list) else []

    def search_pairs(self, query):
        data = self._get(f"{self.DEXSCREENER_BASE}/latest/dex/search", params={"q": query})
        return (data or {}).get("pairs", [])

    # ── Safety Check (GoPlus Security) ──────────────────────────────────────

    def check_token_safety(self, chain, token_address):
        """Check token security via GoPlus API. Returns safety dict."""
        if not token_address or len(token_address) < 10:
            return {
                "safety_score": 3,
                "is_safe": None,
                "safety_flags": [],
                "top_holder_pct": 0,
                "is_honeypot": None,
            }

        cache_key = token_address.lower()
        now = time.time()

        # Check cache (5 min TTL)
        if cache_key in self._safety_cache:
            cached_at, cached_result = self._safety_cache[cache_key]
            if now - cached_at < 300:
                return cached_result

        chain_id = self.CHAIN_MAP.get(chain.lower())
        if not chain_id:
            result = {
                "safety_score": 3,
                "is_safe": None,
                "safety_flags": [f"⚠️ Chain '{chain}' not checked"],
                "top_holder_pct": 0,
                "is_honeypot": None,
            }
            self._safety_cache[cache_key] = (now, result)
            return result

        # Call GoPlus API (2 sec timeout)
        try:
            url = f"{self.GOPLUS_BASE}/token_security/{chain_id}"
            response = self.session.get(
                url,
                params={"contract_addresses": token_address},
                timeout=2,
            )
            response.raise_for_status()
            data = response.json()

            # Parse result
            token_data = (data.get("result", {}) or {}).get(token_address.lower(), {})
            safety_score = 5
            safety_flags = []

            # Check 1: Honeypot
            is_honeypot = token_data.get("is_honeypot")
            if is_honeypot == "1" or is_honeypot is True:
                safety_score = 0
                safety_flags.append("❌ HONEYPOT DETECTED")

            # Check 2: Top holder %
            top_holder_pct = 0
            holder_list = token_data.get("holders", [])
            if holder_list and len(holder_list) > 0:
                top_holder_pct = float(holder_list[0].get("percentage", 0) or 0) * 100
                if top_holder_pct > 30:
                    safety_score -= 1
                    safety_flags.append(f"⚠️ Top holder: {top_holder_pct:.1f}%")

            # Check 3: Liquidity locked
            lp_holders = token_data.get("lp_holders", [])
            is_locked = any(h.get("percentage", 0) == 100 for h in lp_holders)
            if is_locked:
                safety_score += 1
                safety_flags.append("✅ Liquidity locked")

            # Check 4: Owner can mint
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
            result = {
                "safety_score": 3,
                "is_safe": None,
                "safety_flags": ["⚠️ Safety check unavailable"],
                "top_holder_pct": 0,
                "is_honeypot": None,
            }

        self._safety_cache[cache_key] = (now, result)
        return result

    # ── Scoring ──────────────────────────────────────────────────────────────

    def score_pair(self, pair):
        """Score a DexScreener pair from 0-10. Returns (score, signals[])."""
        score = 0
        signals = []

        try:
            # ── Pull raw fields ─────────────────────────────────────────────
            vol_5m  = float(pair.get("volume", {}).get("m5",  0) or 0)
            vol_1h  = float(pair.get("volume", {}).get("h1",  0) or 0)
            vol_24h = float(pair.get("volume", {}).get("h24", 0) or 0)

            chg_5m  = float(pair.get("priceChange", {}).get("m5",  0) or 0)
            chg_1h  = float(pair.get("priceChange", {}).get("h1",  0) or 0)

            liquidity  = float(pair.get("liquidity", {}).get("usd", 0) or 0)
            market_cap = float(pair.get("marketCap", 0) or pair.get("fdv", 0) or 0)

            txns_5m = pair.get("txns", {}).get("m5", {})
            buys_5m = int(txns_5m.get("buys",  0) or 0)
            sells_5m= int(txns_5m.get("sells", 0) or 0)

            created_at = pair.get("pairCreatedAt", 0)
            age_hours  = (time.time() * 1000 - created_at) / 3_600_000 if created_at else 9999

            # ── Signal 1: Volume spike ──────────────────────────────────────
            # 5m volume > 3% of 24h = extremely active right now
            if vol_24h > 0:
                vol_ratio = vol_5m / vol_24h * 100
                if vol_ratio >= 5:
                    score += 3; signals.append(f"🔥 Huge vol spike: {vol_ratio:.1f}% of 24h in 5m")
                elif vol_ratio >= 3:
                    score += 2; signals.append(f"📈 Vol spike: {vol_ratio:.1f}% of 24h in 5m")
                elif vol_ratio >= 1.5:
                    score += 1; signals.append(f"📊 Vol rising: {vol_ratio:.1f}% of 24h in 5m")

            # ── Signal 2: Price momentum (5m) ───────────────────────────────
            if chg_5m >= 15:
                score += 3; signals.append(f"🚀 Price +{chg_5m:.1f}% in 5m (very strong)")
            elif chg_5m >= 8:
                score += 2; signals.append(f"↗️ Price +{chg_5m:.1f}% in 5m")
            elif chg_5m >= 3:
                score += 1; signals.append(f"📊 Price +{chg_5m:.1f}% in 5m")
            elif chg_5m <= -10:
                score -= 2; signals.append(f"🔻 Price {chg_5m:.1f}% in 5m (avoid)")

            # ── Signal 3: Liquidity (safety) ────────────────────────────────
            if liquidity >= 100_000:
                score += 2; signals.append(f"✅ Liquidity: ${liquidity:,.0f} (safe)")
            elif liquidity >= 30_000:
                score += 1; signals.append(f"⚠️ Liquidity: ${liquidity:,.0f} (OK)")
            elif liquidity < 10_000:
                score -= 2; signals.append(f"❌ Low liquidity: ${liquidity:,.0f} (rug risk!)")

            # ── Signal 4: Market cap sweet spot ─────────────────────────────
            if 200_000 <= market_cap <= 10_000_000:
                score += 2; signals.append(f"🎯 MC ${market_cap/1e6:.2f}M (10x potential)")
            elif 50_000 <= market_cap < 200_000:
                score += 1; signals.append(f"🎯 MC ${market_cap:,.0f} (early, risky)")
            elif market_cap > 100_000_000:
                signals.append(f"📦 MC too large: ${market_cap/1e6:.1f}M (less upside)")

            # ── Signal 5: Buy pressure & honeypot detection ──────────────────
            total_txns = buys_5m + sells_5m
            if sells_5m == 0 and buys_5m > 0:
                score -= 2; signals.append(f"🚨 No sells detected: {buys_5m}B/0S (honeypot risk)")
            elif total_txns > 0:
                buy_ratio = buys_5m / total_txns
                if total_txns >= 100 and buy_ratio >= 0.65:
                    score += 2; signals.append(f"💚 Strong buy pressure {buys_5m}B/{sells_5m}S ({buy_ratio*100:.0f}% buys)")
                elif total_txns >= 30 and buy_ratio >= 0.55:
                    score += 1; signals.append(f"👍 Buys dominant: {buys_5m}B/{sells_5m}S")

            # ── Signal 6: 1h momentum confirms 5m ──────────────────────────
            if chg_1h >= 20:
                score += 1; signals.append(f"📈 1h trend: +{chg_1h:.1f}% (confirmed)")

            # ── Bonus: Fresh token (not too old, not too new) ───────────────
            if 2 <= age_hours <= 48:
                score += 1; signals.append(f"🕐 Fresh: {age_hours:.1f}h old")
            elif age_hours < 1:
                score -= 1; signals.append(f"🆕 Very new: {age_hours*60:.0f}min (unverified)")

        except Exception as e:
            signals.append(f"⚠️ Scoring error: {e}")

        return max(0, min(10, score)), signals

    # ── Main scan ────────────────────────────────────────────────────────────

    def scan_once(self):
        """Run one complete scan. Returns list of scored pairs."""
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{ts}] 🔍 Scanning DexScreener…")

        all_pairs = []
        seen = set()

        # 1. Boosted/trending tokens → fetch their pairs
        boosted = self.get_boosted_tokens()
        print(f"  Boosted tokens: {len(boosted)}")
        for item in boosted[:20]:   # cap to avoid rate-limit
            chain   = item.get("chainId", "solana")
            address = item.get("tokenAddress", "")
            if not address:
                continue
            pairs = self.get_token_pairs(chain, address)
            for p in pairs[:2]:   # top 2 pairs per token
                pid = p.get("pairAddress", "")
                if pid and pid not in seen:
                    seen.add(pid)
                    all_pairs.append(p)
            time.sleep(0.15)      # be polite to API

        # 2. Keyword searches for breakout memecoins
        keywords = ["pepe", "doge", "cat", "ai", "moon", "pump", "wif", "bonk", "pippin", "river", "inx"]
        for kw in keywords:
            pairs = self.search_pairs(kw)
            for p in pairs[:5]:
                pid = p.get("pairAddress", "")
                if pid and pid not in seen:
                    seen.add(pid)
                    all_pairs.append(p)
            time.sleep(0.2)

        print(f"  Total pairs collected: {len(all_pairs)}")

        # Score every pair
        results = []
        for pair in all_pairs:
            score, signals = self.score_pair(pair)

            # Get token safety info for promising tokens
            token_address = pair.get("baseToken", {}).get("address", "")
            chain = pair.get("chainId", "")
            safety_info = {}
            if score >= 4:  # Only check safety for tokens scoring >= 4
                safety_info = self.check_token_safety(chain, token_address)
            else:
                safety_info = {
                    "safety_score": 3,
                    "is_safe": None,
                    "safety_flags": [],
                    "top_holder_pct": 0,
                }

            results.append({
                "name":       pair.get("baseToken", {}).get("name", "?"),
                "symbol":     pair.get("baseToken", {}).get("symbol", "?"),
                "chain":      pair.get("chainId", "?"),
                "dex":        pair.get("dexId", "?"),
                "price_usd":  float(pair.get("priceUsd", 0) or 0),
                "chg_5m":     float(pair.get("priceChange", {}).get("m5",  0) or 0),
                "chg_1h":     float(pair.get("priceChange", {}).get("h1",  0) or 0),
                "chg_24h":    float(pair.get("priceChange", {}).get("h24", 0) or 0),
                "vol_5m":     float(pair.get("volume", {}).get("m5",  0) or 0),
                "vol_24h":    float(pair.get("volume", {}).get("h24", 0) or 0),
                "liquidity":  float(pair.get("liquidity", {}).get("usd", 0) or 0),
                "market_cap": float(pair.get("marketCap", 0) or pair.get("fdv", 0) or 0),
                "buys_5m":    int(pair.get("txns", {}).get("m5", {}).get("buys", 0) or 0),
                "sells_5m":   int(pair.get("txns", {}).get("m5", {}).get("sells", 0) or 0),
                "score":      score,
                "is_breakout": score >= self.BREAKOUT_MIN_SCORE,
                "is_strong":   score >= self.STRONG_BREAKOUT,
                "signals":    signals,
                "token_address": token_address,
                "safety_score": safety_info.get("safety_score", 3),
                "is_safe":    safety_info.get("is_safe"),
                "safety_flags": safety_info.get("safety_flags", []),
                "url":        pair.get("url", ""),
                "scanned_at": datetime.now().isoformat(),
            })

        results.sort(key=lambda x: x["score"], reverse=True)

        # Show top results
        top = [r for r in results if r["is_breakout"]]
        print(f"  🎯 Breakout alerts: {len(top)} / {len(results)}")
        for r in top[:5]:
            tag = "🔥 STRONG" if r["is_strong"] else "🎯 BREAKOUT"
            print(f"  {tag} [{r['score']}/10] {r['symbol']} ({r['chain']}) | "
                  f"+{r['chg_5m']:.1f}%/5m | ${r['liquidity']:,.0f} liq | MC ${r['market_cap']:,.0f}")

        self.scan_history = (results + self.scan_history)[:200]
        return results