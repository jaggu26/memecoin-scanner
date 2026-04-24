"""
Memecoin Breakout Scanner — Flask Web Server
Port 3000 | Real-time SSE + REST API + Authentication
"""
from flask import Flask, jsonify, send_from_directory, Response, request, redirect
import json, time, threading, os, base64
from datetime import datetime
from queue import Queue, Empty
from functools import wraps
from scanner import BreakoutScanner
from backtest import Backtester

app = Flask(__name__, static_folder="public")

# ── AUTH CONFIG ──────────────────────────────────────────────────────────────
AUTH_USERNAME = os.getenv('AUTH_USERNAME', 'admin')
AUTH_PASSWORD = os.getenv('AUTH_PASSWORD', 'arb123456')

scanner   = BreakoutScanner()
backtester = Backtester()

# ── In-memory state ──────────────────────────────────────────────────────────
state = {
    "scan_results": [],
    "backtest_results": [],
    "backtest_done": False,
    "scan_count": 0,
    "started_at": datetime.now().isoformat(),
    "sse_clients": [],   # Queue objects
}

# ── Background: scan every 30 seconds ────────────────────────────────────────
def scanner_loop():
    while True:
        try:
            results = scanner.scan_once()
            state["scan_results"] = results
            state["scan_count"]  += 1

            # Broadcast to SSE clients
            payload = json.dumps({
                "type": "scan",
                "data": results[:200],
                "scan_count": state["scan_count"],
                "ts": datetime.now().isoformat(),
            })
            for q in state["sse_clients"][:]:
                try:
                    q.put_nowait(payload)
                except Exception:
                    pass
        except Exception as e:
            print(f"[scanner_loop error] {e}")
        time.sleep(30)

# ── Background: run backtest once on startup ──────────────────────────────────
def backtest_loop():
    time.sleep(5)   # Let scanner start first
    print("\n[Backtest] Starting historical verification…")
    results = backtester.run_all(days=180)
    state["backtest_results"] = results
    state["backtest_done"] = True
    print("[Backtest] Done.")

threading.Thread(target=scanner_loop,  daemon=True).start()
threading.Thread(target=backtest_loop, daemon=True).start()

# ── AUTH DECORATOR ──────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check Authorization header first
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        # Fallback to cookie if header not present
        if not token:
            token = request.cookies.get('auth_token', '')

        if not token:
            return redirect('/login.html')

        # Decode token to check format (should be "username:timestamp")
        try:
            decoded_token = base64.b64decode(token).decode()
            if ':' not in decoded_token:
                return redirect('/login.html')
        except:
            return redirect('/login.html')

        return f(*args, **kwargs)
    return decorated_function

# ── LOGIN API ────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if username == AUTH_USERNAME and password == AUTH_PASSWORD:
        token = base64.b64encode(f"{username}:{int(time.time())}".encode()).decode()
        return jsonify({'success': True, 'token': token})

    return jsonify({'error': 'Invalid credentials'}), 401

# ── SERVE LOGIN PAGE ─────────────────────────────────────────────────────────
@app.route("/login.html")
def login_page():
    return send_from_directory("public", "login.html")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return send_from_directory("public", "index.html")

@app.route("/api/scan")
@login_required
def api_scan():
    if not state["scan_results"]:
        results = scanner.scan_once()
        state["scan_results"] = results
    return jsonify({
        "results": state["scan_results"][:200],
        "scan_count": state["scan_count"],
        "ts": datetime.now().isoformat(),
    })

@app.route("/api/search")
@login_required
def api_search():
    q = request.args.get("q", "").strip()
    if not q or len(q) < 1:
        return jsonify({"results": [], "query": q})

    pairs = scanner.search_pairs(q)   # hits DexScreener search directly

    results = []
    seen = set()
    for pair in pairs:
        pid = pair.get("pairAddress", "")
        if pid in seen:
            continue
        seen.add(pid)

        score, signals = scanner.score_pair(pair)
        token_address = pair.get("baseToken", {}).get("address", "")
        chain = pair.get("chainId", "")

        results.append({
            "name":       pair.get("baseToken", {}).get("name", "?"),
            "symbol":     pair.get("baseToken", {}).get("symbol", "?"),
            "chain":      chain or "?",
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
            "is_breakout": score >= scanner.BREAKOUT_MIN_SCORE,
            "is_strong":   score >= scanner.STRONG_BREAKOUT,
            "signals":    signals,
            "token_address": token_address,
            "safety_score": 3,
            "is_safe": None,
            "safety_flags": [],
            "url":        pair.get("url", ""),
            "scanned_at": datetime.now().isoformat(),
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return jsonify({"results": results, "query": q})

@app.route("/api/backtest")
@login_required
def api_backtest():
    return jsonify({
        "done": state["backtest_done"],
        "results": state["backtest_results"],
    })

@app.route("/api/status")
@login_required
def api_status():
    top = [r for r in state["scan_results"] if r.get("is_breakout")]
    return jsonify({
        "total_scanned": len(state["scan_results"]),
        "breakout_count": len(top),
        "scan_count": state["scan_count"],
        "started_at": state["started_at"],
        "backtest_done": state["backtest_done"],
    })

# SSE — real-time stream to browser
@app.route("/api/stream")
@login_required
def api_stream():
    q = Queue()
    state["sse_clients"].append(q)

    # Send current data immediately
    if state["scan_results"]:
        initial = json.dumps({
            "type": "scan",
            "data": state["scan_results"][:200],
            "scan_count": state["scan_count"],
            "ts": datetime.now().isoformat(),
        })
        q.put(initial)

    def generate():
        try:
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield f"data: {msg}\n\n"
                except Empty:
                    yield f"data: {json.dumps({'type':'ping'})}\n\n"
        finally:
            if q in state["sse_clients"]:
                state["sse_clients"].remove(q)

    return Response(generate(),
                    content_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

if __name__ == "__main__":
    port = int(os.getenv('PORT', 3000))
    print("\n🚀 Memecoin Breakout Scanner starting…")
    print(f"   🌐 Dashboard: http://localhost:{port}")
    print(f"   🔐 Login: http://localhost:{port}/login.html")
    print(f"   👤 Username: {AUTH_USERNAME}")
    print("   Scanning every 30s | Backtesting on startup\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)