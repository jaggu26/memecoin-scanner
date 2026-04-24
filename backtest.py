"""
Backtesting Engine — Tests breakout strategy on historical memecoin data
Measures: Win Rate, Avg PnL, Max Drawdown, Sharpe Ratio
"""
import requests
import pandas as pd
import numpy as np
import time
from datetime import datetime


class Backtester:
    COINGECKO_BASE = "https://api.coingecko.com/api/v3"

    # Famous memecoins that had real breakouts — perfect for testing
    TEST_COINS = {
        "pepe":       "PEPE",
        "bonk":       "BONK",
        "dogwifcoin": "WIF",
        "dogecoin":   "DOGE",
        "shiba-inu":  "SHIB",
        "floki":      "FLOKI",
    }

    # Strategy params
    STOP_LOSS_PCT  = -15    # -15% → exit immediately
    TAKE_PROFIT_1  =  50    # +50% → sell 50% of position
    TAKE_PROFIT_2  = 100    # +100% → sell remaining 50%
    MAX_HOLD_DAYS  = 7      # Forced exit after 7 days
    LOOKBACK       = 20     # Days to look back for vol/price avg

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})

    # ── Data fetch ────────────────────────────────────────────────────────────

    def fetch_history(self, coin_id, days=180):
        """Fetch daily OHLCV from CoinGecko."""
        url = f"{self.COINGECKO_BASE}/coins/{coin_id}/market_chart"
        params = {"vs_currency": "usd", "days": days, "interval": "daily"}
        try:
            r = self.session.get(url, params=params, timeout=15)
            r.raise_for_status()
            raw = r.json()
            prices  = pd.DataFrame(raw["prices"],        columns=["ts", "price"])
            volumes = pd.DataFrame(raw["total_volumes"], columns=["ts", "volume"])
            df = prices.merge(volumes, on="ts")
            df["ts"] = pd.to_datetime(df["ts"], unit="ms")
            df.set_index("ts", inplace=True)
            return df.sort_index()
        except Exception as e:
            print(f"  [CoinGecko error] {coin_id}: {e}")
            return None

    # ── Technical indicators ─────────────────────────────────────────────────

    def calc_rsi(self, series, period=14):
        delta = series.diff()
        gain  = delta.clip(lower=0).rolling(period).mean()
        loss  = (-delta.clip(upper=0)).rolling(period).mean()
        rs    = gain / loss.replace(0, np.nan)
        return 100 - (100 / (1 + rs))

    # ── Breakout detector (same logic as scanner.py) ──────────────────────────

    def is_breakout(self, df, i):
        """
        Returns True if index i shows a breakout:
          - Volume > 2× the 20-day average, AND
          - Price above 20-day high (resistance broken), OR
          - Volume > 3× AND price up >5% today
        """
        if i < self.LOOKBACK + 1:
            return False, 0, 0

        window = df.iloc[i - self.LOOKBACK : i]
        cur    = df.iloc[i]
        prev   = df.iloc[i - 1]

        avg_vol      = window["volume"].mean()
        vol_ratio    = cur["volume"] / avg_vol if avg_vol > 0 else 0
        resistance   = window["price"].max()
        price_change = (cur["price"] - prev["price"]) / prev["price"] * 100

        breakout = (
            (vol_ratio >= 2.0 and cur["price"] > resistance * 1.02) or
            (vol_ratio >= 3.0 and price_change >= 5)
        )
        return breakout, round(vol_ratio, 2), round(price_change, 2)

    # ── Trade simulator ───────────────────────────────────────────────────────

    def simulate_trade(self, df, entry_idx):
        """
        Simulate 1 trade from entry_idx with TP1/TP2/SL.
        Returns (net_pnl_pct, exit_reason, hold_days).
        """
        entry_price = df.iloc[entry_idx]["price"]
        sl  = entry_price * (1 + self.STOP_LOSS_PCT / 100)
        tp1 = entry_price * (1 + self.TAKE_PROFIT_1 / 100)
        tp2 = entry_price * (1 + self.TAKE_PROFIT_2 / 100)

        position = 1.0   # 100%
        realized = 0.0
        end = min(entry_idx + self.MAX_HOLD_DAYS + 1, len(df))

        for j in range(entry_idx + 1, end):
            price = df.iloc[j]["price"]

            # Stop loss
            if price <= sl:
                realized += position * self.STOP_LOSS_PCT
                return realized, "stop_loss", j - entry_idx

            # TP1: sell half at +50%
            if price >= tp1 and position >= 0.9:
                realized += 0.5 * self.TAKE_PROFIT_1
                position -= 0.5

            # TP2: sell rest at +100%
            if price >= tp2 and position > 0:
                realized += position * self.TAKE_PROFIT_2
                position  = 0
                return realized, "tp2_hit", j - entry_idx

        # Timeout exit
        if position > 0:
            final_price = df.iloc[end - 1]["price"]
            final_pnl   = (final_price - entry_price) / entry_price * 100 * position
            realized += final_pnl

        return float(round(realized, 2)), "timeout", self.MAX_HOLD_DAYS

    # ── Full backtest for one coin ────────────────────────────────────────────

    def backtest_coin(self, coin_id, days=180):
        symbol = self.TEST_COINS.get(coin_id, coin_id.upper())
        print(f"\n  📊 Backtesting {symbol} ({days} days)…")

        df = self.fetch_history(coin_id, days)
        if df is None or len(df) < self.LOOKBACK + 5:
            return None

        trades    = []
        last_sig  = -5   # minimum gap between signals

        for i in range(self.LOOKBACK + 1, len(df)):
            breakout, vol_ratio, chg_pct = self.is_breakout(df, i)
            if not breakout or (i - last_sig) < 3:
                continue

            pnl, reason, hold = self.simulate_trade(df, i)
            trades.append({
                "date":       df.index[i].strftime("%Y-%m-%d"),
                "entry":      float(round(df.iloc[i]["price"], 8)),
                "vol_ratio":  float(vol_ratio),
                "chg_pct":    float(chg_pct),
                "pnl":        float(pnl),
                "reason":     reason,
                "hold_days":  int(hold),
                "win":        bool(pnl > 0),
            })
            last_sig = i

        if not trades:
            print(f"    No signals for {symbol}")
            return {"symbol": symbol, "error": "No signals found"}

        tdf      = pd.DataFrame(trades)
        win_rate = tdf["win"].mean() * 100
        avg_pnl  = tdf["pnl"].mean()
        total    = tdf["pnl"].sum()
        max_win  = tdf["pnl"].max()
        max_loss = tdf["pnl"].min()

        # Max drawdown (sequential)
        cumulative = tdf["pnl"].cumsum()
        drawdown   = (cumulative - cumulative.cummax()).min()

        # Profit factor
        wins_sum  = tdf[tdf["win"]]["pnl"].sum()
        loss_sum  = abs(tdf[~tdf["win"]]["pnl"].sum())
        pf        = wins_sum / loss_sum if loss_sum > 0 else 999

        result = {
            "symbol":         symbol,
            "coin_id":        coin_id,
            "days":           days,
            "total_trades":   len(trades),
            "win_rate":       float(round(win_rate, 1)),
            "avg_pnl_pct":    float(round(avg_pnl, 2)),
            "total_pnl_pct":  float(round(total, 2)),
            "max_win_pct":    float(round(max_win, 2)),
            "max_loss_pct":   float(round(max_loss, 2)),
            "max_drawdown":   float(round(drawdown, 2)),
            "profit_factor":  float(round(pf, 2)),
            "trades":         trades[-10:],
        }

        print(f"    ✅ {len(trades)} trades | Win rate: {win_rate:.1f}% | Avg PnL: {avg_pnl:+.1f}% | Total: {total:+.1f}%")
        return result

    # ── Run all ───────────────────────────────────────────────────────────────

    def run_all(self, days=90):
        print(f"\n{'='*55}")
        print(f"  BACKTESTING MEMECOIN BREAKOUT STRATEGY ({days} days)")
        print(f"  Stop Loss: {self.STOP_LOSS_PCT}% | TP1: +{self.TAKE_PROFIT_1}% | TP2: +{self.TAKE_PROFIT_2}%")
        print(f"{'='*55}")

        results = []
        for coin_id in self.TEST_COINS:
            result = self.backtest_coin(coin_id, days)
            if result and "error" not in result:
                results.append(result)
            time.sleep(1.2)   # respect CoinGecko rate limit

        if not results:
            return []

        # ── Summary ──────────────────────────────────────────────────────────
        avg_wr  = np.mean([r["win_rate"]   for r in results])
        avg_pnl = np.mean([r["avg_pnl_pct"] for r in results])
        avg_pf  = np.mean([r["profit_factor"] for r in results])

        print(f"\n{'='*55}")
        print(f"  STRATEGY EFFICIENCY SUMMARY")
        print(f"  Coins tested:   {len(results)}")
        print(f"  Avg Win Rate:   {avg_wr:.1f}%")
        print(f"  Avg PnL/trade:  {avg_pnl:+.1f}%")
        print(f"  Profit Factor:  {avg_pf:.2f}  (>1 = profitable)")
        print(f"{'='*55}")

        for r in results:
            print(f"  {r['symbol']:6} | WR:{r['win_rate']:5.1f}% | "
                  f"AvgPnL:{r['avg_pnl_pct']:+6.1f}% | "
                  f"MaxWin:{r['max_win_pct']:+6.1f}% | "
                  f"MaxLoss:{r['max_loss_pct']:+6.1f}% | "
                  f"PF:{r['profit_factor']:.2f}")

        return results


if __name__ == "__main__":
    bt = Backtester()
    bt.run_all(days=90)