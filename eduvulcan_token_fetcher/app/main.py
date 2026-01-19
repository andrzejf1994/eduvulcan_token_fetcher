#!/usr/bin/env python3
import asyncio
import json
import os
import base64
import logging
import argparse
import time
from datetime import datetime, timezone
from typing import Optional
import urllib.request

from playwright.async_api import async_playwright

LOGGER = logging.getLogger("eduvulcan_token_fetcher")

# Ścieżki w HA
# Zawiera docelową lokalizację zapisu/odczytu tokena w środowisku Home Assistant
TOKEN_FILE = "/config/eduvulcan_token.json"
# Zawiera lokalizację zapisu stanu przeglądarki (cookies, localStorage) dla ponownych logowań
STORAGE_FILE = "/data/eduvulcan_storage.json"

# Startujemy ZAWSZE od /api/ap
# Ten endpoint zwraca lub przekierowuje do logowania i umożliwia pobranie tokena
EDUVULCAN_URL = "https://eduvulcan.pl/api/ap"

# Zapas przed wygaśnięciem JWT (sekundy)
# Dzięki temu odświeżenie następuje przed wygaśnięciem tokena i minimalizuje przerwy
REFRESH_MARGIN = 300  # 5 minut

# Limit nieudanych prób odświeżenia
# Po przekroczeniu wysyłamy powiadomienie i kończymy pętlę watchdog
MAX_FAILURES = 5

# Interwał przy błędzie (sekundy)
# Wydłuża przerwę po błędzie, aby nie obciążać serwisu powtarzalnymi próbami
FAIL_SLEEP = 300  # 5 minut


# Dekoduje payload JWT bez weryfikacji podpisu
# Wejście: jwt (str) w formacie header.payload.signature
# Wyjście: słownik z danymi payload
# Założenia/skutki: brak walidacji podpisu, używane tylko do odczytu exp/tenant
def decode_jwt_payload(jwt: str) -> dict:
    payload = jwt.split(".")[1]  # Wydziel część payload z JWT
    payload += "=" * (-len(payload) % 4)  # Uzupełnij padding Base64 URL-safe
    decoded = base64.urlsafe_b64decode(payload)  # Dekoduj JSON payload
    return json.loads(decoded)


# Wczytuje zapisany token z pliku konfiguracyjnego
# Wejście: brak (ścieżka stała TOKEN_FILE)
# Wyjście: dict z tokenem lub None gdy brak/odczyt nieudany
# Założenia/skutki: loguje ostrzeżenie przy błędzie IO/JSON
def read_saved_token() -> Optional[dict]:
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        LOGGER.warning("Failed to read token file: %s", exc)
        return None


# Sprawdza ważność tokena na podstawie pola exp w payload
# Wejście: token_data (dict) z kluczem jwt_payload
# Wyjście: krotka (is_valid, exp_ts, seconds_left)
# Założenia/skutki: przy błędnym formacie zwraca wartości zerowe
def token_validity(token_data: dict):
    """
    Zwraca: (is_valid: bool, exp_ts: int, seconds_left: int)
    """
    try:
        payload = token_data["jwt_payload"]
        exp = int(payload["exp"])
        now = int(time.time())
        seconds_left = exp - now  # Różnica czasu do wygaśnięcia w sekundach
        return seconds_left > REFRESH_MARGIN, exp, seconds_left
    except Exception:
        return False, 0, 0


# Wysyła powiadomienie persistent_notification przez Supervisor API
# Wejście: tytuł i treść wiadomości
# Wyjście: None (loguje status)
# Założenia/skutki: wymaga SUPERVISOR_TOKEN w środowisku
def send_persistent_notification(title: str, message: str) -> None:
    """
    Wysyła persistent notification do Home Assistant przez Supervisor API.
    Nie wymaga tokena użytkownika ani aiohttp.
    """
    supervisor_token = os.getenv("SUPERVISOR_TOKEN")
    if not supervisor_token:
        LOGGER.error("SUPERVISOR_TOKEN not found in environment; cannot send notification")
        return

    url = "http://supervisor/core/api/services/persistent_notification/create"
    payload = {
        "title": title,
        "message": message,
    }

    data = json.dumps(payload).encode("utf-8")  # Serializuj payload do JSON
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {supervisor_token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # Wywołanie REST do Supervisor API
            LOGGER.info("Persistent notification sent via Supervisor API (status %s)", resp.status)
    except Exception as exc:
        LOGGER.error("Failed to send persistent notification: %s", exc)


# Pobiera nowy token JWT przez automatyzację logowania w Playwright
# Wejście: login i password (str)
# Wyjście: None (zapisuje token i stan sesji na dysk)
# Założenia/skutki: zapisuje pliki TOKEN_FILE i STORAGE_FILE
async def fetch_new_token(login: str, password: str):
    LOGGER.info("Launching Playwright (headless Chromium)")

    async with async_playwright() as p:
        # Uruchom przeglądarkę w trybie headless z flagami kompatybilnymi z kontenerem
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )

        # Wczytaj cookies / sesję jeśli istnieją
        if os.path.exists(STORAGE_FILE):
            LOGGER.info("Loading stored cookies/session")
            context = await browser.new_context(storage_state=STORAGE_FILE)
        else:
            context = await browser.new_context()

        page = await context.new_page()

        try:
            # 1) Idziemy na /api/ap (backend przekieruje na /logowanie jeśli trzeba)
            LOGGER.info("Opening: %s", EDUVULCAN_URL)
            await page.goto(EDUVULCAN_URL, wait_until="networkidle")
            await remove_privacy_overlay(page)

            # Usuń overlay cookies (jeśli jest)
            await page.evaluate("""
                const el = document.getElementById("respect-privacy-wrapper");
                if (el) el.remove();
            """)

            # 2) Sprawdź czy sesja już aktywna (czy istnieje #ap)
            try:
                await page.wait_for_selector("#ap", timeout=5000)
                LOGGER.info("Active session detected – token available without login")
            except Exception:
                LOGGER.info("No active session – performing login flow")

                # Upewnij się, że jesteśmy faktycznie na stronie logowania
                try:
                    await page.wait_for_selector("#Alias", timeout=5000)
                except Exception:
                    LOGGER.warning("Login form not detected – clearing context and retrying fresh login")

                    # Resetuj kontekst przeglądarki, aby usunąć potencjalnie uszkodzoną sesję
                    await context.close()
                    context = await browser.new_context()
                    page = await context.new_page()
                    await page.goto(EDUVULCAN_URL, wait_until="networkidle")
                    await remove_privacy_overlay(page)

                    await page.wait_for_selector("#Alias", timeout=30000)

                # Krok 1: login
                await page.fill("#Alias", login)
                await remove_privacy_overlay(page)
                await page.click("#btNext")

                # Krok 2: hasło
                await page.wait_for_selector("#Password", timeout=30000)
                await page.fill("#Password", password)

                # Captcha (jeśli się pojawi)
                try:
                    await page.wait_for_selector("#captcha", state="visible", timeout=5000)
                    await page.wait_for_function(
                        "document.querySelector('#captcha-response') && document.querySelector('#captcha-response').value !== ''",
                        timeout=30000
                    )
                except Exception:
                    pass

                await remove_privacy_overlay(page)
                await page.click("#btLogOn")

                # Czekamy aż backend zwróci stronę z #ap
                await page.wait_for_selector("#ap", state="attached", timeout=60000)

            # 3) Odczyt tokena z #ap (jedyna prawidłowa metoda)
            token_json = await page.eval_on_selector("#ap", "el => el.value")
            data = json.loads(token_json)

            tokens = data.get("Tokens") or []  # Tokens[] może być puste lub nieobecne
            jwt = tokens[0] if tokens else None  # W praktyce pierwszy element to JWT
            if not jwt:
                raise RuntimeError("Brak JWT w polu Tokens[]")

            payload = decode_jwt_payload(jwt)
            tenant = payload.get("tenant")
            if not tenant:
                raise RuntimeError("Nie udało się odczytać tenant z JWT")

            # 4) Zapis tokena do /config
            output = {
                "tenant": tenant,
                "jwt": jwt,
                "jwt_payload": payload,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "source": "eduvulcan.pl/api/ap",
            }

            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
                f.write("\n")

            # 5) Zapis cookies / localStorage do /data
            await context.storage_state(path=STORAGE_FILE)

            LOGGER.info("Token saved to: %s", TOKEN_FILE)
            LOGGER.info("Storage saved to: %s", STORAGE_FILE)
            LOGGER.info("Done (tenant: %s)", tenant)

        finally:
            await browser.close()

# Usuwa nakładki prywatności/cookies blokujące interakcję z formularzem
# Wejście: page (Playwright Page)
# Wyjście: None (modyfikuje DOM strony)
# Założenia/skutki: modyfikuje elementy DOM, aby umożliwić kliknięcia
async def remove_privacy_overlay(page):
    await page.evaluate("""
        // Usuń główny wrapper
        const wrapper = document.getElementById("respect-privacy-wrapper");
        if (wrapper) wrapper.remove();

        // Usuń iframe jeśli nadal istnieje
        const iframe = document.querySelector("iframe.cookie-frame");
        if (iframe) iframe.remove();

        // Na wszelki wypadek usuń wszelkie elementy z pointer-events: auto
        document.querySelectorAll('[id*="privacy"], [class*="cookie"]').forEach(el => {
            el.style.pointerEvents = 'none';
            el.remove();
        });
    """)

# Uruchamia pętlę odświeżania tokena na podstawie czasu wygaśnięcia
# Wejście: login i password (str)
# Wyjście: None (działa w pętli aż do błędu krytycznego)
# Założenia/skutki: w razie wielokrotnych błędów wysyła persistent notification
async def watchdog_loop(login: str, password: str):
    """
    Tryb ciągły:
    - sprawdza exp JWT
    - odświeża tylko gdy trzeba
    - limit 5 nieudanych prób, potem wysyła persistent notification
    """
    LOGGER.info("Starting JWT watchdog loop (refresh margin: %ss)", REFRESH_MARGIN)

    failures = 0

    # Pętla nieskończona, która usypia między kolejnymi kontrolami ważności
    while True:
        token_data = read_saved_token()

        if token_data:
            valid, exp, seconds_left = token_validity(token_data)
            if valid:
                sleep_for = max(60, seconds_left - REFRESH_MARGIN)  # Minimalnie 60s między kontrolami
                exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()  # Log czytelnego czasu wygaśnięcia
                LOGGER.info(
                    "Token still valid. Expires at %s (in %ss). Next check in %ss",
                    exp_dt, seconds_left, sleep_for
                )
                await asyncio.sleep(sleep_for)
                continue

        LOGGER.info("Token missing or expired – refreshing now...")
        try:
            await fetch_new_token(login, password)
            failures = 0  # reset po sukcesie
        except Exception as exc:
            failures += 1
            LOGGER.exception("Refresh failed (%s/%s): %s", failures, MAX_FAILURES, exc)

            # Po przekroczeniu limitu kończymy pętlę i informujemy użytkownika
            if failures >= MAX_FAILURES:
                msg = (
                    "Nie udało się odświeżyć tokena eduVULCAN po "
                    f"{failures} kolejnych próbach.\n\n"
                    "Sprawdź poprawność loginu/hasła, ewentualne captcha "
                    "lub zmiany w stronie logowania. Add-on wstrzymał kolejne próby."
                )
                send_persistent_notification(
                    title="EduVulcan Token Fetcher – błąd",
                    message=msg,
                )
                LOGGER.error("Max failures reached. Stopping watchdog loop.")
                return

            # Nie pętlimy agresywnie przy błędzie
            await asyncio.sleep(FAIL_SLEEP)
            continue

        # Krótka pauza po odświeżeniu
        await asyncio.sleep(30)


# Punkt wejścia aplikacji: parsuje argumenty i wybiera tryb pracy
# Wejście: argumenty CLI (--once) oraz zmienne środowiskowe login/hasło
# Wyjście: kod zakończenia procesu (int)
# Założenia/skutki: loguje błędy i propaguje kod wyjścia do SystemExit
async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Refresh token once and exit")
    args = parser.parse_args()

    login = os.getenv("EDUVULCAN_LOGIN")
    password = os.getenv("EDUVULCAN_PASSWORD")

    if not login or not password:
        LOGGER.error("Missing login/password in environment variables")
        return 1

    try:
        if args.once:
            LOGGER.info("Running in one-shot mode (--once)")
            await fetch_new_token(login, password)
        else:
            await watchdog_loop(login, password)
        return 0
    except Exception as exc:
        LOGGER.exception("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    # Inicjalizacja loggera i uruchomienie głównej pętli asynchronicznej
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    exit_code = asyncio.run(main())
    raise SystemExit(exit_code)
