#!/usr/bin/env python3
import asyncio
import json
import os
import base64
import logging
import argparse
import time
import re
from datetime import datetime, timezone
from typing import Optional
import urllib.request
import urllib.error

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

LOGGER = logging.getLogger("eduvulcan_token_fetcher")

# Ścieżki w HA
# Zawiera docelową lokalizację zapisu/odczytu tokena w środowisku Home Assistant
TOKEN_FILE = "/config/eduvulcan_token.json"
# Zawiera lokalizację zapisu stanu przeglądarki (cookies, localStorage) dla ponownych logowań
STORAGE_FILE = "/data/eduvulcan_storage.json"
DEBUG_DIR = "/data"

# Startujemy ZAWSZE od /api/ap
# Ten endpoint zwraca lub przekierowuje do logowania i umożliwia pobranie tokena
EDUVULCAN_URL = "https://eduvulcan.pl/api/ap"

# Id powiadomienia HA dla błędów pobierania tokena
ERROR_NOTIFICATION_ID = "eduvulcan_token_fetcher_error"

# Zapas przed wygaśnięciem JWT (sekundy)
# Dzięki temu odświeżenie następuje przed wygaśnięciem tokena i minimalizuje przerwy
REFRESH_MARGIN = 300  # 5 minut

# Limit nieudanych prób odświeżenia
# Po przekroczeniu wysyłamy powiadomienie i kończymy pętlę watchdog
MAX_FAILURES = 5

# Interwał przy błędzie (sekundy)
# Wydłuża przerwę po błędzie, aby nie obciążać serwisu powtarzalnymi próbami
FAIL_SLEEP = 300  # 5 minut


class LoginFlowError(RuntimeError):
    """Raised when the current eduVULCAN login page cannot be automated safely."""


LOGIN_FIELD_SELECTORS = [
    ("legacy Alias field", "#Alias"),
    ("Alias input", "input[name='Alias']"),
    ("alias-like input", "input[id*='Alias' i]"),
    ("username input", "input[name='username' i]"),
    ("login input", "input[name='login' i]"),
    ("email input", "input[type='email']"),
    ("visible text input", "input[type='text']"),
]

PASSWORD_FIELD_SELECTORS = [
    ("legacy Password field", "#Password"),
    ("password input", "input[name='Password' i]"),
    ("visible password input", "input[type='password']"),
]

NEXT_BUTTON_SELECTORS = [
    ("legacy next button", "#btNext"),
    ("next button", "button:has-text('Dalej')"),
    ("continue button", "button:has-text('Kontynuuj')"),
    ("submit button", "button[type='submit']"),
    ("next link", "a:has-text('Dalej')"),
]

LOGIN_BUTTON_SELECTORS = [
    ("legacy logon button", "#btLogOn"),
    ("login button", "button:has-text('Zaloguj')"),
    ("sign in button", "button:has-text('Logowanie')"),
    ("submit button", "button[type='submit']"),
]

INTERMEDIATE_LOGIN_SELECTORS = [
    ("login link", "a:has-text('Zaloguj')"),
    ("login button", "button:has-text('Zaloguj')"),
    ("login url link", "a[href*='logowanie' i]"),
    ("login url link", "a[href*='login' i]"),
]


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
def send_persistent_notification(title: str, message: str, notification_id: Optional[str] = None) -> None:
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
    if notification_id:
        payload["notification_id"] = notification_id

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
    except urllib.error.HTTPError as exc:
        LOGGER.error(
            "Failed to send persistent notification (status %s): %s",
            exc.code,
            exc.reason,
        )
    except Exception as exc:
        LOGGER.error("Failed to send persistent notification: %s", exc)

def dismiss_persistent_notification(notification_id: str) -> None:
    """
    Usuwa persistent notification z Home Assistant przez Supervisor API.
    """
    supervisor_token = os.getenv("SUPERVISOR_TOKEN")
    if not supervisor_token:
        LOGGER.error("SUPERVISOR_TOKEN not found in environment; cannot dismiss notification")
        return

    url = "http://supervisor/core/api/services/persistent_notification/dismiss"
    payload = {
        "notification_id": notification_id,
    }

    data = json.dumps(payload).encode("utf-8")
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
        with urllib.request.urlopen(req, timeout=10) as resp:
            LOGGER.info("Persistent notification dismissed via Supervisor API (status %s)", resp.status)
    except urllib.error.HTTPError as exc:
        LOGGER.error(
            "Failed to dismiss persistent notification (status %s): %s",
            exc.code,
            exc.reason,
        )
    except Exception as exc:
        LOGGER.error("Failed to dismiss persistent notification: %s", exc)

def _safe_debug_name(reason: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", reason.strip().lower())
    return safe[:80] or "page"


async def describe_page(page) -> str:
    try:
        title = await page.title()
    except Exception:
        title = "<title unavailable>"
    return f"url={page.url!r}, title={title!r}"


async def save_page_diagnostics(page, reason: str) -> None:
    """
    Saves HTML and screenshot for the current page so login failures include
    the real page state, not only a selector timeout.
    """
    os.makedirs(DEBUG_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_reason = _safe_debug_name(reason)
    html_path = os.path.join(DEBUG_DIR, f"eduvulcan_debug_{stamp}_{safe_reason}.html")
    screenshot_path = os.path.join(DEBUG_DIR, f"eduvulcan_debug_{stamp}_{safe_reason}.png")

    LOGGER.error("Login diagnostics: %s", await describe_page(page))

    try:
        html = await page.content()
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        LOGGER.error("Saved diagnostic HTML: %s", html_path)
    except Exception as exc:
        LOGGER.warning("Failed to save diagnostic HTML: %s", exc)

    try:
        await page.screenshot(path=screenshot_path, full_page=True)
        LOGGER.error("Saved diagnostic screenshot: %s", screenshot_path)
    except Exception as exc:
        LOGGER.warning("Failed to save diagnostic screenshot: %s", exc)


async def find_visible_locator(page, selectors, timeout: int = 30000):
    deadline = time.monotonic() + timeout / 1000
    last_error = None

    while time.monotonic() < deadline:
        for name, selector in selectors:
            locator = page.locator(selector).first
            try:
                if await locator.count() == 0:
                    continue
                await locator.wait_for(state="visible", timeout=500)
                return name, selector, locator
            except Exception as exc:
                last_error = exc

        await asyncio.sleep(0.25)

    selector_summary = ", ".join(selector for _, selector in selectors)
    raise PlaywrightTimeoutError(
        f"Timeout waiting for any visible selector: {selector_summary}. "
        f"Last error: {last_error}"
    )


async def click_first_visible(page, selectors, timeout: int = 10000):
    name, selector, locator = await find_visible_locator(page, selectors, timeout=timeout)
    LOGGER.info("Clicking %s (%s)", name, selector)
    await remove_privacy_overlay(page)
    await locator.click()
    try:
        await page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass
    return name, selector


async def ensure_login_field(page, timeout: int = 30000):
    deadline = time.monotonic() + timeout / 1000

    while time.monotonic() < deadline:
        await remove_privacy_overlay(page)

        try:
            await page.wait_for_selector("#ap", timeout=1000)
            LOGGER.info("Token field appeared while looking for login form")
            return None
        except Exception:
            pass

        try:
            return await find_visible_locator(page, LOGIN_FIELD_SELECTORS, timeout=2000)
        except Exception:
            pass

        try:
            await click_first_visible(page, INTERMEDIATE_LOGIN_SELECTORS, timeout=2000)
            continue
        except Exception:
            await asyncio.sleep(0.5)

    await save_page_diagnostics(page, "login_form_not_detected")
    raise LoginFlowError(
        "Nie wykryto formularza logowania eduVULCAN. "
        f"Aktualna strona: {await describe_page(page)}"
    )


async def fill_login_form(page, login: str, password: str) -> None:
    login_match = await ensure_login_field(page, timeout=30000)
    if login_match is None:
        return

    login_name, login_selector, login_locator = login_match
    LOGGER.info("Login field detected: %s (%s)", login_name, login_selector)
    await login_locator.fill(login)

    try:
        password_name, password_selector, password_locator = await find_visible_locator(
            page, PASSWORD_FIELD_SELECTORS, timeout=1500
        )
    except Exception:
        try:
            await click_first_visible(page, NEXT_BUTTON_SELECTORS, timeout=10000)
        except Exception:
            LOGGER.info("Next button not detected; submitting login field with Enter")
            await login_locator.press("Enter")
        password_name, password_selector, password_locator = await find_visible_locator(
            page, PASSWORD_FIELD_SELECTORS, timeout=30000
        )

    LOGGER.info("Password field detected: %s (%s)", password_name, password_selector)
    await password_locator.fill(password)

    try:
        await page.wait_for_selector("#captcha", state="visible", timeout=5000)
        await save_page_diagnostics(page, "captcha_detected")
        raise LoginFlowError(
            "Wykryto captcha podczas logowania eduVULCAN. "
            f"Aktualna strona: {await describe_page(page)}"
        )
    except PlaywrightTimeoutError:
        pass

    try:
        await click_first_visible(page, LOGIN_BUTTON_SELECTORS, timeout=10000)
    except Exception:
        LOGGER.info("Login button not detected; submitting password field with Enter")
        await password_locator.press("Enter")

    try:
        await page.wait_for_selector("#ap", state="attached", timeout=30000)
    except Exception as exc:
        await save_page_diagnostics(page, "token_field_not_detected_after_login")
        raise LoginFlowError(
            "Logowanie nie zakonczylo sie strona tokena (#ap). "
            f"Aktualna strona: {await describe_page(page)}. "
            f"Oryginalny blad: {exc}"
        ) from exc


async def fetch_new_token(login: str, password: str):
    LOGGER.info("Launching Playwright (headless Chromium)")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )

        if os.path.exists(STORAGE_FILE):
            LOGGER.info("Loading stored cookies/session")
            context = await browser.new_context(storage_state=STORAGE_FILE)
        else:
            context = await browser.new_context()

        page = await context.new_page()

        try:
            LOGGER.info("Opening: %s", EDUVULCAN_URL)
            await page.goto(EDUVULCAN_URL, wait_until="networkidle")
            await remove_privacy_overlay(page)

            try:
                await page.wait_for_selector("#ap", timeout=5000)
                LOGGER.info("Active session detected - token available without login")
            except Exception:
                LOGGER.info("No active session - performing login flow")

                try:
                    await fill_login_form(page, login, password)
                except LoginFlowError as first_exc:
                    LOGGER.warning(
                        "Login flow failed on stored session (%s); clearing context and retrying fresh login",
                        first_exc,
                    )
                    await save_page_diagnostics(page, "stored_session_login_failed")

                    await context.close()
                    context = await browser.new_context()
                    page = await context.new_page()
                    await page.goto(EDUVULCAN_URL, wait_until="networkidle")
                    await remove_privacy_overlay(page)
                    await fill_login_form(page, login, password)

            token_json = await page.eval_on_selector("#ap", "el => el.value")
            data = json.loads(token_json)

            tokens = data.get("Tokens") or []
            jwt = tokens[0] if tokens else None
            if not jwt:
                await save_page_diagnostics(page, "jwt_missing_in_ap_response")
                send_persistent_notification(
                    title="EduVulcan Token Fetcher - blad",
                    message="Nie wykryto tokena JWT w odpowiedzi eduVULCAN.",
                    notification_id=ERROR_NOTIFICATION_ID,
                )
                raise RuntimeError("Brak JWT w polu Tokens[]")

            payload = decode_jwt_payload(jwt)
            tenant = payload.get("tenant")
            if not tenant:
                raise RuntimeError("Nie udalo sie odczytac tenant z JWT")

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

            await context.storage_state(path=STORAGE_FILE)

            LOGGER.info("Token saved to: %s", TOKEN_FILE)
            LOGGER.info("Storage saved to: %s", STORAGE_FILE)
            LOGGER.info("Done (tenant: %s)", tenant)

        except Exception:
            try:
                await save_page_diagnostics(page, "fetch_new_token_failed")
            except Exception:
                pass
            raise
        finally:
            await browser.close()


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
    last_failure_reason = ""

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
            last_failure_reason = str(exc) or exc.__class__.__name__
            LOGGER.exception("Refresh failed (%s/%s): %s", failures, MAX_FAILURES, exc)

            # Po przekroczeniu limitu kończymy pętlę i informujemy użytkownika
            if failures >= MAX_FAILURES:
                msg = (
                    f"Ostatni blad: {last_failure_reason}\n\n"
                    "Diagnostyka, jesli udalo sie ja zapisac, jest w "
                    "/data/eduvulcan_debug_*.html oraz /data/eduvulcan_debug_*.png.\n\n"
                    "Nie udało się odświeżyć tokena eduVULCAN po "
                    f"{failures} kolejnych próbach.\n\n"
                    "Sprawdź poprawność loginu/hasła, ewentualne captcha "
                    "lub zmiany w stronie logowania. Add-on wstrzymał kolejne próby."
                )
                send_persistent_notification(
                    title="EduVulcan Token Fetcher – błąd",
                    message=msg,
                    notification_id=ERROR_NOTIFICATION_ID,
                )
                LOGGER.error("Max failures reached. Stopping watchdog loop.")
                return 1

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

    supervisor_token = os.getenv("SUPERVISOR_TOKEN")
    if supervisor_token:
        LOGGER.info("SUPERVISOR_TOKEN detected in environment")
    else:
        LOGGER.warning("SUPERVISOR_TOKEN missing in environment; notifications may fail")

    dismiss_persistent_notification(ERROR_NOTIFICATION_ID)

    try:
        if args.once:
            LOGGER.info("Running in one-shot mode (--once)")
            await fetch_new_token(login, password)
        else:
            return await watchdog_loop(login, password)
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
