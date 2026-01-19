# EduVulcan Token Fetcher – Home Assistant Add-on

Dodatek do Home Assistant, który **automatycznie loguje się do eduVULCAN**, pobiera **JWT token dostępu** z oficjalnego endpointu oraz **samodzielnie go odnawia przed wygaśnięciem**. Token jest zapisywany w katalogu `config` Home Assistanta, dzięki czemu może być używany przez inne integracje, skrypty lub automatyzacje.

Repozytorium zawiera gotowy add-on działający w środowisku Home Assistant Supervisor.

---

## 🧠 Co robi ten dodatek?

Dodatek:

* Loguje się do **eduVULCAN** przy użyciu prawdziwego formularza logowania (Playwright / Chromium).
* Otwiera bezpośredni endpoint:

  ```
  https://eduvulcan.pl/api/ap
  ```
* Odczytuje **JWT token** osadzony w polu `#ap` zwracanym przez backend.
* Dekoduje payload JWT i wyciąga:

  * `tenant`
  * `exp` (czas wygaśnięcia)
* Zapisuje token do:

  ```
  /config/eduvulcan_token.json
  ```
* Zapisuje sesję przeglądarki (cookies, localStorage) do:

  ```
  /data/eduvulcan_storage.json
  ```
* Uruchamia **watchdog**, który:

  * monitoruje czas wygaśnięcia JWT (`exp`),
  * automatycznie odświeża token przed jego wygaśnięciem,
  * w razie błędu kończy działanie zamiast wysyłać zapytania z nieaktywnym tokenem.

---

## 🔐 Dlaczego `/api/ap`?

Strona:

```
https://eduvulcan.pl/api/ap
```

jest miejscem, gdzie backend eduVULCAN **udostępnia aktualny token JWT w postaci JSON** w elemencie HTML:

```html
<input id="ap" value='{ "Tokens": ["<JWT>"], ... }' />
```

---

## ⚙️ Mechanizm działania – krok po kroku

### 1️⃣ Start dodatku

Po uruchomieniu Supervisor startuje kontener add-on.

Dodatek:

* odczytuje `EDUVULCAN_LOGIN` i `EDUVULCAN_PASSWORD` z konfiguracji,
* sprawdza, czy istnieje zapisany stan sesji (`/data/eduvulcan_storage.json`).

---

### 2️⃣ Wejście na endpoint tokena

Przeglądarka (Playwright + Chromium) otwiera:

```
https://eduvulcan.pl/api/ap
```

* Jeśli sesja jest nadal aktywna → token jest dostępny od razu.
* Jeśli nie → backend przekierowuje do:

  ```
  /logowanie?ReturnUrl=%2Fapi%2Fap
  ```

---

### 3️⃣ Logowanie

Automatyzowany formularz:

1. Wpisanie loginu (`#Alias`)
2. Kliknięcie „Dalej”
3. Wpisanie hasła (`#Password`)
4. Obsługa CAPTCHA (jeśli wystąpi)
5. Zatwierdzenie logowania

Po poprawnym logowaniu backend wraca do `/api/ap`.

---

### 4️⃣ Pobranie tokena

Dodatek odczytuje zawartość pola:

```js
document.querySelector("#ap").value
```

Z JSON wyciągane jest:

* `Tokens[0]` → JWT
* Dekodowany jest payload (`base64url`) w celu odczytania:

  * `tenant`
  * `exp` (czas wygaśnięcia)

---

### 5️⃣ Zapis danych

#### Token:

```
/config/eduvulcan_token.json
```

Przykład:

```json
{
  "tenant": "ABCD",
  "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "jwt_payload": {
    "tenant": "ABCD",
    "exp": 1768575022,
    "iat": 1768571422
  },
  "fetched_at": "2026-01-16T10:19:03+00:00",
  "source": "eduvulcan.pl/api/ap"
}
```

#### Sesja przeglądarki:

```
/data/eduvulcan_storage.json
```

Zawiera cookies i localStorage, dzięki czemu kolejne odświeżenia zwykle nie wymagają ponownego logowania.

---

### 6️⃣ Watchdog JWT (automatyczne odnawianie)

Dodatek uruchamia pętlę:

1. Odczytuje `exp` z JWT.
2. Oblicza pozostały czas ważności.
3. Gdy do wygaśnięcia zostanie mniej niż ustalony próg:

   * ponownie wykonuje proces logowania,
   * zapisuje nowy token,
   * aktualizuje sesję.

Jeśli wystąpi błąd (np. zmiana strony logowania, błąd CAPTCHA, brak tokena):

* dodatek kończy działanie,
* nie wysyła kolejnych zapytań na nieaktywnym tokenie.

---

## 🧪 Weryfikacja działania

W logach dodatku powinieneś zobaczyć m.in.:

```
Opening: https://eduvulcan.pl/api/ap
Active session detected – token available without login
Token saved to: /config/eduvulcan_token.json
Starting JWT watchdog loop
Token still valid. Expires at 2026-01-16T10:30:22+00:00 (in 2306s)
```

---

## 📦 Zawartość repozytorium

To repozytorium zawiera:

### EduVulcan Token Fetcher

![Supports aarch64 Architecture][aarch64-shield]
![Supports amd64 Architecture][amd64-shield]

Dodatek do automatycznego pobierania i odnawiania JWT tokena z eduVULCAN.

---

## ⚠️ Uwagi prawne

* Dodatek korzysta z **oficjalnej strony eduVULCAN i mechanizmu logowania użytkownika**.
* Nie omija zabezpieczeń ani nie modyfikuje ruchu sieciowego.
* Odpowiedzialność za zgodność z regulaminem serwisu eduVULCAN leży po stronie użytkownika.

---

[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg
