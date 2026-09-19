/* ---------------------------------------------------------------------------
   Shared browser-side helpers: token storage, a fetch wrapper, and the
   login/register panel that both pages use.

   Plain JavaScript on purpose -- no framework, no bundler, no build step. The
   whole frontend is three static files that FastAPI serves directly, so there
   is one deployment and no CORS to configure.
   --------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------
   Token storage

   The JWT is kept in localStorage. Be honest about the trade-off, because an
   interviewer may well ask:

     localStorage is readable by any JavaScript running on this page, so a
     cross-site-scripting bug would leak the token. The more secure option is
     an httpOnly cookie, which JavaScript cannot read at all -- but cookies
     are sent automatically on every request, which opens up CSRF and means
     the API needs a CSRF token as well.

   For this project localStorage is the right call: the API is a pure Bearer
   token API (that is what OAuth2PasswordBearer expects), the token expires in
   an hour, and there is no third-party script on the page to exploit an XSS.
   -------------------------------------------------------------------------- */
const TOKEN_KEY = "secretshare_token";

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function isLoggedIn() {
  return getToken() !== null;
}

/* --------------------------------------------------------------------------
   The fetch wrapper
   -------------------------------------------------------------------------- */

/** Thrown for any non-2xx response, carrying the status so callers can branch
 *  on 404 vs 410 vs 429 rather than string-matching the message. */
class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Call the API.
 *
 * Adds the Authorization header when we have a token, parses the JSON body,
 * and turns any error response into an ApiError.
 */
async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };

  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Only set a JSON content type when we are actually sending JSON. The login
  // endpoint sends a form body instead, and setting the wrong type there makes
  // FastAPI reject it.
  if (options.body && !(options.body instanceof URLSearchParams)) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(path, { ...options, headers });

  // 204 and friends have no body to parse.
  let body = null;
  const text = await response.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: text };
    }
  }

  if (!response.ok) {
    // An expired or invalid token means our stored one is useless -- drop it
    // so the page falls back to showing the login form.
    if (response.status === 401) {
      clearToken();
    }
    throw new ApiError(response.status, detailOf(body) || response.statusText);
  }

  return body;
}

/**
 * Pull a readable message out of an error body.
 *
 * FastAPI returns {"detail": "..."} for HTTPException, but for a validation
 * failure `detail` is a LIST of per-field error objects, which would render as
 * "[object Object]" if we used it directly.
 */
function detailOf(body) {
  if (!body) return null;
  const detail = body.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const field = Array.isArray(item.loc) ? item.loc[item.loc.length - 1] : "input";
        return `${field}: ${item.msg}`;
      })
      .join("; ");
  }
  return null;
}

/* --------------------------------------------------------------------------
   Small DOM helpers
   -------------------------------------------------------------------------- */

function show(element) { element.classList.remove("hidden"); }
function hide(element) { element.classList.add("hidden"); }

/** Render a coloured message box, or clear it when text is null. */
function setMessage(element, text, kind = "error") {
  if (!text) {
    element.textContent = "";
    hide(element);
    return;
  }
  element.textContent = text;
  element.className = `message ${kind}`;
  show(element);
}

/** Copy text to the clipboard and briefly confirm it on the button. */
async function copyToClipboard(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = original; }, 1500);
  } catch {
    // The clipboard API needs a secure context (https or localhost). If it is
    // unavailable, say so rather than failing silently.
    button.textContent = "Press Cmd+C";
  }
}

/** Format an ISO timestamp for display, in the viewer's own timezone. */
function formatTime(isoString) {
  if (!isoString) return "—";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  return date.toLocaleString();
}

/** "in 42 minutes" / "expired", from an ISO timestamp. */
function relativeTime(isoString) {
  const target = new Date(isoString).getTime();
  if (Number.isNaN(target)) return "";
  const minutes = Math.round((target - Date.now()) / 60000);
  if (minutes < 0) return "expired";
  if (minutes < 1) return "in under a minute";
  if (minutes < 60) return `in ${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `in ${hours} hour${hours === 1 ? "" : "s"}`;
  const days = Math.round(hours / 24);
  return `in ${days} day${days === 1 ? "" : "s"}`;
}

/* --------------------------------------------------------------------------
   The shared login / register panel

   Both pages need it: the home page to let you in, and the reveal page
   because reading a secret requires an account (the team access check needs
   to know who is asking).
   -------------------------------------------------------------------------- */

/**
 * Render login + register forms into `container`, and call `onAuthenticated`
 * once the user has a token.
 */
function renderAuthPanel(container, onAuthenticated) {
  container.innerHTML = `
    <div class="tabs">
      <button type="button" data-mode="login" class="active">Log in</button>
      <button type="button" data-mode="register">Register</button>
    </div>
    <div class="message hidden" data-role="message"></div>
    <form data-role="form">
      <label>
        <span>Email</span>
        <input type="email" name="email" autocomplete="username" required>
      </label>
      <label>
        <span>Password <span class="hint">at least 8 characters</span></span>
        <input type="password" name="password" autocomplete="current-password"
               minlength="8" required>
      </label>
      <button type="submit" data-role="submit">Log in</button>
    </form>
  `;

  const messageBox = container.querySelector('[data-role="message"]');
  const form = container.querySelector('[data-role="form"]');
  const submitButton = container.querySelector('[data-role="submit"]');
  const tabs = container.querySelectorAll(".tabs button");

  let mode = "login";

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      mode = tab.dataset.mode;
      tabs.forEach((t) => t.classList.toggle("active", t === tab));
      submitButton.textContent = mode === "login" ? "Log in" : "Create account";
      setMessage(messageBox, null);
    });
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage(messageBox, null);
    submitButton.disabled = true;

    const email = form.email.value.trim();
    const password = form.password.value;

    try {
      if (mode === "register") {
        await api("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });
      }

      // The login endpoint takes a FORM body, not JSON, and the email goes in
      // a field called `username`. That is the OAuth2 password-flow spec --
      // the same thing that makes the Authorize button in /docs work.
      const credentials = new URLSearchParams({ username: email, password });
      const result = await api("/auth/login", {
        method: "POST",
        body: credentials,
      });

      setToken(result.access_token);
      onAuthenticated();
    } catch (error) {
      setMessage(messageBox, error.detail || "Something went wrong");
      submitButton.disabled = false;
    }
  });
}
