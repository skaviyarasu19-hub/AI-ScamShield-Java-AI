// ============================================================
// AI ScamShield - Frontend API helper
// Centralizes fetch calls to the Spring Boot backend, JWT storage,
// and basic auth-guard utilities used across all pages.
// ============================================================

const FILE_SCHEME_UI_URL = "http://127.0.0.1:5500/";
const supportedPages = new Set([
  "index.html",
  "login.html",
  "register.html",
  "dashboard.html",
  "scanner.html",
  "url-scanner.html",
  "assistant.html",
  "history.html",
  "profile.html",
  "admin.html",
]);

if (window.location.protocol === "file:") {
  const fileName = decodeURIComponent(window.location.pathname.split("/").pop() || "index.html");
  const pageName = supportedPages.has(fileName) ? fileName : "index.html";
  const hostedPage = new URL(pageName, FILE_SCHEME_UI_URL);
  hostedPage.search = window.location.search;
  hostedPage.hash = window.location.hash;
  window.location.replace(hostedPage.href);
}

const API_BASE_URL = (() => {
  if (window.location.protocol === "file:") return "http://127.0.0.1:8080/api";
  const apiUrl = new URL(window.location.origin);
  apiUrl.port = "8080";
  apiUrl.pathname = "/api";
  apiUrl.search = "";
  apiUrl.hash = "";
  return apiUrl.toString().replace(/\/$/, "");
})();

const Auth = {
  getToken() {
    return localStorage.getItem("scamshield_token");
  },
  getUser() {
    const raw = localStorage.getItem("scamshield_user");
    return raw ? JSON.parse(raw) : null;
  },
  setSession(authResponse) {
    localStorage.setItem("scamshield_token", authResponse.token);
    localStorage.setItem(
      "scamshield_user",
      JSON.stringify({
        userId: authResponse.userId,
        username: authResponse.username,
        roles: authResponse.roles || [],
      })
    );
  },
  clearSession() {
    localStorage.removeItem("scamshield_token");
    localStorage.removeItem("scamshield_user");
  },
  isLoggedIn() {
    return !!this.getToken();
  },
  isAdmin() {
    const user = this.getUser();
    return !!user && user.roles && user.roles.includes("ROLE_ADMIN");
  },
  requireAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = "login.html";
    }
  },
  requireAdmin() {
    this.requireAuth();
    if (!this.isAdmin()) {
      window.location.href = "dashboard.html";
    }
  },
  logout() {
    this.clearSession();
    window.location.href = "login.html";
  },
};

async function apiRequest(path, { method = "GET", body = null, auth = true } = {}) {
  if (window.location.protocol === "file:") {
    throw new ApiError(
      "This page was opened directly from a file. Open ScamShield at http://127.0.0.1:5500/login.html to connect to the Java backend.",
      -1,
      null
    );
  }

  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = Auth.getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (networkErr) {
    throw new ApiError(
      `ScamShield's Java backend at ${API_BASE_URL} could not be reached. Make sure the backend is running and accessible from this device.`,
      0,
      null
    );
  }

  if (response.status === 401 && auth) {
    Auth.clearSession();
    window.location.href = "login.html";
    return;
  }

  if (response.status === 204) return null;

  let data = null;
  try {
    data = await response.json();
  } catch (e) {
    /* no JSON body */
  }

  if (!response.ok) {
    const message = (data && (data.message || data.error)) || `Request failed (${response.status})`;
    throw new ApiError(message, response.status, data);
  }

  return data;
}

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

// ---------------- Navbar rendering (shared across all logged-in pages) ----------------
function renderNavbar(activePage) {
  const mount = document.getElementById("navbar-mount");
  if (!mount) return;

  const user = Auth.getUser();
  const isAdmin = Auth.isAdmin();

  const links = [
    { href: "dashboard.html", label: "Dashboard" },
    { href: "scanner.html", label: "Message Scanner" },
    { href: "url-scanner.html", label: "URL Scanner" },
    { href: "assistant.html", label: "Scam Assistant" },
    { href: "history.html", label: "History" },
    { href: "profile.html", label: "Profile" },
  ];
  if (isAdmin) links.push({ href: "admin.html", label: "Admin" });

  mount.innerHTML = `
    <nav class="navbar${isAdmin ? " has-admin" : ""}">
      <a class="brand" href="dashboard.html" aria-label="AI ScamShield dashboard">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 32 36" focusable="false">
            <path d="M16 2 28 7v9c0 8-4.8 13.5-12 18C8.8 29.5 4 24 4 16V7l12-5Z" fill="currentColor" opacity=".16"/>
            <path d="M16 2 28 7v9c0 8-4.8 13.5-12 18C8.8 29.5 4 24 4 16V7l12-5Z" fill="none" stroke="currentColor" stroke-width="2"/>
            <path d="m10.5 17 3.6 3.6 7.8-8.1" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.4"/>
          </svg>
        </span>
        <span>ScamShield</span>
      </a>
      <div class="navlinks" id="primary-navigation">
        ${links
          .map(
            (l) =>
              `<a href="${l.href}" class="${activePage === l.href ? "active" : ""}"${activePage === l.href ? ' aria-current="page"' : ""}>${l.label}</a>`
          )
          .join("")}
      </div>
      <div class="nav-user">
        <span class="nav-identity">
          <span class="nav-avatar" aria-hidden="true">${escapeNavbarText((user && user.username || "U").charAt(0).toUpperCase())}</span>
          <span class="nav-user-copy">
            <span class="nav-username">${escapeNavbarText(user ? user.username : "")}</span>
            <span class="nav-user-role">${isAdmin ? "Administrator" : "Protected account"}</span>
          </span>
        </span>
        <button class="btn-logout" onclick="Auth.logout()">Logout</button>
      </div>
      <button class="nav-toggle" type="button" aria-label="Open navigation menu"
        aria-expanded="false" aria-controls="primary-navigation">
        <span></span><span></span><span></span>
      </button>
    </nav>
  `;

  const navbar = mount.querySelector(".navbar");
  const toggle = mount.querySelector(".nav-toggle");
  toggle.addEventListener("click", () => {
    const isOpen = navbar.classList.toggle("nav-open");
    toggle.setAttribute("aria-expanded", String(isOpen));
    toggle.setAttribute("aria-label", isOpen ? "Close navigation menu" : "Open navigation menu");
  });
  navbar.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && navbar.classList.contains("nav-open")) {
      navbar.classList.remove("nav-open");
      toggle.setAttribute("aria-expanded", "false");
      toggle.setAttribute("aria-label", "Open navigation menu");
      toggle.focus();
    }
  });
  mount.querySelectorAll(".navlinks a").forEach((link) => {
    link.addEventListener("click", () => {
      navbar.classList.remove("nav-open");
      toggle.setAttribute("aria-expanded", "false");
      toggle.setAttribute("aria-label", "Open navigation menu");
    });
  });
}

function escapeNavbarText(value) {
  const element = document.createElement("span");
  element.textContent = value == null ? "" : String(value);
  return element.innerHTML;
}

function showAlert(elementId, message, type = "error") {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = `alert alert-${type}`;
  el.style.display = "block";
}

function hideAlert(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.style.display = "none";
}

function formatDate(isoString) {
  if (!isoString) return "-";
  const d = new Date(isoString);
  return d.toLocaleString();
}

function riskLabel(classification) {
  return { SAFE: "Safe", SUSPICIOUS: "Suspicious", LIKELY_SCAM: "Dangerous" }[classification] || classification;
}

function friendlyErrorMessage(error, fallback) {
  if (error && error.data && error.data.fieldErrors) {
    return Object.values(error.data.fieldErrors).join(" ");
  }
  if (error && error.status >= 500) return fallback;
  if (error && error.status === 400) return "Please check the information you entered and try again.";
  if (error && error.status === 0) {
    return error.message || "We couldn't reach ScamShield's Java backend. Check that it is running and try again.";
  }
  return error && error.message ? error.message : fallback;
}
