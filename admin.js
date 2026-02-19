const DB_KEY = "pro_majors_db";
const AUTH_KEY = "pro_majors_auth_session";
const USERS_KEY = "pro_majors_users";
const SECURITY_KEY = "pro_majors_security";
const ADMIN_LOG_KEY = "pro_majors_admin_log";
const SYNC_CHANNEL = "pro_majors_live_sync";
const LOGIN_USERNAME = "maldyaya-admin";
const LOGIN_PASSWORD = "015511";
const ADMIN_SECRET_CODE = "mald-yaya-nour";
const ADMIN_SECRET_SESSION_KEY = "pro_majors_admin_secret_ok";
const SESSION_TTL_MS = 30 * 60 * 1000;

const defaultData = [
    { id: 1, name: "علم البيانات", cat: "تقني", desc: "استخراج المعرفة من البيانات الكبيرة واستخدام التعلم الآلي للتنبؤ بالمستقبل." },
    { id: 2, name: "الطب البشري", cat: "صحي", desc: "تشخيص الأمراض وتقديم الرعاية الصحية الشاملة للمرضى بمختلف التخصصات." },
    { id: 3, name: "التسويق الرقمي", cat: "إداري", desc: "بناء الهوية الرقمية للشركات وإدارة الحملات الإعلانية عبر وسائل التواصل." },
    { id: 4, name: "الهندسة المعمارية", cat: "هندسي", desc: "تصميم المباني والمنشآت التي تجمع بين الجمال الفني والوظيفة العملية." }
];

function parseJSON(key, fallback) {
    try {
        const parsed = JSON.parse(localStorage.getItem(key));
        return parsed ?? fallback;
    } catch {
        return fallback;
    }
}

let db = parseJSON(DB_KEY, defaultData);
const syncChannel = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel(SYNC_CHANNEL) : null;

function saveDb() {
    localStorage.setItem(DB_KEY, JSON.stringify(db));
    emitSync([DB_KEY]);
}

function emitSync(keys) {
    if (!syncChannel) return;
    syncChannel.postMessage({ keys, at: nowMs() });
}

function applyExternalState(keys = []) {
    if (!keys.length || keys.includes(DB_KEY)) {
        db = parseJSON(DB_KEY, defaultData);
    }
    if (document.getElementById("admin-page").style.display === "block") {
        renderAdminTable();
        renderAdminStats();
    }
}

function setupRealtimeSync() {
    if (syncChannel) {
        syncChannel.addEventListener("message", (event) => {
            const keys = Array.isArray(event?.data?.keys) ? event.data.keys : [];
            applyExternalState(keys);
        });
    }

    window.addEventListener("storage", (e) => {
        if (!e.key) return;
        if ([DB_KEY, USERS_KEY, SECURITY_KEY].includes(e.key)) {
            applyExternalState([e.key]);
        }
    });
}

function nowMs() {
    return Date.now();
}

function normalizeText(value = "") {
    return String(value)
        .toLowerCase()
        .replace(/[\u0622\u0623\u0625]/g, "\u0627")
        .replace(/\u0629/g, "\u0647")
        .replace(/\u0649/g, "\u064a")
        .replace(/[\u064B-\u0652]/g, "")
        .trim();
}

function escapeHtml(value = "") {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function getSession() {
    try {
        const session = JSON.parse(sessionStorage.getItem(AUTH_KEY) || "null");
        if (!session) return null;
        if (!session.expiresAt || session.expiresAt < nowMs()) {
            sessionStorage.removeItem(AUTH_KEY);
            sessionStorage.removeItem(ADMIN_SECRET_SESSION_KEY);
            return null;
        }
        return session;
    } catch {
        return null;
    }
}

function refreshSessionTTL() {
    const session = getSession();
    if (!session) return;
    session.expiresAt = nowMs() + SESSION_TTL_MS;
    sessionStorage.setItem(AUTH_KEY, JSON.stringify(session));
}

function hasAdminSession() {
    const session = getSession();
    return !!session && session.role === "admin";
}

function showState(state) {
    document.getElementById("admin-login").style.display = state === "login" ? "flex" : "none";
    document.getElementById("admin-unlock").style.display = state === "unlock" ? "flex" : "none";
    document.getElementById("admin-page").style.display = state === "page" ? "block" : "none";
}

function setAdminSession() {
    sessionStorage.setItem(AUTH_KEY, JSON.stringify({
        user: LOGIN_USERNAME,
        role: "admin",
        createdAt: nowMs(),
        expiresAt: nowMs() + SESSION_TTL_MS
    }));
}

function appendAdminLog(action, payload = "") {
    const logs = parseJSON(ADMIN_LOG_KEY, []);
    logs.unshift({
        at: new Date().toISOString(),
        action,
        payload
    });
    localStorage.setItem(ADMIN_LOG_KEY, JSON.stringify(logs.slice(0, 200)));
}

function renderAdminStats() {
    const users = parseJSON(USERS_KEY, []);
    const security = parseJSON(SECURITY_KEY, { failedByUser: {} });
    const failed = Object.values(security.failedByUser || {}).reduce((sum, item) => sum + (item.attempts || 0), 0);

    document.getElementById("admin-stats-majors").innerText = String(db.length);
    document.getElementById("admin-stats-users").innerText = String(users.length);
    document.getElementById("admin-stats-fails").innerText = String(failed);
    document.getElementById("admin-stats-updated").innerText = new Date().toLocaleTimeString("ar-SA", { hour: "2-digit", minute: "2-digit" });
}

function verifyAccess() {
    if (!hasAdminSession()) {
        showState("login");
        return;
    }
    const secretOk = sessionStorage.getItem(ADMIN_SECRET_SESSION_KEY) === ADMIN_SECRET_CODE;
    if (!secretOk) {
        showState("unlock");
        return;
    }
    showState("page");
    renderAdminTable();
    renderAdminStats();
    refreshSessionTTL();
}

function handleAdminLogin() {
    const user = document.getElementById("admin-login-user").value.trim();
    const pass = document.getElementById("admin-login-pass").value;
    const secret = document.getElementById("admin-login-secret").value.trim();
    const err = document.getElementById("admin-login-error");
    err.textContent = "";

    if (!user || !pass || !secret) {
        err.textContent = "أدخلي بيانات الأدمن كاملة.";
        return;
    }

    if (user !== LOGIN_USERNAME || pass !== LOGIN_PASSWORD || secret !== ADMIN_SECRET_CODE) {
        err.textContent = "بيانات الأدمن غير صحيحة.";
        appendAdminLog("admin_login_fail", user || "unknown");
        return;
    }

    setAdminSession();
    sessionStorage.setItem(ADMIN_SECRET_SESSION_KEY, ADMIN_SECRET_CODE);
    appendAdminLog("admin_login_success", user);
    showState("page");
    renderAdminTable();
    renderAdminStats();
}

function verifyAdminSecret() {
    const input = document.getElementById("admin-secret-input").value.trim();
    const err = document.getElementById("admin-unlock-error");
    err.textContent = "";

    if (input !== ADMIN_SECRET_CODE) {
        err.textContent = "الكود السري غير صحيح.";
        appendAdminLog("secret_fail");
        return;
    }
    sessionStorage.setItem(ADMIN_SECRET_SESSION_KEY, ADMIN_SECRET_CODE);
    appendAdminLog("secret_pass");
    showState("page");
    renderAdminTable();
    renderAdminStats();
}

function renderAdminTable() {
    const adminBody = document.getElementById("admin-table-body");
    adminBody.innerHTML = db.map((m) => `
        <tr>
            <td><strong>${escapeHtml(m.name)}</strong></td>
            <td><span class="category-tag">${escapeHtml(m.cat)}</span></td>
            <td>
                <button class="delete-btn" onclick="handle_Delete(${m.id})"><i class="fas fa-trash-alt"></i></button>
            </td>
        </tr>
    `).join("");
}

function handle_Add() {
    if (!hasAdminSession()) {
        showState("login");
        return;
    }

    const name = document.getElementById("m-name").value.trim();
    const cat = document.getElementById("m-cat").value;
    const desc = document.getElementById("m-desc").value.trim();

    if (!name || !desc) {
        alert("فضلاً أكملي جميع الحقول المطلوبة.");
        return;
    }

    const exists = db.some((m) => normalizeText(m.name) === normalizeText(name));
    if (exists) {
        alert("هذا التخصص موجود بالفعل.");
        return;
    }

    db.unshift({
        id: Date.now(),
        name,
        cat,
        desc,
        salary: "غير محدد",
        skills: "مهارات عامة"
    });

    saveDb();
    appendAdminLog("major_add", name);
    renderAdminTable();
    renderAdminStats();
    document.getElementById("m-name").value = "";
    document.getElementById("m-desc").value = "";
}

function handle_Delete(id) {
    if (!hasAdminSession()) {
        showState("login");
        return;
    }

    const item = db.find((m) => m.id === id);
    if (!item) return;

    if (confirm(`هل أنتِ متأكدة من حذف "${item.name}"؟`)) {
        db = db.filter((m) => m.id !== id);
        saveDb();
        appendAdminLog("major_delete", item.name);
        renderAdminTable();
        renderAdminStats();
    }
}

function goHome() {
    window.location.href = "index.html#/home";
}

function logoutAdmin() {
    sessionStorage.removeItem(AUTH_KEY);
    sessionStorage.removeItem(ADMIN_SECRET_SESSION_KEY);
    window.location.href = "index.html";
}

window.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && document.getElementById("admin-login").style.display === "flex") {
        handleAdminLogin();
    }
    if (e.key === "Enter" && document.getElementById("admin-unlock").style.display === "flex") {
        verifyAdminSecret();
    }
});

["click", "keydown", "mousemove", "touchstart"].forEach((evt) => {
    window.addEventListener(evt, refreshSessionTTL, { passive: true });
});

setupRealtimeSync();
verifyAccess();
