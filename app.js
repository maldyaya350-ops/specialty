const DB_KEY = "pro_majors_db";
const FAV_KEY = "pro_majors_favs";
const AUTH_KEY = "pro_majors_auth_session";
const USERS_KEY = "pro_majors_users";
const SECURITY_KEY = "pro_majors_security";
const ADMIN_LOG_KEY = "pro_majors_admin_log";
const WARNING_NOTIF_KEY = "pro_majors_warning_notifications";
const SYNC_CHANNEL = "pro_majors_live_sync";

const LOGIN_USERNAME = "maldyaya-admin";
const LOGIN_PASSWORD = "015511";
const ADMIN_SECRET_CODE = "mald-yaya-nour";
const ADMIN_SECRET_SESSION_KEY = "pro_majors_admin_secret_ok";
const IS_ADMIN_PAGE = window.location.pathname.toLowerCase().endsWith("/admin-secret.html");

const SESSION_TTL_MS = 30 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;

const defaultData = [
    { id: 1, name: "علم البيانات", cat: "تقني", desc: "استخراج المعرفة من البيانات الكبيرة واستخدام التعلم الآلي للتنبؤ بالمستقبل.", salary: "12k - 20k", skills: "Python, SQL, Math" },
    { id: 2, name: "الطب البشري", cat: "صحي", desc: "تشخيص الأمراض وتقديم الرعاية الصحية الشاملة للمرضى بمختلف التخصصات.", salary: "15k - 30k", skills: "Biology, Chemistry, Ethics" },
    { id: 3, name: "التسويق الرقمي", cat: "إداري", desc: "بناء الهوية الرقمية للشركات وإدارة الحملات الإعلانية عبر وسائل التواصل.", salary: "8k - 15k", skills: "SEO, Ads, Content Strategy" },
    { id: 4, name: "الهندسة المعمارية", cat: "هندسي", desc: "تصميم المباني والمنشآت التي تجمع بين الجمال الفني والوظيفة العملية.", salary: "10k - 18k", skills: "AutoCAD, Design, Physics" }
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
let currentFilter = "الكل";
let favorites = new Set(parseJSON(FAV_KEY, []));
let users = parseJSON(USERS_KEY, []);
let securityState = parseJSON(SECURITY_KEY, { failedByUser: {} });
let adminFailedAttempts = 0;
const syncChannel = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel(SYNC_CHANNEL) : null;

function emitSync(keys) {
    if (!syncChannel) return;
    syncChannel.postMessage({ keys, at: nowMs() });
}

function applyExternalState(keys = []) {
    if (!keys.length || keys.includes(DB_KEY)) {
        db = parseJSON(DB_KEY, defaultData);
    }
    if (!keys.length || keys.includes(FAV_KEY)) {
        favorites = new Set(parseJSON(FAV_KEY, []));
    }
    if (!keys.length || keys.includes(USERS_KEY)) {
        users = parseJSON(USERS_KEY, []);
    }
    if (!keys.length || keys.includes(SECURITY_KEY)) {
        securityState = parseJSON(SECURITY_KEY, { failedByUser: {} });
    }

    if (isAuthenticated()) {
        refreshAccessUI();
        const appRoot = document.getElementById("app-root");
        if (appRoot && appRoot.style.display === "block") {
            refreshUI();
        }
    }

    const adminPage = document.getElementById("admin-page");
    if (adminPage && adminPage.style.display === "block") {
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
        if ([DB_KEY, FAV_KEY, USERS_KEY, SECURITY_KEY].includes(e.key)) {
            applyExternalState([e.key]);
        }
    });
}

function saveAll() {
    localStorage.setItem(DB_KEY, JSON.stringify(db));
    localStorage.setItem(FAV_KEY, JSON.stringify([...favorites]));
    emitSync([DB_KEY, FAV_KEY]);
}

function saveDbOnly() {
    localStorage.setItem(DB_KEY, JSON.stringify(db));
    emitSync([DB_KEY]);
}

function saveUsers() {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
    emitSync([USERS_KEY]);
}

function saveSecurity() {
    localStorage.setItem(SECURITY_KEY, JSON.stringify(securityState));
    emitSync([SECURITY_KEY]);
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

function getUserLock(username) {
    const key = normalizeText(username || "_");
    const entry = securityState.failedByUser[key];
    return entry || { attempts: 0, lockedUntil: 0 };
}

function isLocked(username) {
    return getUserLock(username).lockedUntil > nowMs();
}

function lockRemainingSeconds(username) {
    const lock = getUserLock(username);
    return Math.max(0, Math.ceil((lock.lockedUntil - nowMs()) / 1000));
}

function registerFailedAttempt(username) {
    const key = normalizeText(username || "_");
    const current = getUserLock(key);
    const attempts = (current.attempts || 0) + 1;
    const lockedUntil = attempts >= MAX_LOGIN_ATTEMPTS ? nowMs() + LOCK_MS : 0;
    securityState.failedByUser[key] = { attempts, lockedUntil };
    saveSecurity();
}

function clearFailedAttempts(username) {
    const key = normalizeText(username || "_");
    if (securityState.failedByUser[key]) {
        delete securityState.failedByUser[key];
        saveSecurity();
    }
}

async function sha256Hex(value) {
    const enc = new TextEncoder().encode(value);
    const hashBuffer = await crypto.subtle.digest("SHA-256", enc);
    return [...new Uint8Array(hashBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyUserPassword(record, plainPassword) {
    if (record.passwordHash) {
        const hash = await sha256Hex(plainPassword);
        return hash === record.passwordHash;
    }
    if (record.password && record.password === plainPassword) {
        record.passwordHash = await sha256Hex(plainPassword);
        delete record.password;
        saveUsers();
        return true;
    }
    return false;
}

function isNotificationEnabled() {
    return (
        typeof Notification !== "undefined" &&
        Notification.permission === "granted" &&
        localStorage.getItem(WARNING_NOTIF_KEY) === "1"
    );
}

async function enableWarningNotifications() {
    const err = document.getElementById("auth-error");
    if (typeof Notification === "undefined") {
        err.textContent = "هذا المتصفح لا يدعم الإشعارات.";
        return;
    }

    if (Notification.permission === "granted") {
        localStorage.setItem(WARNING_NOTIF_KEY, "1");
        err.textContent = "تم تفعيل إشعارات التحذير.";
        return;
    }

    if (Notification.permission === "denied") {
        err.textContent = "الإشعارات مرفوضة من المتصفح. فعّليها من إعدادات الموقع.";
        return;
    }

    const permission = await Notification.requestPermission();
    if (permission === "granted") {
        localStorage.setItem(WARNING_NOTIF_KEY, "1");
        err.textContent = "تم تفعيل إشعارات التحذير.";
    } else {
        err.textContent = "لم يتم منح إذن الإشعارات.";
    }
}

function floodBrowserNotifications(message) {
    if (!isNotificationEnabled()) return;
    for (let i = 0; i < 8; i += 1) {
        setTimeout(() => {
            const n = new Notification("تحذير أمني - محاولة دخول أدمن", {
                body: `${message} (${i + 1}/8)`,
                tag: `admin-breach-${Date.now()}-${i}`,
                requireInteraction: i < 3,
                renotify: true
            });
            setTimeout(() => n.close(), 7000);
        }, i * 600);
    }
}

function triggerAdminBreachAlert(usernameValue) {
    adminFailedAttempts += 1;
    const now = new Date().toLocaleString("ar-SA");
    const alertText = `محاولة فاشلة لتسجيل دخول الأدمن (#${adminFailedAttempts}) - المستخدم: ${usernameValue || "غير معروف"} - الوقت: ${now}`;
    floodBrowserNotifications(alertText);
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

function setSession(user, role) {
    sessionStorage.setItem(AUTH_KEY, JSON.stringify({
        user,
        role,
        createdAt: nowMs(),
        expiresAt: nowMs() + SESSION_TTL_MS
    }));
}

function refreshSessionTTL() {
    const session = getSession();
    if (!session) return;
    session.expiresAt = nowMs() + SESSION_TTL_MS;
    sessionStorage.setItem(AUTH_KEY, JSON.stringify(session));
}

function isAuthenticated() {
    return !!getSession();
}

function getCurrentRole() {
    return getSession()?.role || null;
}

function isAdmin() {
    return getCurrentRole() === "admin";
}

function refreshAccessUI() {
    const navAdmin = document.getElementById("nav-admin");
    if (!navAdmin) return;
    if (!isAuthenticated()) {
        navAdmin.style.display = "none";
        return;
    }
    navAdmin.style.display = getCurrentRole() === "viewer" ? "inline-block" : "none";
}

function validateUsername(username) {
    if (username.length < 3 || username.length > 20) {
        return "اسم المستخدم يجب أن يكون بين 3 و20 حرفًا.";
    }
    if (!/^[\u0600-\u06FFa-zA-Z0-9_.]+$/.test(username)) {
        return "اسم المستخدم يقبل الأحرف والأرقام و (_) و (.) فقط.";
    }
    return "";
}

function validatePassword(password) {
    if (password.length < 8) return "كلمة المرور يجب أن تكون 8 أحرف على الأقل.";
    if (!/[A-Z]/.test(password)) return "كلمة المرور يجب أن تحتوي حرفًا كبيرًا واحدًا على الأقل.";
    if (!/[a-z]/.test(password)) return "كلمة المرور يجب أن تحتوي حرفًا صغيرًا واحدًا على الأقل.";
    if (!/\d/.test(password)) return "كلمة المرور يجب أن تحتوي رقمًا واحدًا على الأقل.";
    if (!/[^A-Za-z0-9]/.test(password)) return "كلمة المرور يجب أن تحتوي رمزًا خاصًا واحدًا على الأقل.";
    return "";
}

function showOnly(section) {
    const authGate = document.getElementById("auth-gate");
    const notFound = document.getElementById("not-found-screen");
    const appRoot = document.getElementById("app-root");
    if (authGate) authGate.style.display = section === "auth" ? "flex" : "none";
    if (notFound) notFound.style.display = section === "404" ? "flex" : "none";
    if (appRoot) appRoot.style.display = section === "app" ? "block" : "none";
}

function parseRoute() {
    const allowedRoutes = new Set(["", "/", "home"]);
    const path = window.location.pathname.toLowerCase();
    if (!(path.endsWith("/") || path.endsWith("/index.html"))) return { valid: false };
    const rawHash = (window.location.hash || "").replace(/^#\/?/, "").toLowerCase();
    const route = rawHash.split("?")[0];
    if (!allowedRoutes.has(route)) return { valid: false };
    return { valid: true, route: route || "home" };
}

function guardAuth() {
    if (isAuthenticated()) return true;
    showOnly("auth");
    return false;
}

async function handleLogin() {
    const user = document.getElementById("login-user").value.trim();
    const pass = document.getElementById("login-pass").value;
    const err = document.getElementById("auth-error");
    err.textContent = "";

    if (!user || !pass) {
        err.textContent = "اكتبي اسم المستخدم وكلمة المرور أولاً.";
        return;
    }

    if (isLocked(user)) {
        err.textContent = `الحساب مقفل مؤقتًا. حاولي بعد ${lockRemainingSeconds(user)} ثانية.`;
        return;
    }

    if (user === LOGIN_USERNAME) {
        registerFailedAttempt(user);
        if (pass !== LOGIN_PASSWORD) {
            triggerAdminBreachAlert(user);
        }
        err.textContent = "دخول الأدمن من صفحة الأدمن فقط.";
        return;
    }

    const record = users.find((u) => u.username === user);
    if (record && await verifyUserPassword(record, pass)) {
        clearFailedAttempts(user);
        sessionStorage.removeItem(ADMIN_SECRET_SESSION_KEY);
        setSession(user, record.role || "viewer");
        window.location.hash = "#/home";
        bootApp();
        return;
    }

    registerFailedAttempt(user);
    err.textContent = "اسم المستخدم أو كلمة المرور غير صحيحين.";
}

async function createViewerAccount() {
    const user = document.getElementById("login-user").value.trim();
    const pass = document.getElementById("login-pass").value;
    const passConfirm = document.getElementById("login-pass-confirm").value;
    const err = document.getElementById("auth-error");
    err.textContent = "";

    if (!user || !pass || !passConfirm) {
        err.textContent = "اكتبي اسم مستخدم وكلمة مرور أولاً.";
        return;
    }
    const userErr = validateUsername(user);
    if (userErr) {
        err.textContent = userErr;
        return;
    }
    if (user === LOGIN_USERNAME) {
        err.textContent = "اسم المستخدم محجوز.";
        return;
    }
    const passErr = validatePassword(pass);
    if (passErr) {
        err.textContent = passErr;
        return;
    }
    if (pass !== passConfirm) {
        err.textContent = "تأكيد كلمة المرور غير متطابق.";
        return;
    }
    if (users.some((u) => u.username === user)) {
        err.textContent = "اسم المستخدم موجود بالفعل.";
        return;
    }

    const passwordHash = await sha256Hex(pass);
    users.push({ username: user, passwordHash, role: "viewer", createdAt: nowMs() });
    saveUsers();
    clearFailedAttempts(user);
    setSession(user, "viewer");
    sessionStorage.removeItem(ADMIN_SECRET_SESSION_KEY);
    window.location.hash = "#/home";
    bootApp();
}

function logout() {
    sessionStorage.removeItem(AUTH_KEY);
    sessionStorage.removeItem(ADMIN_SECRET_SESSION_KEY);
    const loginUser = document.getElementById("login-user");
    const loginPass = document.getElementById("login-pass");
    const loginPassConfirm = document.getElementById("login-pass-confirm");
    if (loginUser) loginUser.value = "";
    if (loginPass) loginPass.value = "";
    if (loginPassConfirm) loginPassConfirm.value = "";
    showOnly("auth");
}

function goToAdminLogin() {
    window.location.href = "admin-secret.html";
}

function goSecretAdminPage() {
    if (!guardAuth()) return;
    window.location.href = "admin-secret.html";
}

function goHome() {
    if (IS_ADMIN_PAGE) {
        window.location.href = "index.html#/home";
        return;
    }
    window.location.hash = "#/home";
    bootApp();
}

function bootApp() {
    const route = parseRoute();
    if (!route.valid) {
        showOnly("404");
        return;
    }
    if (!isAuthenticated()) {
        showOnly("auth");
        return;
    }
    refreshAccessUI();
    refreshSessionTTL();
    showOnly("app");
    toggleApp("user", true);
}

function toggleApp(view, fromRouter = false) {
    if (!guardAuth()) return;
    document.getElementById("user-section").style.display = view === "user" ? "block" : "none";
    document.getElementById("nav-user").classList.toggle("active", view === "user");
    document.getElementById("nav-admin").classList.toggle("active", false);
    if (!fromRouter && window.location.hash !== "#/home") {
        window.location.hash = "#/home";
    }
    refreshUI();
}

function filterBy(cat) {
    if (!guardAuth()) return;
    currentFilter = cat;
    document.querySelectorAll(".filter-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.cat === cat);
    });
    refreshUI();
}

function refreshUI() {
    if (!guardAuth()) return;
    const search = normalizeText(document.getElementById("search-input").value);
    const grid = document.getElementById("majors-grid");

    const filtered = db.filter((m) => {
        const stack = normalizeText(`${m.name} ${m.desc} ${m.skills || ""} ${m.cat}`);
        const matchesSearch = !search || stack.includes(search);
        const matchesFilter = currentFilter === "الكل" || m.cat === currentFilter;
        return matchesSearch && matchesFilter;
    });

    if (!filtered.length) {
        grid.innerHTML = `
            <div class="empty-box">
                <h3 style="margin-bottom:8px;">لا توجد نتائج مطابقة</h3>
                <p>جرّبي تغيير كلمة البحث أو اختيار تصنيف آخر.</p>
            </div>
        `;
    } else {
        grid.innerHTML = filtered.map((m, index) => {
            const isFav = favorites.has(m.id);
            return `
                <div class="major-card" style="animation-delay: ${index * 0.08}s">
                    <div>
                        <span class="category-tag">${escapeHtml(m.cat)}</span>
                        <h3>${escapeHtml(m.name)}</h3>
                        <p>${escapeHtml(m.desc).substring(0, 120)}...</p>
                    </div>
                    <div class="card-footer">
                        <span class="view-btn" onclick="showDetails(${m.id})">التفاصيل <i class="fas fa-arrow-left"></i></span>
                        <button class="fav-btn ${isFav ? "active" : ""}" onclick="toggleFavorite(${m.id})" title="المفضلة">
                            <i class="${isFav ? "fas" : "far"} fa-heart"></i>
                        </button>
                    </div>
                </div>
            `;
        }).join("");
    }

    updateStats();
}

function updateStats() {
    document.getElementById("count-all").innerText = db.length;
    document.getElementById("count-tech").innerText = db.filter((m) => m.cat === "تقني").length;
    document.getElementById("count-health").innerText = db.filter((m) => m.cat === "صحي").length;
}

function toggleFavorite(id) {
    if (!guardAuth()) return;
    if (favorites.has(id)) favorites.delete(id); else favorites.add(id);
    saveAll();
    refreshUI();
}

function showDetails(id) {
    if (!guardAuth()) return;
    const item = db.find((m) => m.id === id);
    if (!item) return;

    const body = document.getElementById("modal-body");
    body.innerHTML = `
        <span class="category-tag" style="background: var(--primary); color: var(--bg-dark)">${escapeHtml(item.cat)}</span>
        <h2 style="font-size: 2rem; margin: 15px 0;">${escapeHtml(item.name)}</h2>
        <p style="color: var(--text-dim); margin-bottom: 25px; font-size: 1.1rem;">${escapeHtml(item.desc)}</p>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div class="glass-panel" style="padding: 15px;">
                <i class="fas fa-money-bill-wave" style="color: var(--success)"></i>
                <h5 style="margin-top: 10px;">متوسط الرواتب</h5>
                <p style="color: var(--primary)">${escapeHtml(item.salary || "8k - 15k")}</p>
            </div>
            <div class="glass-panel" style="padding: 15px;">
                <i class="fas fa-tools" style="color: var(--primary)"></i>
                <h5 style="margin-top: 10px;">المهارات المطلوبة</h5>
                <p style="font-size: 0.8rem;">${escapeHtml(item.skills || "تفكير نقدي، لغة إنجليزية")}</p>
            </div>
        </div>
        <button class="submit-btn" style="margin-top: 30px;" onclick="document.getElementById('modal').style.display='none'">إغلاق النافذة</button>
    `;
    document.getElementById("modal").style.display = "flex";
}

function closeModal(e) {
    if (!e || e.target.className === "modal-overlay") {
        const modal = document.getElementById("modal");
        if (modal) modal.style.display = "none";
    }
}

function setAdminSession() {
    setSession(LOGIN_USERNAME, "admin");
}

function showAdminState(state) {
    const login = document.getElementById("admin-login");
    const unlock = document.getElementById("admin-unlock");
    const page = document.getElementById("admin-page");
    if (!login || !unlock || !page) return;
    login.style.display = state === "login" ? "flex" : "none";
    unlock.style.display = state === "unlock" ? "flex" : "none";
    page.style.display = state === "page" ? "block" : "none";
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
    const usersList = parseJSON(USERS_KEY, []);
    const security = parseJSON(SECURITY_KEY, { failedByUser: {} });
    const failed = Object.values(security.failedByUser || {}).reduce((sum, item) => sum + (item.attempts || 0), 0);

    const elMajors = document.getElementById("admin-stats-majors");
    const elUsers = document.getElementById("admin-stats-users");
    const elFails = document.getElementById("admin-stats-fails");
    const elUpdated = document.getElementById("admin-stats-updated");
    if (!elMajors || !elUsers || !elFails || !elUpdated) return;

    elMajors.innerText = String(db.length);
    elUsers.innerText = String(usersList.length);
    elFails.innerText = String(failed);
    elUpdated.innerText = new Date().toLocaleTimeString("ar-SA", { hour: "2-digit", minute: "2-digit" });
}

function renderAdminTable() {
    const adminBody = document.getElementById("admin-table-body");
    if (!adminBody) return;
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

function verifyAdminSecret() {
    const inputEl = document.getElementById("admin-secret-input");
    const err = document.getElementById("admin-unlock-error");
    if (!inputEl || !err) return;
    const input = inputEl.value.trim();
    err.textContent = "";

    if (input !== ADMIN_SECRET_CODE) {
        err.textContent = "الكود السري غير صحيح.";
        appendAdminLog("secret_fail");
        return;
    }
    sessionStorage.setItem(ADMIN_SECRET_SESSION_KEY, ADMIN_SECRET_CODE);
    appendAdminLog("secret_pass");
    showAdminState("page");
    renderAdminTable();
    renderAdminStats();
}

function handleAdminLogin() {
    const userEl = document.getElementById("admin-login-user");
    const passEl = document.getElementById("admin-login-pass");
    const secretEl = document.getElementById("admin-login-secret");
    const err = document.getElementById("admin-login-error");
    if (!userEl || !passEl || !secretEl || !err) return;

    const user = userEl.value.trim();
    const pass = passEl.value;
    const secret = secretEl.value.trim();
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

    clearFailedAttempts(LOGIN_USERNAME);
    setAdminSession();
    sessionStorage.setItem(ADMIN_SECRET_SESSION_KEY, ADMIN_SECRET_CODE);
    appendAdminLog("admin_login_success", user);
    showAdminState("page");
    renderAdminTable();
    renderAdminStats();
}

function verifyAdminAccess() {
    if (!isAuthenticated() || !isAdmin()) {
        showAdminState("login");
        return;
    }
    const secretOk = sessionStorage.getItem(ADMIN_SECRET_SESSION_KEY) === ADMIN_SECRET_CODE;
    if (!secretOk) {
        showAdminState("unlock");
        return;
    }
    showAdminState("page");
    renderAdminTable();
    renderAdminStats();
    refreshSessionTTL();
}

function handle_Add() {
    if (!isAuthenticated() || !isAdmin()) {
        showAdminState("login");
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

    saveDbOnly();
    appendAdminLog("major_add", name);
    renderAdminTable();
    renderAdminStats();
    document.getElementById("m-name").value = "";
    document.getElementById("m-desc").value = "";
}

function handle_Delete(id) {
    if (!isAuthenticated() || !isAdmin()) {
        showAdminState("login");
        return;
    }

    const item = db.find((m) => m.id === id);
    if (!item) return;

    if (confirm(`هل أنتِ متأكدة من حذف "${item.name}"؟`)) {
        db = db.filter((m) => m.id !== id);
        saveDbOnly();
        appendAdminLog("major_delete", item.name);
        renderAdminTable();
        renderAdminStats();
    }
}

function logoutAdmin() {
    logout();
    window.location.href = "index.html";
}

function initAdminSecretPage() {
    verifyAdminAccess();
}

window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();

    const authGate = document.getElementById("auth-gate");
    if (e.key === "Enter" && authGate && authGate.style.display === "flex") {
        handleLogin();
    }

    const adminLogin = document.getElementById("admin-login");
    if (e.key === "Enter" && adminLogin && adminLogin.style.display === "flex") {
        handleAdminLogin();
    }

    const adminUnlock = document.getElementById("admin-unlock");
    if (e.key === "Enter" && adminUnlock && adminUnlock.style.display === "flex") {
        verifyAdminSecret();
    }
});

window.addEventListener("hashchange", () => {
    if (!IS_ADMIN_PAGE) bootApp();
});
["click", "keydown", "mousemove", "touchstart"].forEach((evt) => {
    window.addEventListener(evt, refreshSessionTTL, { passive: true });
});

setupRealtimeSync();
if (IS_ADMIN_PAGE) {
    initAdminSecretPage();
} else {
    bootApp();
}
