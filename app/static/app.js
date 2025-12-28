const state = {
    me: null,
    vlans: [],
    currentVlan: null,
    filterText: "",
    filterType: "all",
    dark: true,
    loading: new Set(), // Track active loading operations
    viewMode: "table" // "table" or "card" for mobile responsiveness
  };
  
  function el(html) {
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }

  // Loading state management
  function setLoading(key, isLoading) {
    if (isLoading) {
      state.loading.add(key);
    } else {
      state.loading.delete(key);
    }
    // Trigger custom event for components that need to react to loading changes
    window.dispatchEvent(new CustomEvent('loadingchange', { detail: { key, isLoading } }));
  }

  function isLoading(key) {
    return state.loading.has(key);
  }

  // Spinner component
  function spinner(size = "w-4 h-4") {
    return el(`
      <svg class="${size} animate-spin text-zinc-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
    `);
  }

  // Skeleton loader for cards
  function skeletonCard() {
    return el(`
      <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-4 animate-pulse">
        <div class="flex items-start justify-between gap-3">
          <div class="flex-1">
            <div class="h-5 bg-zinc-800 rounded w-32 mb-2"></div>
            <div class="h-4 bg-zinc-800 rounded w-48"></div>
          </div>
          <div class="h-4 bg-zinc-800 rounded w-12"></div>
        </div>
        <div class="mt-3 h-2 bg-zinc-800 rounded-full"></div>
        <div class="mt-3 flex gap-3">
          <div class="h-4 bg-zinc-800 rounded w-16"></div>
          <div class="h-4 bg-zinc-800 rounded w-20"></div>
        </div>
      </div>
    `);
  }

  // Skeleton loader for table rows
  function skeletonTableRow() {
    return el(`
      <tr class="border-b border-zinc-900">
        <td class="p-3"><div class="w-8 h-8 bg-zinc-800 rounded-md animate-pulse"></div></td>
        <td class="p-3"><div class="h-4 bg-zinc-800 rounded w-24 animate-pulse"></div></td>
        <td class="p-3"><div class="h-4 bg-zinc-800 rounded w-32 animate-pulse"></div></td>
        <td class="p-3"><div class="h-5 bg-zinc-800 rounded-full w-16 animate-pulse"></div></td>
        <td class="p-3"><div class="h-5 bg-zinc-800 rounded-full w-20 animate-pulse"></div></td>
        <td class="p-3"><div class="h-4 bg-zinc-800 rounded w-40 animate-pulse"></div></td>
        <td class="p-3 text-right">
          <div class="flex gap-2 justify-end">
            <div class="w-6 h-6 bg-zinc-800 rounded animate-pulse"></div>
            <div class="w-6 h-6 bg-zinc-800 rounded animate-pulse"></div>
          </div>
        </td>
      </tr>
    `);
  }

  // Helper to set button loading state
  function setButtonLoading(button, isLoading, originalText = null) {
    if (!button) return;
    
    if (isLoading) {
      button.dataset.originalText = originalText || button.textContent.trim();
      button.disabled = true;
      button.classList.add("opacity-50", "cursor-not-allowed");
      
      // Add spinner if not already present
      if (!button.querySelector(".spinner")) {
        const sp = spinner("w-4 h-4");
        sp.classList.add("spinner", "inline-block", "mr-2");
        button.insertBefore(sp, button.firstChild);
      }
    } else {
      button.disabled = false;
      button.classList.remove("opacity-50", "cursor-not-allowed");
      
      // Remove spinner
      const sp = button.querySelector(".spinner");
      if (sp) sp.remove();
      
      // Restore original text if available
      if (button.dataset.originalText) {
        button.textContent = button.dataset.originalText;
        delete button.dataset.originalText;
      }
    }
  }
  
  function getCsrfToken() {
    // Read CSRF token from cookie
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        return value;
      }
    }
    return null;
  }

  async function api(path, { method="GET", body=null, headers={}, loadingKey=null } = {}) {
    const loadingId = loadingKey || path;
    
    try {
      setLoading(loadingId, true);
      
      const opts = { method, headers: { ...headers } };
      
      // Add CSRF token header for state-changing requests
      if (method !== "GET" && method !== "HEAD") {
        const csrfToken = getCsrfToken();
        if (csrfToken) {
          opts.headers["X-CSRF-Token"] = csrfToken;
        }
      }
      
      if (body && !(body instanceof FormData)) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      } else if (body instanceof FormData) {
        opts.body = body;
      }
      const res = await fetch(path, opts);
      const text = await res.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch {}
      if (!res.ok) {
        const msg = json?.detail || json?.message || text || `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return json;
    } finally {
      setLoading(loadingId, false);
    }
  }
  
  // Enhanced Toast Notification System
  const toastState = {
    container: null,
    queue: [],
    maxVisible: 5,
    defaultDuration: 3000
  };

  function initToastContainer() {
    if (!toastState.container) {
      toastState.container = el(`
        <div class="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none" style="max-width: 400px;"></div>
      `);
      document.body.appendChild(toastState.container);
    }
    return toastState.container;
  }

  function getToastTypeStyles(type) {
    const styles = {
      success: {
        bg: "bg-green-600",
        border: "border-green-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
        </svg>`
      },
      error: {
        bg: "bg-red-600",
        border: "border-red-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
        </svg>`
      },
      warning: {
        bg: "bg-yellow-600",
        border: "border-yellow-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
        </svg>`
      },
      info: {
        bg: "bg-blue-600",
        border: "border-blue-500",
        icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>`
      },
      default: {
        bg: "bg-zinc-800",
        border: "border-zinc-700",
        icon: ""
      }
    };
    return styles[type] || styles.default;
  }

  function createToastElement(id, message, type, duration, action) {
    const styles = getToastTypeStyles(type);
    const hasAction = action && action.label && action.onClick;
    
    const toastEl = el(`
      <div 
        data-toast-id="${id}"
        class="pointer-events-auto bg-zinc-900 border ${styles.border} rounded-lg shadow-xl overflow-hidden"
        style="animation: slideIn 0.3s ease-out forwards;"
      >
        <div class="flex items-start gap-3 p-3">
          ${styles.icon ? `<div class="${styles.bg} rounded-full p-1.5 flex-shrink-0 text-white">${styles.icon}</div>` : ''}
          <div class="flex-1 min-w-0">
            <div class="text-sm text-zinc-100">${escapeHtml(message)}</div>
            ${hasAction ? `
              <div class="mt-2 flex gap-2">
                <button 
                  data-action-btn
                  class="text-xs px-3 py-1.5 rounded-md font-medium transition ${styles.bg} text-white hover:opacity-90"
                >
                  ${escapeHtml(action.label)}
                </button>
              </div>
            ` : ''}
          </div>
          <button 
            data-close-btn
            class="flex-shrink-0 text-zinc-400 hover:text-zinc-200 transition p-1"
            aria-label="Close"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>
        ${duration > 0 ? `
          <div class="h-1 bg-zinc-800">
            <div 
              data-progress-bar
              class="h-full ${styles.bg} transition-all linear"
              style="width: 100%;"
            ></div>
          </div>
        ` : ''}
      </div>
    `);

    // Add CSS animation if not already added
    if (!document.getElementById('toast-animations')) {
      const style = document.createElement('style');
      style.id = 'toast-animations';
      style.textContent = `
        @keyframes slideIn {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        @keyframes slideOut {
          from {
            transform: translateX(0);
            opacity: 1;
          }
          to {
            transform: translateX(100%);
            opacity: 0;
          }
        }
      `;
      document.head.appendChild(style);
    }

    return toastEl;
  }

  function showToast(id, message, type, duration, action) {
    const container = initToastContainer();
    const toastEl = createToastElement(id, message, type, duration, action);
    container.appendChild(toastEl);

    // Handle action button
    const actionBtn = toastEl.querySelector('[data-action-btn]');
    if (actionBtn && action && action.onClick) {
      actionBtn.onclick = () => {
        action.onClick();
        dismissToast(id);
      };
    }

    // Handle close button
    const closeBtn = toastEl.querySelector('[data-close-btn]');
    if (closeBtn) {
      closeBtn.onclick = () => dismissToast(id);
    }

    // Auto-dismiss with progress
    if (duration > 0) {
      const progressBar = toastEl.querySelector('[data-progress-bar]');
      const startTime = Date.now();
      const updateProgress = () => {
        const elapsed = Date.now() - startTime;
        const remaining = Math.max(0, duration - elapsed);
        const progress = (remaining / duration) * 100;
        
        if (progressBar) {
          progressBar.style.width = `${progress}%`;
        }
        
        if (remaining > 0) {
          requestAnimationFrame(updateProgress);
        } else {
          dismissToast(id);
        }
      };
      requestAnimationFrame(updateProgress);
    }

    return id;
  }

  function dismissToast(id) {
    const container = toastState.container;
    if (!container) return;
    
    const toastEl = container.querySelector(`[data-toast-id="${id}"]`);
    if (!toastEl) return;

    // Animate out
    toastEl.style.animation = 'slideOut 0.3s ease-out forwards';
    
    setTimeout(() => {
      toastEl.remove();
      processToastQueue();
    }, 300);
  }

  function processToastQueue() {
    const container = toastState.container;
    if (!container) return;

    const visible = container.querySelectorAll('[data-toast-id]').length;
    const available = toastState.maxVisible - visible;

    while (toastState.queue.length > 0 && available > 0) {
      const item = toastState.queue.shift();
      showToast(item.id, item.message, item.type, item.duration, item.action);
    }
  }

  function toast(message, options = {}) {
    const {
      type = 'default',
      duration = toastState.defaultDuration,
      action = null
    } = options;

    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const container = initToastContainer();
    const visible = container.querySelectorAll('[data-toast-id]').length;

    if (visible >= toastState.maxVisible) {
      // Add to queue
      toastState.queue.push({ id, message, type, duration, action });
    } else {
      // Show immediately
      showToast(id, message, type, duration, action);
    }

    return id;
  }
  
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, m => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" }[m]));
  }
  
  function setRoute(hash) {
    location.hash = hash;
  }
  
  function route() {
    const h = location.hash.replace("#", "");
    if (!state.me) return renderLogin();
    if (state.me && state.me.password_change_required) {
      showPasswordChangeModal();
      return;
    }
    if (!h || h === "/") return renderVlanList();
    if (h.startsWith("/vlan/")) {
      const id = h.split("/")[2];
      return renderVlanDetail(id);
    }
    if (h === "/audit-logs") return renderAuditLogs();
    renderVlanList();
  }
  
  async function init() {
    try {
      state.me = await api("/api/me", { loadingKey: "init-me" });
      if (state.me && state.me.password_change_required) {
        showPasswordChangeModal();
      }
    } catch {
      state.me = null;
    }
    window.addEventListener("hashchange", route);
    // Handle window resize to update view mode on mobile
    window.addEventListener("resize", () => {
      if (state.currentVlan) {
        const tbody = document.querySelector("#rows");
        if (tbody) {
          renderRows(tbody, state.currentVlan);
        }
      }
    });
    route();
  }
  
  function showPasswordChangeModal() {
    const m = modalShell("Setup Required", `
      <div class="space-y-3">
        <div class="text-sm text-zinc-300">
          You are logging in with the default admin account. Please choose a new username and password.
        </div>
        <div>
          <label class="text-xs text-zinc-400">New Username</label>
          <input id="newUsername" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div>
          <label class="text-xs text-zinc-400">Current Password</label>
          <input id="currentPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div>
          <label class="text-xs text-zinc-400">New Password</label>
          <input id="newPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          <div class="text-xs text-zinc-500 mt-1">Must be at least 8 characters</div>
        </div>
        <div>
          <label class="text-xs text-zinc-400">Confirm New Password</label>
          <input id="confirmPassword" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="save" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>
            Save
          </button>
        </div>
      </div>
    `);
    
    // Prevent closing the modal until password is changed
    const closeBtn = m.querySelector("#close");
    if (closeBtn) closeBtn.style.display = "none";
    m.onclick = null; // Disable click-outside-to-close
    
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      const newUsername = m.querySelector("#newUsername").value.trim();
      const currentPassword = m.querySelector("#currentPassword").value;
      const newPassword = m.querySelector("#newPassword").value;
      const confirmPassword = m.querySelector("#confirmPassword").value;
      
      setButtonLoading(saveBtn, true, "Save");
      
      try {
        if (!newUsername || newUsername.length < 3) {
          throw new Error("Username must be at least 3 characters");
        }
        if (!newPassword || newPassword.length < 8) {
          throw new Error("Password must be at least 8 characters");
        }
        if (newPassword !== confirmPassword) {
          throw new Error("Passwords do not match");
        }
        
        // Change username first
        await api("/api/auth/change-username", { method:"POST", body:{ new_username: newUsername }, loadingKey: "change-username" });
        
        // Then change password
        await api("/api/auth/change-password", { method:"POST", body:{ current_password: currentPassword, new_password: newPassword }, loadingKey: "change-password" });
        
        // Refresh user info
        state.me = await api("/api/me", { loadingKey: "me" });
        
        toast("Username and password updated", { type: "success" });
        m.remove();
        setRoute("#/");
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }
  
  function appRoot() {
    return document.getElementById("app");
  }
  
  function topbar() {
    const isAdmin = state.me && state.me.role === "admin";
    return el(`
      <div class="sticky top-0 z-10 bg-zinc-950/80 backdrop-blur border-b border-zinc-800">
        <div class="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <div class="font-semibold tracking-tight">Mini-IPAM</div>
          <div class="text-xs text-zinc-400">VLAN IP Tracker</div>
          <div class="flex-1"></div>
          ${isAdmin ? '<button id="iconLibraryBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium transition-all duration-200 hover:scale-[1.02]">Icon Library</button>' : ''}
          ${isAdmin ? '<button id="createUserBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium flex items-center gap-2 transition-all duration-200">' + 
            '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>' +
            '<span>Create User</span></button>' : ''}
          <button id="auditLogsBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium transition-all duration-200 hover:scale-[1.02]">Audit Logs</button>
          <button id="exportBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium transition-all duration-200 hover:scale-[1.02]">Export</button>
          <button id="logoutBtn" class="text-xs sm:text-sm px-3 sm:px-4 py-2 sm:py-2.5 rounded-md border border-zinc-800 hover:bg-zinc-900 min-h-[44px] font-medium transition-all duration-200 hover:scale-[1.02]">Logout</button>
        </div>
      </div>
    `);
  }
  
  function renderLogin() {
    const root = appRoot();
    root.innerHTML = "";
    const node = el(`
      <div class="min-h-full flex items-center justify-center p-6">
        <div class="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-2xl p-6 shadow-xl">
          <div class="text-lg font-semibold">Sign in</div>
          <div class="text-sm text-zinc-400 mt-1">Log in with your credentials.</div>
  
          <div class="mt-5 space-y-3">
            <div>
              <label class="text-xs text-zinc-400">Username</label>
              <input id="u" placeholder="Enter your username" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 placeholder:text-zinc-600" />
            </div>
            <div>
              <label class="text-xs text-zinc-400">Password</label>
              <input id="p" type="password" placeholder="Enter your password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 placeholder:text-zinc-600" />
            </div>
            <button id="loginBtn" class="w-full mt-2 bg-white text-zinc-900 rounded-lg px-3 py-2.5 font-medium hover:opacity-90 min-h-[44px]">
              Login
            </button>
          </div>
        </div>
      </div>
    `);
    root.appendChild(node);

    const usernameInput = node.querySelector("#u");
    const passwordInput = node.querySelector("#p");
    const loginBtn = node.querySelector("#loginBtn");

    const performLogin = async () => {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      
      if (!username || !password) {
        toast("Please enter username and password", { type: "warning" });
        return;
      }
      
      setButtonLoading(loginBtn, true, "Login");
      
      try {
        const res = await api("/api/auth/login", { method:"POST", body:{ username, password }, loadingKey: "login" });
        state.me = res.user;
        
        if (res.user.password_change_required) {
          showPasswordChangeModal();
        } else {
          toast("Logged in", { type: "success" });
          setRoute("#/");
          route();
        }
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(loginBtn, false);
      }
    };

    loginBtn.onclick = performLogin;

    // Allow Enter key to submit login form
    const handleEnterKey = (e) => {
      if (e.key === "Enter") {
        performLogin();
      }
    };
    usernameInput.addEventListener("keydown", handleEnterKey);
    passwordInput.addEventListener("keydown", handleEnterKey);
  }
  
  async function loadVlans() {
    state.vlans = await api("/api/vlans");
  }
  
  function renderVlanList() {
    const root = appRoot();
    root.innerHTML = "";
    const tb = topbar();
    root.appendChild(tb);
  
    tb.querySelector("#logoutBtn").onclick = async () => {
      const btn = tb.querySelector("#logoutBtn");
      setButtonLoading(btn, true, "Logout");
      try {
        await api("/api/auth/logout", { method:"POST", loadingKey: "logout" });
        state.me = null;
        toast("Logged out", { type: "success" });
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(btn, false);
      }
    };
    tb.querySelector("#exportBtn").onclick = () => {
      window.location.href = "/api/export/data";
    };
    const iconLibraryBtn = tb.querySelector("#iconLibraryBtn");
    if (iconLibraryBtn) {
      iconLibraryBtn.onclick = () => openIconLibraryModal();
    }
    const createUserBtn = tb.querySelector("#createUserBtn");
    if (createUserBtn) {
      createUserBtn.onclick = () => openCreateUserModal();
    }
    const auditLogsBtn = tb.querySelector("#auditLogsBtn");
    if (auditLogsBtn) {
      auditLogsBtn.onclick = () => setRoute("#/audit-logs");
    }

    const content = el(`
      <div class="max-w-6xl mx-auto px-4 py-6">
        <div class="flex items-end justify-between gap-3">
          <div>
            <div class="text-2xl font-semibold tracking-tight">VLANs</div>
            <div class="text-sm text-zinc-400">Track assigned IPs per subnet.</div>
          </div>
          <button id="createVlanBtn" class="bg-white text-zinc-900 rounded-lg px-4 py-2.5 font-medium hover:opacity-90 min-h-[44px] text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
            </svg>
            Create VLAN
          </button>
        </div>
  
        <div id="cards" class="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
      </div>
    `);
  
    root.appendChild(content);
  
    content.querySelector("#createVlanBtn").onclick = () => openVlanModal();
  
    (async () => {
      try {
        await loadVlans();
        renderVlanCards(content.querySelector("#cards"));
      } catch (e) {
        toast(e.message, { type: "error" });
      }
    })();
  }
  
  function meterBar(used, total) {
    const pct = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
    // Color thresholds: green < 50%, yellow 50-80%, red > 80%
    let colorClass = "bg-green-500";
    if (pct >= 80) {
      colorClass = "bg-red-500";
    } else if (pct >= 50) {
      colorClass = "bg-yellow-500";
    }
    return `
      <div class="h-2 rounded-full bg-zinc-800 overflow-hidden">
        <div class="h-2 ${colorClass}" style="width:${pct}%"></div>
      </div>
    `;
  }
  
  function renderVlanCards(container) {
    container.innerHTML = "";
    for (const v of state.vlans) {
      const used = v.derived.used;
      const total = v.derived.total_usable;
      const pct = total > 0 ? Math.round((used / total) * 100) : 0;
      const card = el(`
        <div class="relative bg-zinc-900 border border-zinc-800 rounded-2xl p-4 hover:bg-zinc-900/70 transition-all duration-200 hover:scale-[1.01] hover:border-zinc-700 animate-fadeIn">
          <button class="w-full text-left" data-card-btn>
            <div class="flex items-start justify-between gap-3">
              <div>
                <div class="font-semibold">${escapeHtml(v.name)}</div>
                <div class="text-xs text-zinc-400 mt-1">${escapeHtml(v.subnet_cidr)}${v.vlan_id ? ` · VLAN ${v.vlan_id}` : ""}</div>
              </div>
              <div class="text-right">
                <div class="text-xs text-zinc-400">${used}/${total}</div>
                <div class="text-xs font-medium text-zinc-300 mt-0.5">${pct}%</div>
              </div>
            </div>
            <div class="mt-3">${meterBar(used, total)}</div>
            <div class="mt-3 flex gap-3 text-xs text-zinc-400">
              <div><span class="text-zinc-200">${used}</span> used</div>
              <div><span class="text-zinc-200">${v.derived.reserved}</span> reserved</div>
            </div>
          </button>
          <button class="absolute bottom-3 right-3 px-4 py-2.5 text-sm bg-white text-zinc-900 rounded-lg font-medium hover:opacity-90 transition-all duration-200 hover:scale-[1.02] min-h-[44px] min-w-[44px] flex items-center justify-center gap-1.5" data-add-btn>
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
            </svg>
            <span class="hidden sm:inline">Add</span>
          </button>
        </div>
      `);
      card.querySelector("[data-card-btn]").onclick = () => setRoute(`#/vlan/${v.id}`);
      card.querySelector("[data-add-btn]").onclick = async (e) => {
        e.stopPropagation();
        const btn = e.target.closest("[data-add-btn]");
        setButtonLoading(btn, true, "+Add");
        try {
          const fullVlan = await api(`/api/vlans/${v.id}`, { loadingKey: `vlan-${v.id}` });
          openAssignmentModal(fullVlan);
        } catch (e) {
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(btn, false);
        }
      };
      container.appendChild(card);
    }
  }
  
  function modalShell(title, innerHtml) {
    const m = el(`
      <div class="fixed inset-0 z-50 flex items-center justify-center p-0 sm:p-4 bg-black/60 animate-fadeIn">
        <div class="w-full h-full sm:h-auto sm:max-w-xl bg-zinc-900 border-0 sm:border border-zinc-800 rounded-none sm:rounded-2xl shadow-2xl overflow-hidden flex flex-col animate-scaleIn">
          <div class="px-4 sm:px-5 py-4 border-b border-zinc-800 flex items-center justify-between flex-shrink-0">
            <div class="font-semibold text-lg">${escapeHtml(title)}</div>
            <button class="min-w-[44px] min-h-[44px] flex items-center justify-center text-zinc-400 hover:text-zinc-200 text-xl transition-all duration-200 hover:scale-110 hover:rotate-90" id="close">✕</button>
          </div>
          <div class="flex-1 overflow-y-auto p-4 sm:p-5">${innerHtml}</div>
        </div>
      </div>
    `);
    m.querySelector("#close").onclick = () => m.remove();
    m.onclick = (e) => { if (e.target === m) m.remove(); };
    document.body.appendChild(m);
    return m;
  }
  
  function openVlanModal(existing=null) {
    const isEdit = !!existing;
    const m = modalShell(isEdit ? "Edit VLAN" : "Create VLAN", `
      <div class="space-y-3">
        <div>
          <label class="text-xs text-zinc-400">Name</label>
          <input id="name" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label class="text-xs text-zinc-400">VLAN ID (optional)</label>
            <input id="vid" type="number" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          </div>
          <div>
            <label class="text-xs text-zinc-400">Subnet CIDR</label>
            <input id="cidr" placeholder="192.168.10.0/24" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 mono" />
          </div>
        </div>
        <div class="flex flex-col sm:flex-row justify-end gap-2 pt-2">
          <button id="cancel" class="min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm font-medium flex items-center gap-2 transition-all duration-200">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
            Cancel
          </button>
          <button id="save" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
            ${isEdit ? `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
              </svg>
              Save
            ` : `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
              </svg>
              Create
            `}
          </button>
        </div>
      </div>
    `);
  
    const name = m.querySelector("#name");
    const vid = m.querySelector("#vid");
    const cidr = m.querySelector("#cidr");
  
    if (existing) {
      name.value = existing.name;
      vid.value = existing.vlan_id ?? "";
      cidr.value = existing.subnet_cidr;
    }
  
    m.querySelector("#cancel").onclick = () => m.remove();
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      setButtonLoading(saveBtn, true);
      try {
        const payload = {
          name: name.value.trim(),
          vlan_id: vid.value ? parseInt(vid.value, 10) : null,
          subnet_cidr: cidr.value.trim()
        };
        if (!payload.name || !payload.subnet_cidr) throw new Error("Name and CIDR are required");

        if (!existing) {
          await api("/api/vlans", { method:"POST", body: payload, loadingKey: "create-vlan" });
          toast("VLAN created", { type: "success" });
        } else {
          await api(`/api/vlans/${existing.id}`, { method:"PATCH", body: payload, loadingKey: "update-vlan" });
          toast("VLAN updated", { type: "success" });
        }
        m.remove();
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }
  
  async function renderVlanDetail(vlanId) {
    const root = appRoot();
    root.innerHTML = "";
    const tb = topbar();
    root.appendChild(tb);
  
    tb.querySelector("#logoutBtn").onclick = async () => {
      const btn = tb.querySelector("#logoutBtn");
      setButtonLoading(btn, true, "Logout");
      try {
        await api("/api/auth/logout", { method:"POST", loadingKey: "logout" });
        state.me = null;
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(btn, false);
      }
    };
    tb.querySelector("#exportBtn").onclick = () => window.location.href = "/api/export/data";
    const iconLibraryBtn = tb.querySelector("#iconLibraryBtn");
    if (iconLibraryBtn) {
      iconLibraryBtn.onclick = () => openIconLibraryModal();
    }
    const createUserBtn = tb.querySelector("#createUserBtn");
    if (createUserBtn) {
      createUserBtn.onclick = () => openCreateUserModal();
    }
    const auditLogsBtn = tb.querySelector("#auditLogsBtn");
    if (auditLogsBtn) {
      auditLogsBtn.onclick = () => setRoute("#/audit-logs");
    }

    const wrap = el(`
      <div class="max-w-6xl mx-auto px-4 py-6">
        <button id="back" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm text-zinc-200 hover:text-zinc-100 min-h-[44px] font-medium transition-all duration-200 hover:scale-[1.02] flex items-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
          </svg>
          Back
        </button>

        <div id="header" class="mt-4"></div>

        <div class="mt-6 space-y-3">
          <div class="flex flex-col sm:flex-row gap-3">
            <input id="search" placeholder="Search IP / hostname / tag / notes..." class="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2.5 outline-none focus:border-zinc-600 min-h-[44px]" />
            <select id="typeFilter" class="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2.5 outline-none focus:border-zinc-600 min-h-[44px]">
              <option value="all">All types</option>
            </select>
          </div>
          <div class="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
            <button id="nextBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm font-medium transition-all duration-200 hover:scale-[1.02]">Next available</button>
            <button id="addBtn" class="px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 min-h-[44px] text-sm flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
              </svg>
              Add
            </button>
            <div class="flex gap-2">
              <div class="relative">
                <button id="exportBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                  </svg>
                  Export
                </button>
                <div id="exportMenu" class="hidden absolute top-full mt-1 right-0 bg-zinc-900 border border-zinc-800 rounded-lg shadow-lg z-50 min-w-[120px] animate-slideUp">
                  <button class="exportFormatBtn w-full text-left px-4 py-2 hover:bg-zinc-800 text-sm transition-all duration-200" data-format="csv">CSV</button>
                  <button class="exportFormatBtn w-full text-left px-4 py-2 hover:bg-zinc-800 text-sm transition-all duration-200" data-format="json">JSON</button>
                  <button class="exportFormatBtn w-full text-left px-4 py-2 hover:bg-zinc-800 text-sm transition-all duration-200" data-format="excel">Excel</button>
                </div>
              </div>
              <button id="importBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm font-medium flex items-center gap-2 transition-all duration-200 hover:scale-[1.02]">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                </svg>
                Import
              </button>
            </div>
            <div class="flex-1"></div>
            <button id="viewToggle" class="md:hidden px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 min-h-[44px] text-sm flex items-center justify-center gap-2 transition-all duration-200 hover:scale-[1.02]">
              <span id="viewToggleText">Card View</span>
              <svg id="viewToggleIcon" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path>
              </svg>
            </button>
          </div>
        </div>

        <div id="tableContainer" class="mt-4 overflow-hidden rounded-2xl border border-zinc-800 hidden md:block">
          <table class="w-full text-sm">
            <thead class="bg-zinc-900 border-b border-zinc-800 text-zinc-300">
              <tr>
                <th class="text-left p-3 w-12">Icon</th>
                <th class="text-left p-3 mono">IP</th>
                <th class="text-left p-3">Hostname/Service</th>
                <th class="text-left p-3">Type</th>
                <th class="text-left p-3">Tags</th>
                <th class="text-left p-3">Notes</th>
                <th class="text-right p-3 w-24">Actions</th>
              </tr>
            </thead>
            <tbody id="rows" class="bg-zinc-950"></tbody>
          </table>
        </div>
        <div id="cardContainer" class="mt-4 space-y-3 md:hidden"></div>
      </div>
    `);

    root.appendChild(wrap);
    wrap.querySelector("#back").onclick = () => setRoute("#/");

    // Show skeleton loaders while fetching
    const tbody = wrap.querySelector("#rows");
    const cardContainer = wrap.querySelector("#cardContainer");
    for (let i = 0; i < 5; i++) {
      tbody.appendChild(skeletonTableRow());
      if (cardContainer) {
        cardContainer.appendChild(skeletonCard());
      }
    }

    let vlan;
    try {
      vlan = await api(`/api/vlans/${vlanId}`, { loadingKey: `vlan-${vlanId}` });
      state.currentVlan = vlan;
    } catch (e) {
      tbody.innerHTML = `<tr><td class="p-4 text-zinc-500 text-center" colspan="7">Failed to load VLAN: ${escapeHtml(e.message)}</td></tr>`;
      if (cardContainer) {
        cardContainer.innerHTML = `<div class="p-4 text-zinc-500 text-center bg-zinc-900 border border-zinc-800 rounded-lg">Failed to load VLAN: ${escapeHtml(e.message)}</div>`;
      }
      toast(e.message);
      return;
    }
  
    // populate type filter options
    const settings = await api("/api/settings");
    const typeSel = wrap.querySelector("#typeFilter");
    for (const t of settings.type_options) {
      typeSel.appendChild(el(`<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`));
    }
  
    wrap.querySelector("#search").oninput = (e) => {
      state.filterText = e.target.value;
      renderRows(wrap.querySelector("#rows"), vlan);
    };
    typeSel.onchange = (e) => {
      state.filterType = e.target.value;
      renderRows(wrap.querySelector("#rows"), vlan);
    };
  
    const addBtn = wrap.querySelector("#addBtn");
    const nextBtn = wrap.querySelector("#nextBtn");
    const totalUsable = vlan.derived?.total_usable ?? 0;
    
    // Disable assignment buttons if no usable hosts
    if (totalUsable === 0) {
      addBtn.disabled = true;
      addBtn.classList.add("opacity-50", "cursor-not-allowed");
      addBtn.title = "No usable hosts in this subnet";
      nextBtn.disabled = true;
      nextBtn.classList.add("opacity-50", "cursor-not-allowed");
      nextBtn.title = "No usable hosts in this subnet";
    }
    
    addBtn.onclick = () => {
      if (totalUsable === 0) {
        toast("No usable hosts in this subnet (/31 and /32 subnets cannot have assignments)", { type: "error" });
        return;
      }
      openAssignmentModal(vlan);
    };
    nextBtn.onclick = async () => {
      if (totalUsable === 0) {
        toast("No usable hosts in this subnet (/31 and /32 subnets cannot have assignments)", { type: "error" });
        return;
      }
      setButtonLoading(nextBtn, true, "Next available");
      try {
        const res = await api(`/api/vlans/${vlan.id}/next-available`, { loadingKey: `next-ip-${vlan.id}` });
        if (!res.ip) {
          toast("No available IP found", { type: "info" });
          return;
        }
        openAssignmentModal(vlan, null, { presetIp: res.ip });
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(nextBtn, false);
      }
    };

    // Export button handler
    const exportBtn = wrap.querySelector("#exportBtn");
    const exportMenu = wrap.querySelector("#exportMenu");
    let exportMenuOpen = false;
    
    exportBtn.onclick = (e) => {
      e.stopPropagation();
      exportMenuOpen = !exportMenuOpen;
      exportMenu.classList.toggle("hidden", !exportMenuOpen);
    };
    
    // Close export menu when clicking outside
    document.addEventListener("click", (e) => {
      if (!exportBtn.contains(e.target) && !exportMenu.contains(e.target)) {
        exportMenuOpen = false;
        exportMenu.classList.add("hidden");
      }
    });
    
    // Export format handlers
    wrap.querySelectorAll(".exportFormatBtn").forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        exportMenuOpen = false;
        exportMenu.classList.add("hidden");
        
        const format = btn.dataset.format;
        const search = (state.filterText || "").trim() || null;
        const typeFilter = state.filterType && state.filterType !== "all" ? state.filterType : null;
        
        try {
          const params = new URLSearchParams({ format });
          if (search) params.append("search", search);
          if (typeFilter) params.append("type_filter", typeFilter);
          
          const url = `/api/vlans/${vlan.id}/assignments/export?${params.toString()}`;
          window.location.href = url;
          toast(`Exporting as ${format.toUpperCase()}...`, { type: "info" });
        } catch (e) {
          toast(e.message, { type: "error" });
        }
      };
    });
    
    // Import button handler
    const importBtn = wrap.querySelector("#importBtn");
    importBtn.onclick = () => openImportModal(vlan);

    // View toggle handler (only on mobile)
    const viewToggle = wrap.querySelector("#viewToggle");
    if (viewToggle) {
      // Initialize view mode based on screen size
      const isMobile = window.innerWidth < 768;
      if (isMobile && state.viewMode === "table") {
        state.viewMode = "card"; // Default to card view on mobile
      }
      
      const updateViewToggle = () => {
        const isTable = state.viewMode === "table";
        const toggleText = wrap.querySelector("#viewToggleText");
        const toggleIcon = wrap.querySelector("#viewToggleIcon");
        if (isTable) {
          toggleText.textContent = "Card View";
          toggleIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path>';
        } else {
          toggleText.textContent = "Table View";
          toggleIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path>';
        }
      };
      viewToggle.onclick = () => {
        state.viewMode = state.viewMode === "table" ? "card" : "table";
        updateViewToggle();
        renderRows(wrap.querySelector("#rows"), vlan);
      };
      updateViewToggle();
    }

    renderVlanHeader(wrap.querySelector("#header"), vlan);
    renderRows(wrap.querySelector("#rows"), vlan);
  }
  
  function ipToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }

  function intToIp(int) {
    return [
      (int >>> 24) & 255,
      (int >>> 16) & 255,
      (int >>> 8) & 255,
      int & 255
    ].join('.');
  }

  function renderIpRangeMap(container, vlan) {
    const d = vlan.derived;
    const usedSet = new Set(vlan.used_effective || []);
    const reservedSet = new Set(vlan.reserved_effective || []);
    
    const startInt = ipToInt(d.usable_start);
    const endInt = ipToInt(d.usable_end);
    const total = endInt - startInt + 1;
    
    // Limit visualization to reasonable size (max 256 IPs for performance)
    const maxDisplay = 256;
    const step = total > maxDisplay ? Math.ceil(total / maxDisplay) : 1;
    const displayCount = Math.ceil(total / step);
    
    const mapDiv = document.createElement("div");
    mapDiv.className = "mt-4 p-4 bg-zinc-900 border border-zinc-800 rounded-lg";
    
    const mapTitle = document.createElement("div");
    mapTitle.className = "text-xs text-zinc-400 mb-3";
    mapTitle.textContent = "IP Range Map";
    mapDiv.appendChild(mapTitle);
    
    const mapGrid = document.createElement("div");
    mapGrid.className = "flex flex-wrap gap-0.5";
    mapGrid.style.maxHeight = "120px";
    mapGrid.style.overflowY = "auto";
    
    for (let i = 0; i < displayCount; i++) {
      const ipInt = startInt + (i * step);
      if (ipInt > endInt) break;
      
      const ip = intToIp(ipInt);
      const isUsed = usedSet.has(ip);
      const isReserved = reservedSet.has(ip);
      
      const cell = document.createElement("div");
      cell.className = "w-2 h-2 rounded-sm";
      cell.title = `${ip} - ${isUsed ? 'Used' : isReserved ? 'Reserved' : 'Free'}`;
      
      if (isUsed) {
        cell.className += " bg-blue-500";
      } else if (isReserved) {
        cell.className += " bg-orange-500";
      } else {
        cell.className += " bg-zinc-700";
      }
      
      mapGrid.appendChild(cell);
    }
    
    mapDiv.appendChild(mapGrid);
    
    const legend = document.createElement("div");
    legend.className = "mt-3 flex flex-wrap gap-4 text-xs text-zinc-400";
    legend.innerHTML = `
      <div class="flex items-center gap-2">
        <div class="w-3 h-3 rounded-sm bg-blue-500"></div>
        <span>Used</span>
      </div>
      <div class="flex items-center gap-2">
        <div class="w-3 h-3 rounded-sm bg-orange-500"></div>
        <span>Reserved</span>
      </div>
      <div class="flex items-center gap-2">
        <div class="w-3 h-3 rounded-sm bg-zinc-700"></div>
        <span>Free</span>
      </div>
      ${total > maxDisplay ? `<span class="text-zinc-500">Showing ${displayCount} of ${total} IPs</span>` : ''}
    `;
    mapDiv.appendChild(legend);
    
    container.appendChild(mapDiv);
  }

  function renderVlanHeader(container, vlan) {
    const d = vlan.derived;
    const used = vlan.assignments.filter(a => !a.archived).length;
    const reserved = vlan.reserved_effective ? vlan.reserved_effective.length : 0;
    const total = d.total_usable;
    const pct = total > 0 ? Math.round((used / total) * 100) : 0;
    
    // Clear container
    container.innerHTML = "";
    
    // Create main wrapper
    const wrapper = document.createElement("div");
    wrapper.className = "flex flex-col md:flex-row md:items-end md:justify-between gap-3";
    
    // Left section
    const leftDiv = document.createElement("div");
    
    const titleDiv = document.createElement("div");
    titleDiv.className = "text-2xl font-semibold tracking-tight";
    titleDiv.textContent = vlan.name;
    leftDiv.appendChild(titleDiv);
    
    const infoDiv = document.createElement("div");
    infoDiv.className = "text-sm text-zinc-400 mt-1";
    
    const subnetSpan = document.createElement("span");
    subnetSpan.className = "mono";
    subnetSpan.textContent = vlan.subnet_cidr;
    infoDiv.appendChild(subnetSpan);
    
    if (vlan.vlan_id) {
      infoDiv.appendChild(document.createTextNode(` · VLAN ${vlan.vlan_id}`));
    }
    
    infoDiv.appendChild(document.createTextNode(" · GW "));
    
    const gwSpan = document.createElement("span");
    gwSpan.className = "mono";
    gwSpan.textContent = d.gateway_ip || d.gateway_suggested || "-";
    infoDiv.appendChild(gwSpan);
    
    leftDiv.appendChild(infoDiv);
    
    const usableDiv = document.createElement("div");
    usableDiv.className = "text-xs text-zinc-500 mt-1";
    
    if (total === 0) {
      usableDiv.appendChild(document.createTextNode("No usable hosts ("));
      const cidrSpan = document.createElement("span");
      cidrSpan.className = "mono text-orange-400";
      cidrSpan.textContent = "/31 or /32 subnet";
      usableDiv.appendChild(cidrSpan);
      usableDiv.appendChild(document.createTextNode(")"));
    } else {
      usableDiv.appendChild(document.createTextNode("Usable: "));
      
      const usableStartSpan = document.createElement("span");
      usableStartSpan.className = "mono";
      usableStartSpan.textContent = d.usable_start;
      usableDiv.appendChild(usableStartSpan);
      
      usableDiv.appendChild(document.createTextNode(" → "));
      
      const usableEndSpan = document.createElement("span");
      usableEndSpan.className = "mono";
      usableEndSpan.textContent = d.usable_end;
      usableDiv.appendChild(usableEndSpan);
      
      usableDiv.appendChild(document.createTextNode(` (${total})`));
    }
    leftDiv.appendChild(usableDiv);
    
    wrapper.appendChild(leftDiv);
    
    // Right section with enhanced breakdown
    const rightDiv = document.createElement("div");
    rightDiv.className = "min-w-[240px]";
    
    const statsDiv = document.createElement("div");
    statsDiv.className = "text-xs text-zinc-400 mb-3 space-y-1";
    statsDiv.innerHTML = `
      <div class="flex justify-between items-center">
        <span>Used:</span>
        <span class="text-zinc-200 font-medium">${used} (${pct}%)</span>
      </div>
      <div class="flex justify-between items-center">
        <span>Reserved:</span>
        <span class="text-zinc-200 font-medium">${reserved}</span>
      </div>
      <div class="flex justify-between items-center">
        <span>Free:</span>
        <span class="text-zinc-200 font-medium">${Math.max(0, total - used - reserved)}</span>
      </div>
    `;
    rightDiv.appendChild(statsDiv);
    
    // Enhanced breakdown with separate bars
    const breakdownDiv = document.createElement("div");
    breakdownDiv.className = "space-y-1.5";
    
    // Used bar
    const usedBarDiv = document.createElement("div");
    usedBarDiv.className = "relative h-2 rounded-full bg-zinc-800 overflow-hidden";
    const usedBarFill = document.createElement("div");
    usedBarFill.className = "h-2 bg-blue-500";
    usedBarFill.style.width = `${total > 0 ? Math.min(100, (used / total) * 100) : 0}%`;
    usedBarDiv.appendChild(usedBarFill);
    breakdownDiv.appendChild(usedBarDiv);
    
    // Reserved bar (stacked on top of used)
    if (reserved > 0) {
      const reservedBarDiv = document.createElement("div");
      reservedBarDiv.className = "relative h-2 rounded-full bg-zinc-800 overflow-hidden";
      const reservedBarFill = document.createElement("div");
      reservedBarFill.className = "h-2 bg-orange-500";
      reservedBarFill.style.width = `${total > 0 ? Math.min(100, (reserved / total) * 100) : 0}%`;
      reservedBarDiv.appendChild(reservedBarFill);
      breakdownDiv.appendChild(reservedBarDiv);
    }
    
    // Overall usage meter
    const overallMeter = el(meterBar(used, total));
    breakdownDiv.appendChild(overallMeter);
    
    rightDiv.appendChild(breakdownDiv);
    
    wrapper.appendChild(rightDiv);
    container.appendChild(wrapper);
    
    // Add IP range map below
    renderIpRangeMap(container, vlan);
  }
  
  function pill(text) {
    return `<span class="text-xs px-2 py-1 rounded-full border border-zinc-800 bg-zinc-900 transition-colors duration-150">${escapeHtml(text)}</span>`;
  }
  
  function tagChip(t) {
    return `<span class="text-xs px-2 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-200 transition-colors duration-150">${escapeHtml(t)}</span>`;
  }
  
  function matchesFilter(a) {
    const q = (state.filterText || "").trim().toLowerCase();
    const typeOk = state.filterType === "all" ? true : a.type === state.filterType;
    if (!typeOk) return false;
    if (!q) return !a.archived;
  
    const hay = [
      a.ip, a.hostname, a.type,
      ...(a.tags || []),
      a.notes || ""
    ].join(" ").toLowerCase();
    return !a.archived && hay.includes(q);
  }
  
  function renderRows(tbody, vlan) {
    const list = vlan.assignments.filter(matchesFilter).sort((x,y) => x.ip.localeCompare(y.ip));
    const cardContainer = document.querySelector("#cardContainer");
    const tableContainer = document.querySelector("#tableContainer");

    // Show/hide containers based on view mode and screen size
    const isMobile = window.innerWidth < 768; // md breakpoint
    const useCardView = isMobile ? (state.viewMode === "card") : false;
    
    if (useCardView) {
      tableContainer.classList.add("hidden");
      cardContainer.classList.remove("hidden");
      renderCards(cardContainer, list, vlan);
    } else {
      tableContainer.classList.remove("hidden");
      cardContainer.classList.add("hidden");
      renderTableRows(tbody, list, vlan);
    }
  }

  function renderTableRows(tbody, list, vlan) {
    tbody.innerHTML = "";
    
    if (list.length === 0) {
      tbody.appendChild(el(`<tr><td class="p-4 text-zinc-500 text-center" colspan="7">No assignments match your filters.</td></tr>`));
      return;
    }

    for (const a of list) {
      // Create icon cell using DOM methods
      const iconTd = document.createElement("td");
      iconTd.className = "p-3";
      if (a.icon?.data_base64) {
        const img = document.createElement("img");
        img.className = "w-8 h-8 rounded-md border border-zinc-800 object-cover object-center";
        // Escape mime_type to prevent XSS in data URI
        const safeMimeType = escapeHtml(a.icon.mime_type || "image/png");
        img.src = `data:${safeMimeType};base64,${a.icon.data_base64}`;
        iconTd.appendChild(img);
      } else {
        const div = document.createElement("div");
        div.className = "w-8 h-8 rounded-md border border-zinc-800 bg-zinc-900";
        iconTd.appendChild(div);
      }

      const tr = el(`
        <tr class="border-b border-zinc-900 hover:bg-zinc-900/30 transition-colors duration-150 animate-fadeIn">
          <td class="p-3 mono">${escapeHtml(a.ip)}</td>
          <td class="p-3">${escapeHtml(a.hostname || "")}</td>
          <td class="p-3">${pill(a.type)}</td>
          <td class="p-3">
            <div class="flex flex-wrap gap-1">
              ${(a.tags || []).slice(0, 8).map(tagChip).join("")}
            </div>
          </td>
          <td class="p-3 text-zinc-300">${escapeHtml((a.notes || "").slice(0, 80))}</td>
          <td class="p-3 text-right">
            <div class="flex flex-row gap-2 items-center justify-end">
              <button class="min-w-[44px] min-h-[44px] px-3 py-2 rounded-md border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center transition-all duration-200 hover:scale-[1.05]" data-edit title="Edit">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                </svg>
              </button>
              <button class="min-w-[44px] min-h-[44px] px-3 py-2 rounded-md border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center transition-all duration-200 hover:scale-[1.05]" data-del title="Delete">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                </svg>
              </button>
            </div>
          </td>
        </tr>
      `);
      
      // Insert icon cell as first child
      tr.insertBefore(iconTd, tr.firstChild);
  
      tr.querySelector("[data-edit]").onclick = () => openAssignmentModal(vlan, a);
      tr.querySelector("[data-del]").onclick = async () => {
        if (!confirm(`Delete ${a.ip}?`)) return;
        const delBtn = tr.querySelector("[data-del]");
        setButtonLoading(delBtn, true);
        
        // Store assignment data for undo
        const deletedAssignment = {
          vlanId: vlan.id,
          assignment: {
            ip: a.ip,
            hostname: a.hostname,
            type: a.type,
            tags: a.tags || [],
            notes: a.notes || "",
            icon: a.icon
          }
        };
        
        try {
          await api(`/api/vlans/${vlan.id}/assignments/${a.id}`, { method:"DELETE", loadingKey: `delete-${a.id}` });
          
          // Show toast with undo option
          toast(`Deleted ${a.ip}`, { 
            type: "success",
            duration: 5000,
            action: {
              label: "Undo",
              onClick: async () => {
                try {
                  await api(`/api/vlans/${deletedAssignment.vlanId}/assignments`, {
                    method: "POST",
                    body: deletedAssignment.assignment,
                    loadingKey: `undo-${deletedAssignment.vlanId}`
                  });
                  toast("Restored", { type: "success" });
                  const fresh = await api(`/api/vlans/${deletedAssignment.vlanId}`, { loadingKey: `vlan-${deletedAssignment.vlanId}` });
                  state.currentVlan = fresh;
                  Object.assign(vlan, fresh);
                  const tbody = document.querySelector("#rows");
                  renderRows(tbody, vlan);
                } catch (e) {
                  toast(e.message, { type: "error" });
                }
              }
            }
          });
          
          const fresh = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
          state.currentVlan = fresh;
          Object.assign(vlan, fresh);
          const tbody = document.querySelector("#rows");
          renderRows(tbody, vlan);
        } catch (e) { 
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(delBtn, false);
        }
      };

      tbody.appendChild(tr);
    }
  }

  function renderCards(container, list, vlan) {
    container.innerHTML = "";
    
    if (list.length === 0) {
      container.appendChild(el(`<div class="p-4 text-zinc-500 text-center bg-zinc-900 border border-zinc-800 rounded-lg">No assignments match your filters.</div>`));
      return;
    }

    for (const a of list) {
      const card = el(`
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4 space-y-3 transition-all duration-200 hover:border-zinc-700 animate-fadeIn">
          <div class="flex items-start gap-3">
            ${a.icon?.data_base64 ? 
              `<img src="data:${escapeHtml(a.icon.mime_type || "image/png")};base64,${a.icon.data_base64}" class="w-12 h-12 rounded-md border border-zinc-800 object-cover object-center flex-shrink-0" />` :
              `<div class="w-12 h-12 rounded-md border border-zinc-800 bg-zinc-950 flex-shrink-0"></div>`
            }
            <div class="flex-1 min-w-0">
              <div class="flex items-start justify-between gap-2">
                <div class="flex-1 min-w-0">
                  <div class="font-semibold mono text-base">${escapeHtml(a.ip)}</div>
                  ${a.hostname ? `<div class="text-sm text-zinc-300 mt-0.5 truncate">${escapeHtml(a.hostname)}</div>` : ''}
                </div>
                <div class="flex-shrink-0">${pill(a.type)}</div>
              </div>
            </div>
          </div>
          
          ${(a.tags || []).length > 0 ? `
            <div class="flex flex-wrap gap-1.5">
              ${(a.tags || []).map(tagChip).join("")}
            </div>
          ` : ''}
          
          ${a.notes ? `
            <div class="text-sm text-zinc-300 line-clamp-2">${escapeHtml(a.notes)}</div>
          ` : ''}
          
          <div class="flex gap-2 pt-2 border-t border-zinc-800">
            <button class="flex-1 min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center gap-2 text-sm font-medium transition-all duration-200 hover:scale-[1.02]" data-edit>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
              </svg>
              Edit
            </button>
            <button class="flex-1 min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center justify-center gap-2 text-sm font-medium text-red-400 transition-all duration-200 hover:scale-[1.02]" data-del>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
              </svg>
              Delete
            </button>
          </div>
        </div>
      `);
      
      card.querySelector("[data-edit]").onclick = () => openAssignmentModal(vlan, a);
      card.querySelector("[data-del]").onclick = async () => {
        if (!confirm(`Delete ${a.ip}?`)) return;
        const delBtn = card.querySelector("[data-del]");
        setButtonLoading(delBtn, true);
        
        // Store assignment data for undo
        const deletedAssignment = {
          vlanId: vlan.id,
          assignment: {
            ip: a.ip,
            hostname: a.hostname,
            type: a.type,
            tags: a.tags || [],
            notes: a.notes || "",
            icon: a.icon
          }
        };
        
        try {
          await api(`/api/vlans/${vlan.id}/assignments/${a.id}`, { method:"DELETE", loadingKey: `delete-${a.id}` });
          
          // Show toast with undo option
          toast(`Deleted ${a.ip}`, { 
            type: "success",
            duration: 5000,
            action: {
              label: "Undo",
              onClick: async () => {
                try {
                  await api(`/api/vlans/${deletedAssignment.vlanId}/assignments`, {
                    method: "POST",
                    body: deletedAssignment.assignment,
                    loadingKey: `undo-${deletedAssignment.vlanId}`
                  });
                  toast("Restored", { type: "success" });
                  const fresh = await api(`/api/vlans/${deletedAssignment.vlanId}`, { loadingKey: `vlan-${deletedAssignment.vlanId}` });
                  state.currentVlan = fresh;
                  Object.assign(vlan, fresh);
                  const cardContainer = document.querySelector("#cardContainer");
                  const tbody = document.querySelector("#rows");
                  renderRows(tbody, vlan);
                } catch (e) {
                  toast(e.message, { type: "error" });
                }
              }
            }
          });
          
          const fresh = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
          state.currentVlan = fresh;
          Object.assign(vlan, fresh);
          const cardContainer = document.querySelector("#cardContainer");
          const tbody = document.querySelector("#rows");
          renderRows(tbody, vlan);
        } catch (e) { 
          toast(e.message, { type: "error" });
        } finally {
          setButtonLoading(delBtn, false);
        }
      };

      container.appendChild(card);
    }
  }
  
  function openCreateUserModal() {
    const m = modalShell("Create User", `
      <div class="space-y-3">
        <div>
          <label class="text-xs text-zinc-400">Username</label>
          <input id="username" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          <div class="text-xs text-zinc-500 mt-1">Must be at least 3 characters</div>
        </div>
        <div>
          <label class="text-xs text-zinc-400">Password</label>
          <input id="password" type="password" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          <div class="text-xs text-zinc-500 mt-1">Must be at least 8 characters</div>
        </div>
        <div>
          <label class="text-xs text-zinc-400">Role</label>
          <select id="role" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600">
            <option value="readonly">Read Only</option>
            <option value="readwrite">Read/Write</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="cancel" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center gap-2 transition-all duration-200 min-h-[44px]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
            Cancel
          </button>
          <button id="save" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200 hover:scale-[1.02] min-h-[44px]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
            </svg>
            Create
          </button>
        </div>
      </div>
    `);

    const username = m.querySelector("#username");
    const password = m.querySelector("#password");
    const role = m.querySelector("#role");

    m.querySelector("#cancel").onclick = () => m.remove();
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      setButtonLoading(saveBtn, true, "Create");
      try {
        const payload = {
          username: username.value.trim(),
          password: password.value,
          role: role.value
        };
        
        if (!payload.username || payload.username.length < 3) {
          throw new Error("Username must be at least 3 characters");
        }
        if (!payload.password || payload.password.length < 8) {
          throw new Error("Password must be at least 8 characters");
        }

        await api("/api/users", { method:"POST", body: payload, loadingKey: "create-user" });
        toast("User created", { type: "success" });
        m.remove();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }

  function openIconLibraryModal() {
    const m = modalShell("Icon Library Management", `
      <div class="space-y-4">
        <div>
          <label class="text-xs text-zinc-400">Upload Multiple Icons</label>
          <input id="uploadIcons" type="file" accept="image/*" multiple class="mt-1 w-full text-sm" />
          <div class="text-xs text-zinc-500 mt-1">Select multiple image files. They will be normalized to 256×256 PNG.</div>
          <button id="uploadBtn" class="mt-2 px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm">Upload Icons</button>
        </div>
        
        <div class="border-t border-zinc-800 pt-4">
          <div class="flex items-center justify-between mb-3">
            <label class="text-xs text-zinc-400">Icon Library</label>
            <input id="librarySearch" type="text" placeholder="Search icons..." class="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-1.5 text-sm outline-none focus:border-zinc-600 w-48" />
          </div>
          <div id="iconLibraryGrid" class="grid grid-cols-4 sm:grid-cols-6 gap-3 max-h-96 overflow-y-auto p-2 bg-zinc-950 border border-zinc-800 rounded-lg">
            <!-- Icons will be loaded here -->
          </div>
        </div>
      </div>
    `);

    const uploadIcons = m.querySelector("#uploadIcons");
    const uploadBtn = m.querySelector("#uploadBtn");
    const librarySearch = m.querySelector("#librarySearch");
    const iconLibraryGrid = m.querySelector("#iconLibraryGrid");
    let allLibraryIcons = [];

    function renderLibraryIcons(filterText = "") {
      iconLibraryGrid.innerHTML = "";
      const filtered = allLibraryIcons.filter(iconInfo => {
        if (!filterText) return true;
        const search = filterText.toLowerCase();
        return iconInfo.name.toLowerCase().includes(search) || 
               iconInfo.filename.toLowerCase().includes(search);
      });
      
      if (filtered.length === 0) {
        iconLibraryGrid.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-4">No icons found</div>';
        return;
      }
      
      for (const iconInfo of filtered) {
        const card = el(`
          <div class="relative group">
            <div class="aspect-square p-2 border border-zinc-800 rounded-lg bg-zinc-900 hover:border-zinc-600 transition">
              <img src="/icons/${escapeHtml(iconInfo.filename)}" class="w-full h-full object-contain" />
            </div>
            <div class="mt-1 text-xs text-zinc-400 truncate" title="${escapeHtml(iconInfo.name)}">${escapeHtml(iconInfo.name)}</div>
            <button class="absolute top-1 right-1 w-6 h-6 bg-red-600 hover:bg-red-700 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity" data-delete-icon="${escapeHtml(iconInfo.filename)}" title="Delete">
              <svg class="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </button>
          </div>
        `);
        
        const deleteBtn = card.querySelector(`[data-delete-icon="${escapeHtml(iconInfo.filename)}"]`);
        deleteBtn.onclick = async () => {
          if (!confirm(`Delete icon "${iconInfo.name}"?`)) return;
          setButtonLoading(deleteBtn, true);
          try {
            await api(`/api/icons/${iconInfo.filename}`, { method: "DELETE", loadingKey: `delete-icon-${iconInfo.filename}` });
            toast("Icon deleted", { type: "success" });
            // Reload icons
            await loadLibraryIcons();
          } catch (e) {
            toast(e.message, { type: "error" });
          } finally {
            setButtonLoading(deleteBtn, false);
          }
        };
        
        iconLibraryGrid.appendChild(card);
      }
    }

    async function loadLibraryIcons() {
      iconLibraryGrid.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-4">' + spinner("w-5 h-5").outerHTML + '<div class="mt-2">Loading icons...</div></div>';
      try {
        const iconList = await api("/api/icons/list", { loadingKey: "icons-library-list" });
        allLibraryIcons = iconList.icons || [];
        renderLibraryIcons();
      } catch (e) {
        iconLibraryGrid.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-2">Failed to load icons</div>';
        toast(e.message, { type: "error" });
      }
    }

    librarySearch.oninput = (e) => {
      renderLibraryIcons(e.target.value);
    };

    uploadBtn.onclick = async () => {
      if (!uploadIcons.files || uploadIcons.files.length === 0) {
        toast("Please select at least one file", { type: "warning" });
        return;
      }
      
      setButtonLoading(uploadBtn, true, "Upload Icons");
      try {
        const fd = new FormData();
        for (let i = 0; i < uploadIcons.files.length; i++) {
          fd.append("files", uploadIcons.files[i]);
        }
        
        const result = await api("/api/icons/upload-multiple", { method: "POST", body: fd, loadingKey: "upload-icons" });
        
        if (result.success_count > 0) {
          toast(`Successfully uploaded ${result.success_count} icon(s)`, { type: "success" });
          if (result.errors && result.errors.length > 0) {
            const errorMsg = result.errors.map(e => `${e.filename}: ${e.error}`).join(", ");
            toast(`Some uploads failed: ${errorMsg}`, { type: "warning", duration: 5000 });
          }
          uploadIcons.value = "";
          await loadLibraryIcons();
        } else {
          toast("No icons were uploaded", { type: "error" });
        }
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(uploadBtn, false);
      }
    };

    // Load icons on open
    loadLibraryIcons();
  }

  function openAssignmentModal(vlan, existing=null, opts={}) {
    // Prevent opening assignment modal if no usable hosts
    const totalUsable = vlan.derived?.total_usable ?? 0;
    if (!existing && totalUsable === 0) {
      toast("No usable hosts in this subnet (/31 and /32 subnets cannot have assignments)", { type: "error" });
      return;
    }
    
    const isEdit = !!existing;
    const m = modalShell(isEdit ? "Edit assignment" : "Add assignment", `
      <div class="space-y-3">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label class="text-xs text-zinc-400">IP</label>
            <div class="mt-1 flex gap-2">
              <input id="ip" placeholder="${vlan.derived ? `${escapeHtml(vlan.derived.usable_start)} - ${escapeHtml(vlan.derived.usable_end)}` : ''}" class="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 mono" />
              <button id="generateIpBtn" class="min-w-[44px] min-h-[44px] px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg hover:bg-zinc-700 text-sm whitespace-nowrap" title="Generate random available IP">🎲</button>
            </div>
            <div class="text-xs text-zinc-500 mt-1">Must be inside ${escapeHtml(vlan.subnet_cidr)} and not reserved.</div>
          </div>
          <div>
            <label class="text-xs text-zinc-400">Type</label>
            <input id="type" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          </div>
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Hostname / Service</label>
          <input id="host" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Tags</label>
          <input id="tags" placeholder="Press Enter to add tag" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600" />
          <div id="tagsContainer" class="mt-2 flex flex-wrap gap-2"></div>
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Notes</label>
          <textarea id="notes" rows="3" class="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600"></textarea>
        </div>
  
        <div>
          <label class="text-xs text-zinc-400">Icon (optional)</label>
          <div class="mt-2 space-y-3">
            <div class="relative">
              <input id="iconSearch" type="text" placeholder="Search icons..." class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm outline-none focus:border-zinc-600" />
              <svg class="absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-zinc-500 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
              </svg>
            </div>
            <div id="iconPicker" class="grid grid-cols-4 sm:grid-cols-6 gap-2 max-h-64 overflow-y-auto p-2 bg-zinc-950 border border-zinc-800 rounded-lg">
              <!-- Icons will be loaded here -->
            </div>
            <div id="iconPreviewModal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
              <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4 max-w-sm w-full">
                <div class="flex items-center justify-between mb-3">
                  <div class="text-sm font-medium" id="previewIconName"></div>
                  <button id="closePreview" class="text-zinc-400 hover:text-zinc-200">✕</button>
                </div>
                <div class="flex justify-center mb-3">
                  <img id="previewIconImg" class="w-32 h-32 object-contain rounded-lg border border-zinc-800" />
                </div>
                <button id="selectPreviewIcon" class="w-full px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm">Select</button>
              </div>
            </div>
            <div class="flex items-center gap-3">
              <div class="text-xs text-zinc-400">Or upload custom:</div>
              <input id="icon" type="file" accept="image/*" multiple class="flex-1 text-xs" />
            </div>
            <div class="flex items-center gap-3">
              <div id="preview" class="w-12 h-12 rounded-lg border border-zinc-800 bg-zinc-900 overflow-hidden flex items-center justify-center"></div>
              <div class="text-xs text-zinc-500" id="previewText">No icon</div>
            </div>
            <div class="text-xs text-zinc-500">Icons are auto normalized to 256×256 PNG. You can upload multiple at once.</div>
          </div>
        </div>
  
        <div class="flex justify-end gap-2 pt-2">
          <button id="cancel" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 flex items-center gap-2 transition-all duration-200 min-h-[44px]">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
            Cancel
          </button>
          <button id="save" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 flex items-center gap-2 transition-all duration-200 hover:scale-[1.02] min-h-[44px]">
            ${isEdit ? `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
              </svg>
              Save
            ` : `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
              </svg>
              Add
            `}
          </button>
        </div>
      </div>
    `);
  
    const ip = m.querySelector("#ip");
    const type = m.querySelector("#type");
    const host = m.querySelector("#host");
    const tagsInput = m.querySelector("#tags");
    const tagsContainer = m.querySelector("#tagsContainer");
    const notes = m.querySelector("#notes");
    const icon = m.querySelector("#icon");
    const iconPicker = m.querySelector("#iconPicker");
    const iconSearch = m.querySelector("#iconSearch");
    const preview = m.querySelector("#preview");
    const previewText = m.querySelector("#previewText");
    const generateIpBtn = m.querySelector("#generateIpBtn");
    const iconPreviewModal = m.querySelector("#iconPreviewModal");
    const previewIconImg = m.querySelector("#previewIconImg");
    const previewIconName = m.querySelector("#previewIconName");
    const closePreview = m.querySelector("#closePreview");
    const selectPreviewIcon = m.querySelector("#selectPreviewIcon");

    let iconObj = existing?.icon || null;
    let selectedIconName = null;
    let tagsList = [];
    let allIcons = []; // Store all icons for filtering
    let previewIconData = null; // Store icon data for preview modal

    function renderTags() {
      tagsContainer.innerHTML = "";
      tagsList.forEach((tag, index) => {
        // Create tag chip using DOM methods
        const chip = document.createElement("span");
        chip.className = "text-xs px-2 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-200 cursor-pointer hover:bg-zinc-800";
        chip.textContent = tag + " ×";
        chip.onclick = () => {
          tagsList.splice(index, 1);
          renderTags();
        };
        tagsContainer.appendChild(chip);
      });
    }

    tagsInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        const tag = tagsInput.value.trim();
        if (tag && !tagsList.includes(tag)) {
          tagsList.push(tag);
          renderTags();
          tagsInput.value = "";
        }
      }
    });
  
    function setPreview(obj) {
      if (!obj) {
        preview.innerHTML = "";
        previewText.textContent = "No icon";
        return;
      }
      // Clear and create img element using DOM methods
      preview.innerHTML = "";
      const img = document.createElement("img");
      img.className = "w-12 h-12 object-cover object-center";
      // Escape mime_type to prevent XSS in data URI
      const safeMimeType = escapeHtml(obj.mime_type || "image/png");
      img.src = `data:${safeMimeType};base64,${obj.data_base64}`;
      preview.appendChild(img);
      previewText.textContent = "Icon set";
    }

    // Function to render icons with filtering
    function renderIcons(filterText = "") {
      iconPicker.innerHTML = "";
      const filtered = allIcons.filter(iconInfo => {
        if (!filterText) return true;
        const search = filterText.toLowerCase();
        return iconInfo.name.toLowerCase().includes(search) || 
               iconInfo.filename.toLowerCase().includes(search);
      });
      
      if (filtered.length === 0) {
        iconPicker.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-2">No icons match your search</div>';
        return;
      }
      
      for (const iconInfo of filtered) {
        const btn = el(`
          <button type="button" class="w-full aspect-square p-2 border border-zinc-800 rounded-lg hover:border-zinc-600 hover:bg-zinc-900 transition group relative" data-icon-name="${escapeHtml(iconInfo.filename)}" title="${escapeHtml(iconInfo.name)}">
            <img src="/icons/${escapeHtml(iconInfo.filename)}" class="w-full h-full object-contain" />
            <div class="absolute inset-0 bg-zinc-900/80 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center rounded-lg">
              <span class="text-xs text-zinc-200">Preview</span>
            </div>
          </button>
        `);
        
        // Preview on hover (with delay)
        let hoverTimeout;
        btn.onmouseenter = () => {
          hoverTimeout = setTimeout(() => {
            if (iconPreviewModal && !iconPreviewModal.classList.contains("hidden")) {
              return; // Already showing
            }
            previewIconImg.src = `/icons/${escapeHtml(iconInfo.filename)}`;
            previewIconName.textContent = iconInfo.name;
            previewIconData = iconInfo;
            iconPreviewModal.classList.remove("hidden");
          }, 500); // 500ms delay before showing preview
        };
        btn.onmouseleave = () => {
          if (hoverTimeout) {
            clearTimeout(hoverTimeout);
          }
        };
        
        // Close preview when clicking outside
        const closePreviewOnOutside = (e) => {
          if (e.target === iconPreviewModal) {
            iconPreviewModal.classList.add("hidden");
          }
        };
        iconPreviewModal.addEventListener("click", closePreviewOnOutside);
        
        // Click to select directly
        btn.onclick = async () => {
          setButtonLoading(btn, true);
          try {
            // Remove previous selection
            iconPicker.querySelectorAll("button").forEach(b => {
              b.classList.remove("border-zinc-600", "bg-zinc-900");
              b.classList.add("border-zinc-800");
            });
            // Highlight selected
            btn.classList.remove("border-zinc-800");
            btn.classList.add("border-zinc-600", "bg-zinc-900");
            
            selectedIconName = iconInfo.filename;
            const normalized = await api(`/api/icons/${iconInfo.filename}`, { loadingKey: `icon-${iconInfo.filename}` });
            iconObj = normalized;
            setPreview(iconObj);
            iconPreviewModal.classList.add("hidden");
            toast("Icon selected", { type: "success" });
          } catch (e) {
            toast(e.message, { type: "error" });
          } finally {
            setButtonLoading(btn, false);
          }
        };
        iconPicker.appendChild(btn);
      }
    }

    // Search functionality
    iconSearch.oninput = (e) => {
      renderIcons(e.target.value);
    };

    // Preview modal handlers
    closePreview.onclick = () => {
      iconPreviewModal.classList.add("hidden");
    };
    iconPreviewModal.onclick = (e) => {
      if (e.target === iconPreviewModal) {
        iconPreviewModal.classList.add("hidden");
      }
    };
    selectPreviewIcon.onclick = async () => {
      if (!previewIconData) return;
      setButtonLoading(selectPreviewIcon, true);
      try {
        // Remove previous selection
        iconPicker.querySelectorAll("button").forEach(b => {
          b.classList.remove("border-zinc-600", "bg-zinc-900");
          b.classList.add("border-zinc-800");
        });
        
        selectedIconName = previewIconData.filename;
        const normalized = await api(`/api/icons/${previewIconData.filename}`, { loadingKey: `icon-${previewIconData.filename}` });
        iconObj = normalized;
        setPreview(iconObj);
        iconPreviewModal.classList.add("hidden");
        
        // Highlight selected button
        const selectedBtn = iconPicker.querySelector(`[data-icon-name="${escapeHtml(previewIconData.filename)}"]`);
        if (selectedBtn) {
          selectedBtn.classList.remove("border-zinc-800");
          selectedBtn.classList.add("border-zinc-600", "bg-zinc-900");
        }
        
        toast("Icon selected", { type: "success" });
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(selectPreviewIcon, false);
      }
    };

    // Load and display predefined icons
    (async () => {
      // Show loading state in icon picker
      iconPicker.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-4"><div class="inline-block">' + spinner("w-5 h-5").outerHTML + '</div><div class="mt-2">Loading icons...</div></div>';
      
      try {
        const iconList = await api("/api/icons/list", { loadingKey: "icons-list" });
        allIcons = iconList.icons || [];
        renderIcons();
      } catch (e) {
        iconPicker.innerHTML = '<div class="col-span-full text-xs text-zinc-500 text-center py-2">Failed to load icons</div>';
      }
    })();
  
    if (existing) {
      ip.value = existing.ip;
      type.value = existing.type;
      host.value = existing.hostname || "";
      tagsList = [...(existing.tags || [])];
      renderTags();
      notes.value = existing.notes || "";
      setPreview(existing.icon || null);
    } else {
      type.value = "server";
      if (opts.presetIp) ip.value = opts.presetIp;
    }

    icon.onchange = async () => {
      if (!icon.files || icon.files.length === 0) return;
      
      // Handle multiple files - process first one for assignment, show message if more
      const file = icon.files[0];
      const hasMultiple = icon.files.length > 1;
      
      // Show loading in preview
      preview.innerHTML = spinner("w-6 h-6").outerHTML;
      previewText.textContent = "Processing...";
      
      try {
        // Clear predefined icon selection
        iconPicker.querySelectorAll("button").forEach(b => {
          b.classList.remove("border-zinc-600", "bg-zinc-900");
          b.classList.add("border-zinc-800");
        });
        selectedIconName = null;
        
        const fd = new FormData();
        fd.append("file", file);
        const normalized = await api("/api/icons/normalize", { method:"POST", body: fd, loadingKey: "normalize-icon" });
        iconObj = normalized;
        setPreview(iconObj);
        
        if (hasMultiple) {
          toast(`Icon normalized. Note: Only the first file was used. Use the Icon Library to upload multiple icons.`, { type: "info", duration: 5000 });
        } else {
          toast("Icon normalized", { type: "success" });
        }
      } catch (e) {
        preview.innerHTML = "";
        previewText.textContent = "Failed";
        toast(e.message, { type: "error" });
      }
    };

    generateIpBtn.onclick = async () => {
      setButtonLoading(generateIpBtn, true);
      try {
        const res = await api(`/api/vlans/${vlan.id}/next-available`, { loadingKey: `next-ip-${vlan.id}` });
        if (res.ip) {
          ip.value = res.ip;
          toast("Generated available IP", { type: "success" });
        } else {
          toast("No available IP found", { type: "info" });
        }
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(generateIpBtn, false);
      }
    };

    m.querySelector("#cancel").onclick = () => m.remove();
  
    const saveBtn = m.querySelector("#save");
    saveBtn.onclick = async () => {
      setButtonLoading(saveBtn, true);
      try {
        const payload = {
          ip: ip.value.trim(),
          hostname: host.value.trim(),
          type: type.value.trim() || "server",
          tags: tagsList,
          notes: notes.value.trim(),
          icon: iconObj
        };
        if (!payload.ip) throw new Error("IP is required");
  
        if (!existing) {
          await api(`/api/vlans/${vlan.id}/assignments`, { method:"POST", body: payload, loadingKey: `create-assignment-${vlan.id}` });
          toast("Added", { type: "success" });
        } else {
          await api(`/api/vlans/${vlan.id}/assignments/${existing.id}`, { method:"PATCH", body: payload, loadingKey: `update-assignment-${existing.id}` });
          toast("Saved", { type: "success" });
        }
  
        const fresh = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
        state.currentVlan = fresh;
        Object.assign(vlan, fresh);
  
        // rerender
        const tbody = document.querySelector("#rows");
        const header = document.querySelector("#header");
        renderVlanHeader(header, vlan);
        renderRows(tbody, vlan);
  
        m.remove();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(saveBtn, false);
      }
    };
  }

  function openImportModal(vlan) {
    const m = modalShell("Import Assignments", `
      <div class="space-y-4">
        <div class="text-sm text-zinc-400">
          Import assignments from CSV, JSON, or Excel file. Required columns: <code class="text-zinc-300">ip</code>. 
          Optional columns: <code class="text-zinc-300">hostname</code>, <code class="text-zinc-300">type</code>, 
          <code class="text-zinc-300">tags</code> (comma-separated), <code class="text-zinc-300">notes</code>.
        </div>
        <div>
          <label class="text-xs text-zinc-400 mb-2 block">File</label>
          <input type="file" id="importFile" accept=".csv,.json,.xlsx,.xls" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 min-h-[44px] text-sm" />
        </div>
        <div id="importResults" class="hidden space-y-2">
          <div id="importSuccess" class="text-sm text-green-400"></div>
          <div id="importErrors" class="text-sm text-red-400 space-y-1"></div>
        </div>
        <div class="flex flex-col sm:flex-row justify-end gap-2 pt-2">
          <button id="cancelImport" class="min-h-[44px] px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm font-medium">Cancel</button>
          <button id="importSubmit" class="min-h-[44px] px-4 py-2.5 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm">Import</button>
        </div>
      </div>
    `);

    const fileInput = m.querySelector("#importFile");
    const importBtn = m.querySelector("#importSubmit");
    const cancelBtn = m.querySelector("#cancelImport");
    const resultsDiv = m.querySelector("#importResults");
    const successDiv = m.querySelector("#importSuccess");
    const errorsDiv = m.querySelector("#importErrors");

    cancelBtn.onclick = () => m.remove();

    importBtn.onclick = async () => {
      if (!fileInput.files || fileInput.files.length === 0) {
        toast("Please select a file", { type: "error" });
        return;
      }

      const file = fileInput.files[0];
      const formData = new FormData();
      formData.append("file", file);

      setButtonLoading(importBtn, true, "Importing...");
      resultsDiv.classList.add("hidden");
      successDiv.textContent = "";
      errorsDiv.innerHTML = "";

      try {
        const result = await api(`/api/vlans/${vlan.id}/assignments/import`, {
          method: "POST",
          body: formData,
          loadingKey: `import-${vlan.id}`
        });

        if (result.imported > 0) {
          successDiv.textContent = `Successfully imported ${result.imported} assignment(s)`;
          toast(`Imported ${result.imported} assignment(s)`, { type: "success" });
          
          // Reload VLAN data
          const updatedVlan = await api(`/api/vlans/${vlan.id}`, { loadingKey: `vlan-${vlan.id}` });
          state.currentVlan = updatedVlan;
          Object.assign(vlan, updatedVlan);
          
          // Re-render rows
          const tbody = document.querySelector("#rows");
          if (tbody) renderRows(tbody, updatedVlan);
        }

        if (result.errors > 0) {
          let errorHtml = `<div class="font-semibold">${result.errors} error(s) occurred:</div>`;
          if (result.error_details && result.error_details.length > 0) {
            const errorList = result.error_details.slice(0, 10).map(err => {
              const row = err.row ? `Row ${err.row}: ` : "";
              const ip = err.ip ? `${err.ip} - ` : "";
              return `<div>${row}${ip}${escapeHtml(err.error)}</div>`;
            }).join("");
            errorHtml += errorList;
            if (result.error_details.length > 10) {
              errorHtml += `<div class="text-zinc-500">... and ${result.error_details.length - 10} more errors</div>`;
            }
          }
          errorsDiv.innerHTML = errorHtml;
        }

        if (result.errors > 0 || result.imported > 0) {
          resultsDiv.classList.remove("hidden");
        }

        if (result.imported > 0) {
          // Close modal after successful import
          setTimeout(() => {
            m.remove();
          }, 2000);
        }
      } catch (e) {
        toast(e.message, { type: "error" });
        errorsDiv.innerHTML = `<div>${escapeHtml(e.message)}</div>`;
        resultsDiv.classList.remove("hidden");
      } finally {
        setButtonLoading(importBtn, false);
      }
    };
  }

  async function renderAuditLogs() {
    const root = appRoot();
    root.innerHTML = "";
    const tb = topbar();
    root.appendChild(tb);

    tb.querySelector("#logoutBtn").onclick = async () => {
      const btn = tb.querySelector("#logoutBtn");
      setButtonLoading(btn, true, "Logout");
      try {
        await api("/api/auth/logout", { method:"POST", loadingKey: "logout" });
        state.me = null;
        toast("Logged out", { type: "success" });
        route();
      } catch (e) {
        toast(e.message, { type: "error" });
      } finally {
        setButtonLoading(btn, false);
      }
    };
    tb.querySelector("#exportBtn").onclick = () => window.location.href = "/api/export/data";
    const iconLibraryBtn = tb.querySelector("#iconLibraryBtn");
    if (iconLibraryBtn) {
      iconLibraryBtn.onclick = () => openIconLibraryModal();
    }
    const createUserBtn = tb.querySelector("#createUserBtn");
    if (createUserBtn) {
      createUserBtn.onclick = () => openCreateUserModal();
    }
    const auditLogsBtn = tb.querySelector("#auditLogsBtn");
    if (auditLogsBtn) {
      auditLogsBtn.onclick = () => setRoute("#/audit-logs");
    }

    const content = el(`
      <div class="max-w-6xl mx-auto px-4 py-6">
        <div class="flex items-end justify-between gap-3 mb-6">
          <div>
            <div class="text-2xl font-semibold tracking-tight">Audit Logs</div>
            <div class="text-sm text-zinc-400">View all system activity and changes.</div>
          </div>
          <button id="backBtn" class="px-4 py-2.5 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm text-zinc-200 hover:text-zinc-100 min-h-[44px] font-medium">← Back</button>
        </div>

        <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-4 mb-6">
          <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">User</label>
              <input id="userFilter" type="text" placeholder="Filter by user..." class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">Action</label>
              <input id="actionFilter" type="text" placeholder="Filter by action..." class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">Date From</label>
              <input id="dateFrom" type="date" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
            <div>
              <label class="text-xs text-zinc-400 mb-1 block">Date To</label>
              <input id="dateTo" type="date" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 outline-none focus:border-zinc-600 text-sm min-h-[44px]" />
            </div>
          </div>
          <div class="flex justify-end gap-2 mt-3">
            <button id="clearFiltersBtn" class="px-4 py-2 rounded-lg border border-zinc-800 hover:bg-zinc-950 text-sm font-medium min-h-[44px]">Clear Filters</button>
            <button id="applyFiltersBtn" class="px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:opacity-90 text-sm min-h-[44px]">Apply Filters</button>
          </div>
        </div>

        <div id="auditLogsContainer" class="space-y-3">
          <!-- Logs will be loaded here -->
        </div>
      </div>
    `);

    root.appendChild(content);
    content.querySelector("#backBtn").onclick = () => setRoute("#/");

    let currentFilters = {
      user: null,
      action: null,
      dateFrom: null,
      dateTo: null
    };

    async function loadAuditLogs() {
      const container = content.querySelector("#auditLogsContainer");
      container.innerHTML = '<div class="text-center py-8">' + spinner("w-6 h-6").outerHTML + '<div class="mt-2 text-zinc-400">Loading audit logs...</div></div>';

      try {
        const params = new URLSearchParams();
        if (currentFilters.user) params.append("user_filter", currentFilters.user);
        if (currentFilters.action) params.append("action_filter", currentFilters.action);
        if (currentFilters.dateFrom) {
          // Convert local date to UTC ISO string
          const date = new Date(currentFilters.dateFrom + "T00:00:00");
          params.append("date_from", date.toISOString());
        }
        if (currentFilters.dateTo) {
          // Convert local date to UTC ISO string (end of day)
          const date = new Date(currentFilters.dateTo + "T23:59:59");
          params.append("date_to", date.toISOString());
        }

        const res = await api(`/api/audit-logs?${params.toString()}`, { loadingKey: "audit-logs" });
        renderAuditLogEntries(container, res.entries || []);
      } catch (e) {
        container.innerHTML = `<div class="text-center py-8 text-red-400">Failed to load audit logs: ${escapeHtml(e.message)}</div>`;
        toast(e.message, { type: "error" });
      }
    }

    function renderAuditLogEntries(container, entries) {
      container.innerHTML = "";
      
      if (entries.length === 0) {
        container.appendChild(el(`<div class="text-center py-8 text-zinc-500">No audit log entries found.</div>`));
        return;
      }

      for (const entry of entries) {
        const card = el(`
          <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:bg-zinc-900/70 transition">
            <div class="flex items-start justify-between gap-3 mb-3">
              <div class="flex-1">
                <div class="flex items-center gap-2 mb-1">
                  <span class="text-sm font-medium text-zinc-200">${escapeHtml(entry.user || "unknown")}</span>
                  <span class="text-xs text-zinc-500">•</span>
                  <span class="text-xs text-zinc-400">${escapeHtml(entry.action || "")}</span>
                  <span class="text-xs text-zinc-500">•</span>
                  <span class="text-xs text-zinc-400">${escapeHtml(entry.entity || "")}</span>
                </div>
                <div class="text-xs text-zinc-500">${escapeHtml(entry.ts || "")}</div>
              </div>
              ${(entry.before || entry.after) ? `<button class="text-xs px-3 py-1.5 rounded-md border border-zinc-800 hover:bg-zinc-950 min-h-[32px] font-medium" data-show-diff>Show Changes</button>` : ''}
            </div>
            ${entry.before || entry.after ? `
              <div class="mt-3 pt-3 border-t border-zinc-800 hidden" data-diff-view>
                ${renderDiffView(entry.before, entry.after)}
              </div>
            ` : ''}
          </div>
        `);

        const showDiffBtn = card.querySelector("[data-show-diff]");
        if (showDiffBtn) {
          const diffView = card.querySelector("[data-diff-view]");
          showDiffBtn.onclick = () => {
            if (diffView.classList.contains("hidden")) {
              diffView.classList.remove("hidden");
              showDiffBtn.textContent = "Hide Changes";
            } else {
              diffView.classList.add("hidden");
              showDiffBtn.textContent = "Show Changes";
            }
          };
        }

        container.appendChild(card);
      }
    }

    function renderDiffView(before, after) {
      if (!before && !after) return "";
      
      const beforeStr = before ? JSON.stringify(before, null, 2) : "";
      const afterStr = after ? JSON.stringify(after, null, 2) : "";
      
      if (!before) {
        return `
          <div class="space-y-2">
            <div class="text-xs font-medium text-green-400">Added:</div>
            <pre class="text-xs bg-green-950/30 border border-green-800/50 rounded p-3 overflow-x-auto text-green-200">${escapeHtml(afterStr)}</pre>
          </div>
        `;
      }
      
      if (!after) {
        return `
          <div class="space-y-2">
            <div class="text-xs font-medium text-red-400">Removed:</div>
            <pre class="text-xs bg-red-950/30 border border-red-800/50 rounded p-3 overflow-x-auto text-red-200">${escapeHtml(beforeStr)}</pre>
          </div>
        `;
      }

      // Simple diff: show before and after side by side
      return `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div class="space-y-2">
            <div class="text-xs font-medium text-red-400">Before:</div>
            <pre class="text-xs bg-red-950/30 border border-red-800/50 rounded p-3 overflow-x-auto text-red-200 max-h-64 overflow-y-auto">${escapeHtml(beforeStr)}</pre>
          </div>
          <div class="space-y-2">
            <div class="text-xs font-medium text-green-400">After:</div>
            <pre class="text-xs bg-green-950/30 border border-green-800/50 rounded p-3 overflow-x-auto text-green-200 max-h-64 overflow-y-auto">${escapeHtml(afterStr)}</pre>
          </div>
        </div>
      `;
    }

    content.querySelector("#applyFiltersBtn").onclick = () => {
      currentFilters.user = content.querySelector("#userFilter").value.trim() || null;
      currentFilters.action = content.querySelector("#actionFilter").value.trim() || null;
      currentFilters.dateFrom = content.querySelector("#dateFrom").value || null;
      currentFilters.dateTo = content.querySelector("#dateTo").value || null;
      loadAuditLogs();
    };

    content.querySelector("#clearFiltersBtn").onclick = () => {
      content.querySelector("#userFilter").value = "";
      content.querySelector("#actionFilter").value = "";
      content.querySelector("#dateFrom").value = "";
      content.querySelector("#dateTo").value = "";
      currentFilters = { user: null, action: null, dateFrom: null, dateTo: null };
      loadAuditLogs();
    };

    // Load initial logs
    loadAuditLogs();
  }
  
  init();
  