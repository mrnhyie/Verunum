/* Verunum toast notifications — window.vtoast(message, opts) */
(function () {
  'use strict';

  var ICONS = {
    success: '<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>',
    error: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg>',
    info: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 11.5v4.5"/></svg>',
    chat: '<svg viewBox="0 0 24 24"><path d="M21 12a8 8 0 0 1-8 8H4l2.3-2.7A8 8 0 1 1 21 12z"/><path d="M8.5 11h.01M12 11h.01M15.5 11h.01"/></svg>'
  };
  var DEFAULTS = { duration: 4200, chatDuration: 6500 };
  var MAX_VISIBLE = 4;

  function stack() {
    var s = document.querySelector('.toast-stack');
    if (!s) {
      s = document.createElement('div');
      s.className = 'toast-stack';
      s.setAttribute('aria-live', 'polite');
      document.body.appendChild(s);
    }
    return s;
  }

  function build(msg, opts) {
    var type = ICONS[opts.type] ? opts.type : 'info';
    var toast = document.createElement('div');
    toast.className = 'toast';
    toast.dataset.type = type;
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');

    var icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.innerHTML = ICONS[type];
    toast.appendChild(icon);

    var body = document.createElement('div');
    body.className = 'toast-body';
    if (opts.title) {
      var title = document.createElement('strong');
      title.className = 'toast-title';
      title.textContent = opts.title;
      body.appendChild(title);
    }
    var text = document.createElement('span');
    text.className = 'toast-msg';
    text.textContent = msg;
    body.appendChild(text);
    toast.appendChild(body);

    var life = document.createElement('i');
    life.className = 'toast-life';
    toast.appendChild(life);

    var duration = opts.duration || (type === 'chat' ? DEFAULTS.chatDuration : DEFAULTS.duration);
    life.style.animationDuration = duration + 'ms';
    return { toast: toast, life: life, duration: duration };
  }

  function vtoast(message, opts) {
    if (message === undefined || message === null || message === '') return null;
    opts = opts || {};
    var s = stack();
    while (s.children.length >= MAX_VISIBLE) {
      dismiss(s.firstElementChild);
    }

    var built = build(String(message), opts);
    s.appendChild(built.toast);

    var remaining = built.duration;
    var startedAt = Date.now();
    var timer = null;

    function schedule(ms) {
      timer = setTimeout(function () { dismiss(built.toast); }, ms);
      startedAt = Date.now();
    }
    schedule(remaining);

    built.toast.addEventListener('mouseenter', function () {
      if (timer) { clearTimeout(timer); timer = null; }
      remaining -= Date.now() - startedAt;
      if (remaining < 900) remaining = 900;
    });
    built.toast.addEventListener('mouseleave', function () {
      if (!timer) schedule(remaining);
    });
    built.toast.addEventListener('click', function () {
      if (typeof opts.onClick === 'function') { try { opts.onClick(); } catch (e) {} }
      dismiss(built.toast);
    });

    return built.toast;
  }

  function dismiss(toast) {
    if (!toast || toast.classList.contains('leaving')) return;
    toast.classList.add('leaving');
    setTimeout(function () { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 340);
  }

  window.vtoast = vtoast;
  window.vtoast.dismiss = dismiss;

  // Server redirects can append ?toast=Message&toast_type=success to any URL.
  function fromQuery() {
    try {
      var params = new URLSearchParams(window.location.search);
      var message = params.get('toast');
      if (!message) return;
      var type = params.get('toast_type') || 'success';
      vtoast(message, { type: type });
      params.delete('toast');
      params.delete('toast_type');
      var qs = params.toString();
      var clean = window.location.pathname + (qs ? '?' + qs : '') + window.location.hash;
      window.history.replaceState(null, '', clean);
    } catch (e) {}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fromQuery);
  } else {
    fromQuery();
  }
})();
