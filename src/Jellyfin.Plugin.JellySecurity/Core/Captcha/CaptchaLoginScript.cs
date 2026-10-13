namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

/// <summary>
/// Inserts the reCAPTCHA checkbox into the browser login document.
/// Jellyfin's web files on disk are not edited.
/// </summary>
public static class CaptchaLoginScript
{
    public static string Inject(string html, string? siteKey)
    {
        return Inject(html, siteKey, "ReCaptcha");
    }

    public static string Inject(string html, string? siteKey, string? provider)
    {
        var kind = WidgetKind(provider);
        if (string.IsNullOrEmpty(html) || kind is null || !RecaptchaKey.IsSiteKey(siteKey))
        {
            return html;
        }

        if (html.Contains("jelly-security-recaptcha", StringComparison.Ordinal))
        {
            return html;
        }

        var script = "<script>" + Build(siteKey!.Trim(), kind) + "</script>";
        var index = html.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return html + script;
        }

        return string.Concat(html.AsSpan(0, index), script, html.AsSpan(index));
    }

    public static string Build(string siteKey, string provider)
    {
        return Script
            .Replace("__SITE_KEY__", siteKey, StringComparison.Ordinal)
            .Replace("__PROVIDER__", provider, StringComparison.Ordinal);
    }

    private static string? WidgetKind(string? provider)
    {
        if (CaptchaPolicy.IsTurnstile(provider))
        {
            return "turnstile";
        }

        if (CaptchaPolicy.IsGoogle(provider))
        {
            return "google";
        }

        return null;
    }

    private const string Script = """
(function () {
  var siteKey = "__SITE_KEY__";
  var provider = "__PROVIDER__";
  var widgetId = null;
  var mountId = "jelly-security-recaptcha";
  var headerName = "X-Jelly-Security-Captcha";
  var scheduled = false;

  function isGateway(url) {
    return /\/Users\/AuthenticateByName(?:\?|$)/i.test(url)
      || /\/Users\/ForgotPassword(?:\?|$)/i.test(url)
      || /\/Users\/[0-9a-f-]{36}\/Authenticate(?:\?|$)/i.test(url);
  }

  function client() {
    return provider === "turnstile" ? window.turnstile : window.grecaptcha;
  }

  function token() {
    try {
      var api = client();
      return (api && api.getResponse && api.getResponse(widgetId)) || "";
    } catch (e) {
      return "";
    }
  }

  function loginForm() {
    var password = document.querySelector("#txtManualPassword");
    if (!password) return null;
    return password.closest("form") || document.querySelector(".manualLoginForm");
  }

  function resetForm() {
    if (!/forgotpassword/i.test(location.href)) return null;
    var name = document.querySelector("#txtName");
    if (!name) return null;
    return name.closest("form") || name.parentElement;
  }

  function showHint(form) {
    var hint = form.querySelector(".jelly-security-captcha-hint");
    if (!hint) {
      hint = document.createElement("div");
      hint.className = "jelly-security-captcha-hint";
      hint.style.color = "#ffb4a8";
      hint.style.margin = "0.5em 0";
      var mount = document.getElementById(mountId);
      if (mount && mount.parentNode) mount.parentNode.insertBefore(hint, mount.nextSibling);
      else form.appendChild(hint);
    }
    hint.textContent = "Complete the check before continuing.";
  }

  function shown(el) {
    if (!el || !el.isConnected) return false;
    try {
      var style = window.getComputedStyle(el);
      return style.display !== "none" && style.visibility !== "hidden" && el.getClientRects().length > 0;
    } catch (e) {
      return false;
    }
  }

  function render(box) {
    var api = client();
    if (!api || !api.render || box.getAttribute("data-rendered")) return;
    var options = provider === "turnstile"
      ? { sitekey: siteKey, theme: "dark", appearance: "always", language: "en" }
      : { sitekey: siteKey, theme: "dark" };
    widgetId = api.render(box, options);
    box.setAttribute("data-rendered", "1");
  }

  function ensureWidget() {
    var form = loginForm() || resetForm();
    if (!form || !shown(form)) return;
    var box = document.getElementById(mountId);
    if (!box || !form.contains(box)) {
      box = document.createElement("div");
      box.id = mountId;
      box.style.margin = "1em 0";
      var submit = form.querySelector("button[type='submit'], .raised");
      if (submit && submit.parentNode) submit.parentNode.insertBefore(box, submit);
      else form.appendChild(box);
    }
    render(box);
  }

  window.jellySecurityCaptchaOnload = function () { ensureWidget(); };

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(function () {
      scheduled = false;
      ensureWidget();
    });
  }

  if (document.head) {
    var loader = document.createElement("script");
    loader.src = provider === "turnstile"
      ? "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=jellySecurityCaptchaOnload&render=explicit"
      : "https://www.google.com/recaptcha/api.js?onload=jellySecurityCaptchaOnload&render=explicit&hl=en";
    loader.async = true;
    loader.defer = true;
    document.head.appendChild(loader);
  }

  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["class", "style", "hidden"] });
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!form || !form.querySelector) return;
    if (!form.querySelector("#txtManualPassword") && !(form.querySelector("#txtName") && /forgotpassword/i.test(location.href))) return;
    if (!token()) {
      ev.preventDefault();
      ev.stopPropagation();
      showHint(form);
    }
  }, true);

  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function (input, init) {
      var url = typeof input === "string" ? input : (input && input.url) || "";
      if (!isGateway(url)) return origFetch.apply(this, arguments);
      var value = token();
      init = init ? Object.assign({}, init) : {};
      var headers = new Headers(init.headers || (typeof Request !== "undefined" && input instanceof Request ? input.headers : undefined));
      if (value) headers.set(headerName, value);
      init.headers = headers;
      return origFetch.call(this, input, init).finally(function () {
        try { client().reset(widgetId); } catch (e) {}
      });
    };
  }

  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  var origSet = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__jellySecurityUrl = url;
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    var url = this.__jellySecurityUrl ? String(this.__jellySecurityUrl) : "";
    if (isGateway(url)) {
      var value = token();
      if (value) {
        try { origSet.call(this, headerName, value); } catch (e) {}
      }
      this.addEventListener("loadend", function () {
        try { client().reset(widgetId); } catch (e) {}
      });
    }
    return origSend.apply(this, arguments);
  };
})();
""";
}
