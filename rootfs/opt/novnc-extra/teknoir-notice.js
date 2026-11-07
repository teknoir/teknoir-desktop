/*
 * The shared-desktop notice (README "Notice banner").
 *
 * desktop-entrypoint writes /run/desktop/notice.json and the image symlinks it
 * to teknoir-notice.json next to this file, so the page fetches it from the
 * same origin. A TeknoirBot's desktop is shared with its whole teamspace, and
 * the banner is where the people who open it are told not to sign in to
 * personal accounts there.
 *
 * It is a plain deferred script: no top-level await, no document.write and no
 * globals (everything lives in this IIFE), so noVNC's own start-up is never
 * delayed or blocked, and the VNC canvas keeps keyboard focus. The text is set
 * with textContent, so markup in the notice is shown literally. Anything odd
 * about the file (missing, an error, not JSON, no text) means no banner and
 * nothing logged by this script (the browser itself still reports a 404 in
 * host mode).
 */
(function () {
  "use strict";

  var SOURCE = "teknoir-notice.json";
  var ID = "teknoir_notice";

  function build(text) {
    // The banner is fixed, so the page has to make room for it: noVNC's
    // container is moved down and shortened by the banner's height (its
    // ResizeObserver then asks the remote desktop for a smaller size), and
    // noVNC's own status line, also fixed at the top, moves down with it.
    // Otherwise the banner covers the top of the remote screen (the XFCE
    // panel) and noVNC's status text.
    var room = document.createElement("style");
    room.textContent =
      "#noVNC_container{position:relative;top:24px;height:calc(100% - 24px)}" +
      "#noVNC_status{top:24px}";
    document.head.appendChild(room);

    var bar = document.createElement("div");
    bar.id = ID;
    bar.setAttribute("role", "status");
    bar.title = text;
    // z-index 99: above noVNC's canvas, control bar (10), transition screen
    // (50) and connect dialog (60), but below its status line (#noVNC_status,
    // 100) and fatal-error box (#noVNC_fallback_error, 1000), so "Disconnected"
    // and "Failed to connect to server" stay readable (noVNC 1.7.0
    // app/styles/base.css).
    bar.style.cssText =
      "position:fixed;top:0;left:0;right:0;z-index:99;" +
      "box-sizing:border-box;display:flex;align-items:center;" +
      "height:24px;padding:0 0.6em;background:#7a5a00;color:#ffffff;" +
      "font-family:system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;" +
      "font-size:13px;line-height:24px;text-align:left;cursor:default";

    var label = document.createElement("span");
    label.id = ID + "_text";
    label.style.cssText =
      "flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
    label.textContent = text;
    bar.appendChild(label);

    var close = document.createElement("button");
    close.type = "button";
    close.setAttribute("aria-label", "Hide notice");
    // Not in the tab order, and never focused by this script: the mousedown
    // handlers below stop a click from moving keyboard focus off the VNC
    // canvas.
    close.setAttribute("tabindex", "-1");
    // The escape, not the literal character: vnc.html declares no charset and
    // websockify sends none, so Chrome decodes this classic script as
    // windows-1252, where a raw UTF-8 byte would be mojibake.
    close.textContent = "\u00d7";
    // noVNC's input.css styles every <button> (min-width:8em, bold, a 6px
    // radius), which would make this a 128px-wide target that also takes
    // that width from the notice text: reset those, 24x24 like the bar.
    close.style.cssText =
      "flex:0 0 auto;min-width:0;width:24px;height:24px;margin:0 0 0 0.6em;" +
      "padding:0;border:0;border-radius:0;" +
      "background:transparent;color:#ffffff;font-family:inherit;" +
      "font-size:16px;font-weight:normal;line-height:24px;cursor:pointer";
    close.addEventListener("click", function () {
      if (bar.parentNode) {
        bar.parentNode.removeChild(bar);
      }
      if (room.parentNode) {
        room.parentNode.removeChild(room);
      }
    });
    // A press anywhere on the bar (the x included) must not move keyboard
    // focus: noVNC reads keys only on its canvas. The click still fires, so
    // the close button still hides the banner.
    bar.addEventListener("mousedown", function (event) {
      event.preventDefault();
    });
    close.addEventListener("mousedown", function (event) {
      event.preventDefault();
    });
    bar.appendChild(close);

    return bar;
  }

  // Set once a banner has been shown in this page load, closed or not: no
  // further fetches after that.
  var shown = false;

  function show(data) {
    if (!data || typeof data.text !== "string") {
      return;
    }
    var text = data.text.trim();
    if (!text || shown || !document.body || document.getElementById(ID)) {
      return;
    }
    shown = true;
    // Insert inside an animation frame. noVNC 1.7.0 (core/rfb.js
    // _handleResize) answers a ResizeObserver callback by queueing a frame
    // callback that records the screen's live size as the size it expects. A
    // banner inserted after that callback was queued but before it ran is
    // recorded as expected, the 24 px change is then ignored, and the remote
    // desktop keeps its old height with its bottom cut off (seen on a
    // reconnect). Frame callbacks run in the order they were queued, so
    // noVNC's runs first and sees the page without the banner.
    var insert = function () {
      document.body.insertBefore(build(text), document.body.firstChild);
    };
    if (typeof requestAnimationFrame === "function") {
      requestAnimationFrame(insert);
    } else {
      insert();
    }
  }

  function load() {
    if (shown) {
      return;
    }
    var request;
    try {
      request = fetch(SOURCE, { cache: "no-store", credentials: "same-origin" });
    } catch (e) {
      return; // No fetch in this browser: same as an empty notice.
    }
    request
      .then(function (response) {
        if (!response || !response.ok) {
          return null;
        }
        return response.json();
      })
      .then(show)
      .catch(function () {
        // No notice is not an error: the desktop works as if this file were
        // not here.
      });
  }

  load();

  // The page can come from the browser cache when the desktop is opened again
  // while it is down (the server sends no Cache-Control; a reload revalidates),
  // and once it is back noVNC connects without a page load (its own reconnect,
  // or the Connect button). So a failed first fetch (a 502/503 from the
  // gateway, a 404 while the service is not published) is tried again each
  // time noVNC connects, until a banner has been shown. noVNC 1.7.0 marks a
  // connection with the class noVNC_connected on <html> (app/ui.js
  // updateVisualState; the Dockerfile checks it is still there). No timer:
  // nothing runs while the desktop is down, and a desktop without a notice
  // costs one fetch per connect.
  var root = document.documentElement;
  if (root && root.classList && typeof MutationObserver === "function") {
    var connected = root.classList.contains("noVNC_connected");
    new MutationObserver(function () {
      var now = root.classList.contains("noVNC_connected");
      if (now && !connected) {
        load();
      }
      connected = now;
    }).observe(root, { attributes: true, attributeFilter: ["class"] });
  }
})();
