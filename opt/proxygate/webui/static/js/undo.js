/**
 * undo.js — Shared global undo stack for deletions across the Rules and
 * Proxies panels. One combined history (max 20 entries) ordered by deletion
 * time, so Ctrl+Z always undoes whichever was deleted most recently,
 * regardless of which panel it came from or which panel currently has
 * a selection.
 *
 * rules.js / proxies.js each register a restorer for their entry "type" via
 * registerRestorer(type, fn); push({type, ...}) whenever they delete
 * something. This file owns the Ctrl+Z key handling and the stack itself;
 * it has no knowledge of rules/proxies data shapes.
 */

(function () {
  "use strict";

  const MAX_HISTORY = 20;
  let stack = []; // most recent last; pop() undoes the latest deletion of either type
  const restorers = {}; // type -> async (entry) => void

  function push(entry) {
    stack.push(entry);
    if (stack.length > MAX_HISTORY) stack.shift();
  }

  function registerRestorer(type, fn) {
    restorers[type] = fn;
  }

  async function undo() {
    if (!stack.length) return;
    const entry = stack.pop();
    const restore = restorers[entry.type];
    if (!restore) return;
    try {
      await restore(entry);
    } catch (e) {
      stack.push(entry); // restore attempt failed — put it back for another try
      PG.log.error("undo", "Restore failed", { type: entry.type, error: e.message });
    }
  }

  function isModalOpen() {
    const backdrop = document.getElementById("modal-backdrop");
    return backdrop && !backdrop.classList.contains("hidden");
  }

  function isTypingTarget(el) {
    if (!el) return false;
    const tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
  }

  function onKeyDown(e) {
    if (isModalOpen() || isTypingTarget(e.target)) return;
    if (e.ctrlKey && e.key.toLowerCase() === "z") {
      e.preventDefault();
      undo();
    }
  }

  document.addEventListener("keydown", onKeyDown);

  window.PG = window.PG || {};
  window.PG.undoStack = { push, registerRestorer };
})();
