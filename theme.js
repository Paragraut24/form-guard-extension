/**
 * theme.js — Shared theme management for PhishGuard
 * Handles loading, applying, and persisting the dark/light theme preference.
 * Can be used as a module or as a plain script.
 */

const ThemeManager = (() => {
  const STORAGE_KEY = 'phishguard_theme';
  const DEFAULT_THEME = 'dark';

  /** Apply a theme to the document root */
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  /** Load stored theme and apply immediately (call early to avoid flash) */
  async function loadAndApply() {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEY);
      const theme = result[STORAGE_KEY] || DEFAULT_THEME;
      applyTheme(theme);
      return theme;
    } catch {
      applyTheme(DEFAULT_THEME);
      return DEFAULT_THEME;
    }
  }

  /** Save a theme to storage and apply it */
  async function setTheme(theme) {
    applyTheme(theme);
    try {
      await chrome.storage.local.set({ [STORAGE_KEY]: theme });
    } catch (e) {
      console.warn('ThemeManager: could not persist theme', e);
    }
  }

  /** Toggle between dark and light */
  async function toggle() {
    const current = document.documentElement.getAttribute('data-theme') || DEFAULT_THEME;
    const next = current === 'dark' ? 'light' : 'dark';
    await setTheme(next);
    return next;
  }

  /** Read current applied theme */
  function current() {
    return document.documentElement.getAttribute('data-theme') || DEFAULT_THEME;
  }

  return { loadAndApply, setTheme, toggle, current, applyTheme };
})();
