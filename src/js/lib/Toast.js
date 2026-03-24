import { htmlToElement } from "./Helpers.js";

const TOAST_DURATION_MS = 4000;
let container = null;

function getContainer() {
  if (!container) {
    container = htmlToElement(
      `<div class="Toast__container" aria-live="polite" aria-atomic="false"></div>`,
    );
    document.body.appendChild(container);
  }
  return container;
}

/**
 * @param {string} message
 * @param {'error'|'info'|'success'} type
 * @param {number} duration  ms before auto-dismiss (0 = sticky)
 * @returns {{ update: (msg: string) => void, dismiss: () => void }}
 */
export function show(message, type = "error", duration = TOAST_DURATION_MS) {
  const toast = htmlToElement(`
    <div class="Toast Toast--${type}" role="alert">
      <span class="Toast__message">${message}</span>
      <button class="Toast__close" aria-label="Dismiss">✕</button>
    </div>
  `);

  const msgEl = toast.querySelector(".Toast__message");
  let dismissTimer = null;
  let dismissed = false;

  const remove = () => {
    if (toast.parentNode) toast.remove();
  };

  const dismiss = () => {
    if (dismissed) return;
    dismissed = true;
    clearTimeout(dismissTimer);
    toast.classList.add("Toast--leaving");
    setTimeout(remove, 300);
  };

  const update = (msg) => {
    msgEl.textContent = msg;
  };

  toast.querySelector(".Toast__close").addEventListener("click", dismiss);

  if (duration > 0) {
    dismissTimer = setTimeout(dismiss, duration);
  }

  getContainer().appendChild(toast);
  return { update, dismiss };
}

export default { show };
