/* global Event, FormData, FileReader */

import Menu from "./Menu.js";
import Modal from "./Modal.js";
import Gallery from "./Gallery.js";
import {
  API_URL,
  API_SAVE,
  API_UPLOAD,
  SELECTOR_TITLE,
  SELECTOR_NOTE,
  SELECTOR_SORT_ORDER,
} from "./Constants.js";
import {
  areObjectsEqual,
  htmlToElement,
  isDomNode,
  isHexColor,
  mergeSettings,
  preventDefaults,
  processContentEditable,
  stripExtension,
  removeHtml,
  Fetch,
} from "./Helpers.js";

const MAX_CONCURRENT_UPLOADS = 3;
const TOAST_DURATION_MS = 4000;

// ---------------------------------------------------------------------------
// Toast — self-contained, no markup required in the host page
// ---------------------------------------------------------------------------

const Toast = (() => {
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
  function show(message, type = "error", duration = TOAST_DURATION_MS) {
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
      // animationend is unreliable when competing with the enter animation —
      // use a hard timeout as the primary removal path.
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

  return { show };
})();

/**
 * Provides editing capabilities.
 * Acts as interface between UI and API.
 *
 * State is maintained in-memory (_state). The DOM is treated as a view of
 * that state, never as a source of truth. Reads from DOM only happen on
 * user-initiated fields (title, note) that are contenteditable, where the
 * DOM is the canonical input surface.
 */
class Editor {
  /**
   * @param  {Object}   options
   * @param  {string}   options.dropAreaSelector
   * @param  {string}   options.fileInputSelector
   * @param  {string}   options.buttonPreviewSelector
   * @param  {string}   options.fullscreenDropZone
   * @param  {string}   options.bgColor
   * @param  {string}   options.textColor
   * @param  {string}   options.fontFamily
   * @param  {Gallery}  options.gallery
   * @param  {function} options.onUpdate
   * @param  {function} options.onError
   */
  constructor(options) {
    const defaults = {
      dropAreaSelector: "#drop-area",
      fileInputSelector: "#file-input",
      buttonPreviewSelector: ".editbutton.preview",
      gallery: new Gallery({
        gallerySelector: ".Gallery",
        imageSelector: ".Image",
        lazyloadSelector: ".lazy",
        active: false,
      }),
      fullscreenDropZone: true,
      bgColor: "#bbb",
      textColor: "#333",
      fontFamily: document.body.style.fontFamily,
      onUpdate: (_newData, _oldData) => {},
      onError: (context, err) => console.error(`[Editor] ${context}:`, err),
    };

    this.options = mergeSettings(options, defaults);

    // Initialize private color/font properties with default values
    this._bgColor = this.options.bgColor;
    this._textColor = this.options.textColor;
    this._fontFamily = this.options.fontFamily;

    // Bind all methods that are used as callbacks
    this.actionSave = this.actionSave.bind(this);
    this.actionCancel = this.actionCancel.bind(this);
    this.actionUpdate = this.actionUpdate.bind(this);
    this._processUploadQueue = this._processUploadQueue.bind(this);
    this._uploadProgressMessage = this._uploadProgressMessage.bind(this);

    // Upload queue state
    this._uploadQueue = [];
    this._activeUploads = 0;
    this._uploadTotal = 0; // total files enqueued in current batch
    this._uploadDone = 0; // completed (success or failure)
    this._uploadToast = null; // live progress toast handle
    this._isSaving = false;

    // In-memory state — single source of truth
    this._state = null;
    this._backup = null;

    // Event listener tracking for cleanup
    this._listeners = [];

    this.files = [];
    this.init(this.options);
  }

  // ---------------------------------------------------------------------------
  // Initialization
  // ---------------------------------------------------------------------------

  init(options) {
    const {
      bgColor,
      textColor,
      fontFamily,
      gallery,
      dropAreaSelector,
      fullscreenDropZone,
      fileInputSelector,
      onUpdate,
      onError,
    } = options;

    this._gallery = gallery;
    this._buttons = [];
    this._dropArea = document.querySelector(dropAreaSelector);
    this._fileInput = document.querySelector(fileInputSelector);
    this._fullscreenDropZone = Boolean(fullscreenDropZone);
    this.onUpdate = onUpdate;
    this.onError = onError;

    if (!this._gallery) {
      this.onError("init", "No Gallery provided — Editor cannot initialize.");
      return;
    }
    if (!this._dropArea) {
      this.onError(
        "init",
        `No drop area found for selector [${dropAreaSelector}] — Editor cannot initialize.`,
      );
      return;
    }
    if (!this._fileInput) {
      console.warn(
        `[Editor] No file input found for selector [${fileInputSelector}] — upload via file input is disabled.`,
      );
    }

    // Read CSRF token once at init, fail loudly if missing
    this._csrfToken = this._readCsrfToken(this._dropArea);
    if (!this._csrfToken) {
      this.onError(
        "init",
        "CSRF token not found in drop area — uploads will fail.",
      );
    }

    this._menu = new Menu();
    this._modal = new Modal({
      target: ".modal",
      active: true,
      triggers: ".modal__bg, .modal__close",
    });

    // Apply initial display properties
    this._applyBgColor(bgColor);
    this._applyTextColor(textColor);
    this._applyFontFamily(fontFamily);

    // Snapshot state after DOM is ready — this is the restore point for Cancel
    this._state = this._readStateFromDom();
    this._backup = this._cloneState(this._state);

    this.initListeners();

    const sortOrderSelect = document.querySelector(SELECTOR_SORT_ORDER);
    if (sortOrderSelect) {
      sortOrderSelect.addEventListener("change", (e) => {
        this._state.sortorder = e.target.value;
        this._gallery.setImages(this._gallery.images, this._state.sortorder);
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Ties a button to the Editor's menu object.
   * @param {Object} options — refer to Menu class
   */
  addButton(options) {
    const button = this.menu.addButton(options);
    if (button) {
      this._buttons.push(button);
    }
  }

  /**
   * Saves the current state if it differs from the last saved backup.
   * No-ops if a save is already in flight.
   */
  actionSave() {
    if (this._isSaving) return;
    const state = this._collectCurrentState();
    if (!areObjectsEqual(state, this._backup)) {
      this._saveData(state);
    }
  }

  /**
   * Restores to the last saved backup if state has drifted.
   * No-ops if a save is already in flight.
   */
  actionCancel() {
    if (this._isSaving) return;
    if (!areObjectsEqual(this._collectCurrentState(), this._backup)) {
      this._saveData(this._cloneState(this._backup));
    }
  }

  /**
   * Marks an image for deletion.
   * @param {Event} e
   */
  editDeleteImage(e) {
    if (!this._state?.images) return;
    const id = this._getIdFromEvent(e);
    if (id) {
      this._gallery.removeImageById(id);
      this._state.images = this._state.images.filter((img) => img.id !== id);
    }
  }

  /**
   * Recovers a previously deleted image.
   * @param {Event} e
   */
  editRevertImage(e) {
    if (!this._state?.images) return;
    const id = this._getIdFromEvent(e);
    if (id) {
      this._gallery.revertRemoveImageById(id);
      // Restore image entry in state from backup
      const reverted = this._backup.images.find((img) => img.id === id);
      if (reverted && !this._state.images.find((img) => img.id === id)) {
        this._state.images.push({ ...reverted });
      }
    }
  }

  /**
   * Updates the view and internal state from API response data.
   * @param {object} data
   */
  actionUpdate(data) {
    const { images, title, note, bgcolor, textcolor, fontfamily, sortorder } =
      data;

    if (Array.isArray(images)) {
      this._gallery.setImages(images, sortorder);
      this._gallery.images.forEach((image) => this.addControlsToImage(image));
      this._state.images = images.map((img) => ({ ...img }));
    }
    if (title !== undefined) {
      const titleEl = document.querySelector(SELECTOR_TITLE);
      if (titleEl) titleEl.innerHTML = title;
      this._state.title = removeHtml(title);
    }
    if (note !== undefined) {
      const noteEl = document.querySelector(SELECTOR_NOTE);
      if (noteEl) {
        const html = htmlToElement("<div>" + note + "</div>");
        noteEl.replaceChildren(html);
      }
      this._state.note = processContentEditable(note);
    }
    if (bgcolor && isHexColor(bgcolor)) {
      this._applyBgColor(bgcolor);
      this._state.bgcolor = bgcolor;
    }
    if (textcolor && isHexColor(textcolor)) {
      this._applyTextColor(textcolor);
      this._state.textcolor = textcolor;
    }
    if (fontfamily) {
      this._applyFontFamily(fontfamily);
      this._state.fontfamily = fontfamily;
    }
    if (sortorder !== undefined) {
      this._state.sortorder = sortorder;
    }
  }

  // ---------------------------------------------------------------------------
  // Listeners
  // ---------------------------------------------------------------------------

  initListeners() {
    const events = ["dragenter", "dragover", "dragleave", "drop"];
    events.forEach((eventName) => {
      this._dropArea.addEventListener(eventName, preventDefaults, false);
      this._listeners.push({
        el: this._dropArea,
        event: eventName,
        fn: preventDefaults,
      });
      document.body.addEventListener(eventName, preventDefaults, false);
      this._listeners.push({
        el: document.body,
        event: eventName,
        fn: preventDefaults,
      });
    });

    if (this._fullscreenDropZone) {
      const dragEnterHandler = () => this._dropArea.classList.add("active");
      document.addEventListener("dragenter", dragEnterHandler, true);
      this._listeners.push({
        el: document,
        event: "dragenter",
        fn: dragEnterHandler,
      });

      const dragLeaveHandler = () => this._dropArea.classList.remove("active");
      this._dropArea.addEventListener("dragleave", dragLeaveHandler);
      this._listeners.push({
        el: this._dropArea,
        event: "dragleave",
        fn: dragLeaveHandler,
      });

      const dropHandler = () => this._dropArea.classList.remove("active");
      this._dropArea.addEventListener("drop", dropHandler);
      this._listeners.push({
        el: this._dropArea,
        event: "drop",
        fn: dropHandler,
      });
    }

    ["dragenter", "dragover"].forEach((eventName) => {
      this._dropArea.addEventListener(eventName, () => this.highlight(), false);
      this._listeners.push({
        el: this._dropArea,
        event: eventName,
        fn: () => this.highlight(),
      });
    });
    ["dragleave", "drop"].forEach((eventName) => {
      this._dropArea.addEventListener(
        eventName,
        () => this.unhighlight(),
        false,
      );
      this._listeners.push({
        el: this._dropArea,
        event: eventName,
        fn: () => this.unhighlight(),
      });
    });

    const dropHandler = (e) => this.handleDrop(e);
    this._dropArea.addEventListener("drop", dropHandler, false);
    this._listeners.push({
      el: this._dropArea,
      event: "drop",
      fn: dropHandler,
    });

    if (this._fileInput) {
      const fileInputHandler = (e) => {
        if (e.target?.files) {
          this.handleFiles(e.target.files);
        }
      };
      this._fileInput.addEventListener("change", fileInputHandler);
      this._listeners.push({
        el: this._fileInput,
        event: "change",
        fn: fileInputHandler,
      });
    }

    // Add controls to existing gallery images — only once
    this._gallery.images.forEach((image) => this.addControlsToImage(image));
  }

  // ---------------------------------------------------------------------------
  // Image controls
  // ---------------------------------------------------------------------------

  /**
   * Attaches delete/revert controls to an image. Idempotent — will not
   * double-attach if called again on the same image.
   * @param {Image} image
   */
  addControlsToImage(image) {
    if (image.dom.querySelector(".Image__controls")) return;

    const deleteButton = this._getImageButton("╳", "button--delete", image.id);
    const revertButton = this._getImageButton("⏪", "button--revert", image.id);
    const imageControls = htmlToElement('<div class="Image__controls"></div>');

    imageControls.appendChild(deleteButton);
    imageControls.appendChild(revertButton);
    image.dom.appendChild(imageControls);

    this.menu.addButton({
      type: "toggle",
      domNode: deleteButton,
      domNode2: revertButton,
      callback: this.editDeleteImage.bind(this),
      callback2: this.editRevertImage.bind(this),
    });
  }

  // ---------------------------------------------------------------------------
  // Styling setters/getters
  // ---------------------------------------------------------------------------

  set bgColor(color) {
    this._applyBgColor(color);
  }
  get bgColor() {
    return this._bgColor;
  }

  set textColor(color) {
    this._applyTextColor(color);
  }
  get textColor() {
    return this._textColor;
  }

  set fontFamily(fontfamily) {
    this._applyFontFamily(fontfamily);
  }
  get fontFamily() {
    return this._fontFamily;
  }

  get buttons() {
    return this._buttons;
  }
  get gallery() {
    return this._gallery;
  }
  get menu() {
    return this._menu;
  }

  /**
   * Cleanup method to remove all event listeners and reset state.
   * Call this when destroying the Editor instance to prevent memory leaks.
   */
  destroy() {
    // Remove all tracked event listeners
    this._listeners.forEach(({ el, event, fn }) => {
      el.removeEventListener(event, fn);
    });
    this._listeners = [];

    // Clear upload queue
    this._uploadQueue = [];

    // Dismiss any active toasts
    if (this._uploadToast) {
      this._uploadToast.dismiss();
      this._uploadToast = null;
    }

    // Null out references
    this._state = null;
    this._backup = null;
    this._gallery = null;
    this._menu = null;
    this._modal = null;
    this._dropArea = null;
    this._fileInput = null;
  }

  // ---------------------------------------------------------------------------
  // File handling
  // ---------------------------------------------------------------------------

  handleDrop(e) {
    const files = [...e.dataTransfer.files].filter((f) =>
      f.type.match(/image.*/),
    );
    if (files.length > 0) {
      this.handleFiles(files);
    }
  }

  /**
   * Enqueues files for upload and starts processing up to MAX_CONCURRENT_UPLOADS
   * at once. Progress is shown in a live toast that updates as files complete.
   * @param {FileList|File[]} files
   */
  handleFiles(files) {
    const fileArray = [...files];

    // Accumulate into the running batch so mid-flight drops add to the total
    this._uploadTotal += fileArray.length;
    fileArray.forEach((file) => this._uploadQueue.push(file));

    this._uploadToast ??= Toast.show(
      this._uploadProgressMessage(),
      "info",
      0, // sticky — we dismiss it ourselves
    );

    this._processUploadQueue();
  }

  // ---------------------------------------------------------------------------
  // Private: upload queue
  // ---------------------------------------------------------------------------

  _processUploadQueue() {
    try {
      while (
        this._uploadQueue.length > 0 &&
        this._activeUploads < MAX_CONCURRENT_UPLOADS
      ) {
        const file = this._uploadQueue.shift();
        this._activeUploads++;

        // We wrap the entire execution in a promise chain to catch
        // synchronous errors (like a failing formData.append or a missing method)
        Promise.resolve()
          .then(() => this._uploadFile(file))
          .then((result) => {
            if (result?.data?.length && result.data[0]) {
              const fileData = result.data[0];
              this.previewFile(file, fileData.name);
              this.files.push(fileData);
              this._state.images.push({
                id: fileData.id ?? fileData.name,
                filename: fileData.name,
                newfilename: stripExtension(fileData.name),
              });
            }
          })
          .catch((err) => {
            this.onError("upload", err);
            Toast.show(`Upload failed: "${file.name}"`, "error");
          })
          .finally(() => {
            this._activeUploads--;
            this._uploadDone++;

            const done = this._uploadDone;
            const total = this._uploadTotal;
            const isQueueEmpty = this._uploadQueue.length === 0;
            const isProcessingComplete =
              this._activeUploads === 0 && isQueueEmpty;

            this._uploadToast?.update(
              isProcessingComplete
                ? `Uploaded ${total} ${total === 1 ? "file" : "files"}`
                : `Uploading… ${done} / ${total}`,
            );

            if (isProcessingComplete) {
              const toast = this._uploadToast;
              this._uploadToast = null;
              this._uploadTotal = 0;
              this._uploadDone = 0;
              setTimeout(() => toast?.dismiss(), 1200);
            }

            // Trigger the next items in the queue
            this._processUploadQueue();
          });
      }
    } catch (err) {
      // Reset counters on synchronous errors
      this._uploadTotal = 0;
      this._uploadDone = 0;
      this._uploadQueue = [];
      this.onError("upload", err);
    }
  }

  /**
   * Generates the initial progress message for the upload toast.
   * @returns {string}
   */
  _uploadProgressMessage() {
    return `Uploading… 0 / ${this._uploadTotal}`;
  }

  // ---------------------------------------------------------------------------
  // Private: save/load
  // ---------------------------------------------------------------------------

  _saveData(data) {
    this._isSaving = true;
    const saveToast = Toast.show("Saving…", "info", 0);

    this._uploadData(data)
      .then((res) => {
        this.actionUpdate(res.data);
        this.onUpdate(res.data, this._backup);
        this._backup = this._cloneState(this._collectCurrentState());
        saveToast.update("Saved ✓");
        setTimeout(() => saveToast.dismiss(), 1200);
      })
      .catch((err) => {
        this.onError("save", err);
        saveToast.dismiss();
        Toast.show("Save failed. Please try again.", "error");
      })
      .finally(() => {
        this._isSaving = false;
      });
  }

  _uploadData(data) {
    const api = new Fetch();
    const formData = new FormData();

    formData.append("data", JSON.stringify(data));
    formData.append("action", API_SAVE);
    formData.append("csrf_token", this._csrfToken);

    return api.newRequest(API_URL, formData);
  }

  _uploadFile(file) {
    const api = new Fetch();
    const formData = new FormData();

    formData.append("file", file);
    formData.append("action", API_UPLOAD);
    formData.append("csrf_token", this._csrfToken);

    return api.newRequest(API_URL, formData);
  }

  // ---------------------------------------------------------------------------
  // Private: state helpers
  // ---------------------------------------------------------------------------

  /**
   * Collects the full current state. For contenteditable fields (title, note)
   * the DOM is authoritative since the user types directly into it.
   * Everything else is read from this._state.
   * @returns {object}
   */
  _collectCurrentState() {
    const state = this._cloneState(this._state);

    const titleEl = document.querySelector(SELECTOR_TITLE);
    if (titleEl) state.title = removeHtml(titleEl.innerHTML);

    const noteEl = document.querySelector(SELECTOR_NOTE);
    if (noteEl) state.note = processContentEditable(noteEl.innerHTML);

    // Sync caption edits from DOM back into state
    state.images = this._gallery.images.map((image) => ({
      id: image.id,
      filename: image.filename,
      newfilename: removeHtml(image.caption),
    }));

    const sortOrderEl = document.querySelector(SELECTOR_SORT_ORDER);
    if (sortOrderEl) state.sortorder = sortOrderEl.value;

    // CRITICAL: Include current color/font values from private properties
    // Setters update these properties but not this._state, so we must include them here
    state.bgcolor = this._bgColor;
    state.textcolor = this._textColor;
    state.fontfamily = this._fontFamily;

    return state;
  }

  /**
   * Reads the initial state from the DOM at page load.
   * Only called once during init.
   * @returns {object}
   */
  _readStateFromDom() {
    const state = {
      title: "",
      note: "",
      images: [],
      bgcolor: this._bgColor,
      textcolor: this._textColor,
      fontfamily: this._fontFamily,
      sortorder: "asc",
    };

    const titleEl = document.querySelector(SELECTOR_TITLE);
    if (titleEl) state.title = removeHtml(titleEl.innerHTML);

    const noteEl = document.querySelector(SELECTOR_NOTE);
    if (noteEl) state.note = processContentEditable(noteEl.innerHTML);

    state.images = this._gallery.images.map((image) => ({
      id: image.id,
      filename: image.filename,
      newfilename: removeHtml(image.caption),
    }));

    const sortOrderEl = document.querySelector(SELECTOR_SORT_ORDER);
    if (sortOrderEl) state.sortorder = sortOrderEl.value;

    return state;
  }

  _cloneState(state) {
    // Deep clone via JSON — state contains only serializable data (strings, arrays, objects)
    // This is intentional: Editor state should never contain non-serializable values
    return JSON.parse(JSON.stringify(state));
  }

  // ---------------------------------------------------------------------------
  // Private: display helpers
  // ---------------------------------------------------------------------------

  _applyBgColor(color) {
    if (isHexColor(color)) {
      this._bgColor = color;
      document.body.style.backgroundColor = color;
    }
  }

  _applyTextColor(color) {
    if (isHexColor(color)) {
      this._textColor = color;
      document.body.style.color = color;
    }
  }

  _applyFontFamily(fontfamily) {
    if (fontfamily) {
      this._fontFamily = fontfamily;
      document.body.style.fontFamily = fontfamily;
    }
  }

  _getImageButton(content, buttonClass, id) {
    return htmlToElement(
      `<div class="pure-button ${buttonClass}" data-id="${id}"><span>${content}</span></div>`,
    );
  }

  _getIdFromEvent(e) {
    if (!e) return null;
    return (
      e.target?.getAttribute("data-id") ||
      e.target?.parentNode?.getAttribute("data-id") ||
      null
    );
  }

  /**
   * Reads CSRF token from a DOM node. Called once at init.
   * @param {Element} domNode
   * @returns {string}
   */
  _readCsrfToken(domNode) {
    if (domNode && isDomNode(domNode)) {
      const input = domNode.querySelector("[name=csrf_token]");
      return input?.value ?? "";
    }
    return "";
  }

  // ---------------------------------------------------------------------------
  // Drop zone highlight
  // ---------------------------------------------------------------------------

  highlight() {
    this._dropArea.classList.add("highlight");
  }

  unhighlight() {
    // Only unhighlight if drag truly left the drop area (not over child elements)
    if (!this._dropArea.contains(event?.relatedTarget)) {
      this._dropArea.classList.remove("highlight");
    }
  }

  // ---------------------------------------------------------------------------
  // Preview (unchanged behavior, kept for API compatibility)
  // ---------------------------------------------------------------------------

  previewFile(file, filename) {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onloadend = () => {
      const image = this._gallery.addImage(
        this._getPreviewDom(reader.result, filename),
      );
      if (image) {
        this.addControlsToImage(image);
      }
    };
  }

  _getPreviewDom(src, filename) {
    if (!src) return null;
    return htmlToElement(`<div class="Image">
      <div class="Image__container">
        <img class="lazy miniarch" src="./assets/css/loading.gif" data-src="${src}" data-filename="${filename}" title="${filename} preview" />
      </div>
      <div class="Image__caption"><span contenteditable="true">${stripExtension(filename)}</span></div>
    </div>`);
  }
}

export default Editor;
