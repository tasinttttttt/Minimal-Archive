/* global CustomEvent, Event */

import {
  EVENT_RESET,
  EVENT_STATUS_CHANGE,
  EVENT_IMAGE_UPDATE,
  EVENT_NEXT_IMAGE,
} from "./Constants.js";

import {
  isDomNode,
  uuidv4,
  htmlToElement,
  mergeSettings,
  removeHtml,
} from "./Helpers.js";

class Image {
  constructor(options) {
    const defaults = {
      dom: null,
      filename: null,
      active: true,
      url: null,
      caption: null,
      imageSelector: ".Image",
      lazyloadSelector: ".lazy",
      editable: false,
    };
    const { url, filename, caption, dom, active, editable } = mergeSettings(
      options,
      defaults,
    );

    // Fix: arrow class fields replace manual bind boilerplate
    this.applyStyle = () => {
      if (this._dom) {
        if (this._status) {
          this._dom.classList.add("Image--active");
          this._dom.classList.remove("Image--inactive");
        } else {
          this._dom.classList.remove("Image--active");
          this._dom.classList.add("Image--inactive");
        }
      }
    };

    this.resetStatus = () => this._setStatus(false);
    this.toggleStatus = () => this._setStatus(!this._status);
    this.handleClick = () => {
      if (this._status === true) {
        this.nextImage();
      } else {
        this.toggleStatus();
      }
    };
    this.nextImage = () => document.dispatchEvent(new Event(EVENT_NEXT_IMAGE));
    this.updateCaption = () => {
      if (this._captionSelector) {
        this._caption = removeHtml(this._captionSelector.innerHTML);
      }
    };

    // Setting state
    this._id = uuidv4();
    this._dom = isDomNode(dom) ? dom : this.generateDom(url, filename, caption);
    if (!this._dom) {
      console.warn("%o is not a dom element. Can't get image dom.", dom);
    }
    this._src = url;
    this._caption = removeHtml(caption);
    this._filename = filename;
    this._captionSelector =
      this._dom && this._dom.querySelector("[contenteditable]");
    this._active = active;
    this._status = false;
    this._editable = editable;

    // Initializing style and initial listeners
    this.applyStyle();
    if (this._active) {
      this.activate(true);
    }
    if (this._editable && this._captionSelector) {
      this._captionSelector.addEventListener("input", this.updateCaption);
    }
  }

  activate(force) {
    if (force || !this._active) {
      this._active = true;
      this.initListeners();
    }
  }

  deactivate(force) {
    if (force || this._active) {
      this._active = false;
      this.removeListeners();
    }
  }

  initListeners() {
    if (this._dom) {
      this._dom.addEventListener("click", this.handleClick);
    }
    document.addEventListener(EVENT_RESET, this.resetStatus);
  }

  removeListeners() {
    if (this._dom) {
      this._dom.removeEventListener("click", this.handleClick);
    }
    document.removeEventListener(EVENT_RESET, this.resetStatus);
  }

  // Fix: single unified private method for all status changes — setter, toggle, and reset
  // all go through here, ensuring EVENT_STATUS_CHANGE and EVENT_IMAGE_UPDATE always fire together
  _setStatus(value) {
    this._status = value;
    this.applyStyle();
    if (this._dom) {
      this._dom.dispatchEvent(new Event(EVENT_STATUS_CHANGE));
    }
    document.dispatchEvent(
      new CustomEvent(EVENT_IMAGE_UPDATE, {
        detail: { image: this._status ? this : null },
      }),
    );
  }

  generateDom(src, filename, caption) {
    if (!src) return null;
    // Fix: sanitize all interpolated values including title
    return htmlToElement(`<div class="Image">
      <div class="Image__container">
        <img class="lazy miniarch" src="./assets/css/loading.gif" data-src="${removeHtml(src)}" data-filename="${removeHtml(filename)}" title="${removeHtml(filename)} preview" />
      </div>
      <div class="Image__caption"><span contenteditable="true">${removeHtml(caption) ?? ""}</span></div>
      </div>`);
  }

  // Fix: add destroy to clean up caption listener, which removeListeners doesn't cover
  destroy() {
    this.deactivate(true);
    if (this._captionSelector) {
      this._captionSelector.removeEventListener("input", this.updateCaption);
    }
    this._dom = null;
    this._captionSelector = null;
  }

  // Fix: expose as getter to match the rest of the accessor interface
  get id() {
    return this._id;
  }

  // Fix: removed surprising generateDom fallback — dom getter returns what's stored
  get dom() {
    return this._dom;
  }
  set dom(dom) {
    this._dom = dom;
  }

  get status() {
    return this._status;
  }
  // Fix: status setter goes through _setStatus so both events always fire
  set status(value) {
    this._setStatus(value);
  }

  get caption() {
    return this._caption;
  }
  set caption(caption) {
    this._caption = caption;
  }

  get filename() {
    return this._filename;
  }
  set filename(filename) {
    this._filename = removeHtml(filename);
  }

  get src() {
    return this._src;
  }
  set src(src) {
    this._src = removeHtml(src);
  }
}

export default Image;
