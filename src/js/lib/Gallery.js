/* global Event */

import LazyLoad from "./LazyLoad.js";
import Image from "./Image.js";
import {
  EVENT_IMAGE_UPDATE,
  EVENT_NEXT_IMAGE,
  EVENT_RESET,
} from "./Constants.js";
import {
  basename,
  htmlToElement,
  isDomNode,
  mergeSettings,
  stripExtension,
} from "./Helpers.js";

class Gallery {
  /**
   * @param {Object}  options
   * @param {string}  options.gallerySelector
   * @param {string}  options.imageSelector
   * @param {string}  options.lazyloadSelector
   * @param {boolean} options.active
   */
  constructor(options) {
    const defaults = {
      gallerySelector: ".Gallery",
      imageSelector: ".Image",
      lazyloadSelector: ".lazy",
      active: true,
    };
    const { gallerySelector, imageSelector, lazyloadSelector, active } =
      mergeSettings(options, defaults);

    // Bind callbacks once — keeps listener identity stable for add/removeEventListener
    this.keyHandler = this.keyHandler.bind(this);
    this.updateImage = this.updateImage.bind(this);
    this.next = this.next.bind(this);
    this.prev = this.prev.bind(this);

    this._active = false; // will be set properly by activate/deactivate below
    this._current = null;
    this._imageSelector = imageSelector;

    this._gallery = document.querySelector(gallerySelector);
    if (!this._gallery) {
      console.warn(
        `[Gallery] No DOM node found for selector "${gallerySelector}". Adding images may fail.`,
      );
    }

    this._images = this._initializeImages(imageSelector, active);
    // Backup keeps the original set for revert. Use a separate shallow clone.
    this._imagesBackup = [...this._images];

    this._lazyload = new LazyLoad({ elements_selector: lazyloadSelector });

    // Activate or deactivate, applying all side effects via the proper methods
    if (active) {
      this.activate(true);
    } else {
      this.deactivate(true);
    }
  }

  // ---------------------------------------------------------------------------
  // Activation lifecycle
  // ---------------------------------------------------------------------------

  activate(force = false) {
    if (!force && this._active) return;
    this._active = true;
    this._gallery?.classList.remove("Gallery--inactive");
    this._gallery?.classList.add("Gallery--active");
    this._initListeners();
  }

  deactivate(force = false) {
    if (!force && !this._active) return;
    this._active = false;
    this._gallery?.classList.remove("Gallery--active");
    this._gallery?.classList.add("Gallery--inactive");
    this._removeListeners();
    this._deactivateImages();
  }

  toggleActive() {
    this._active ? this.deactivate(true) : this.activate(true);
  }

  // ---------------------------------------------------------------------------
  // Listener setup / teardown
  // ---------------------------------------------------------------------------

  _initListeners() {
    document.addEventListener(EVENT_IMAGE_UPDATE, this.updateImage);
    document.addEventListener(EVENT_NEXT_IMAGE, this.next);
    document.addEventListener("keyup", this.keyHandler);
    this._activateImages();
  }

  _removeListeners() {
    document.removeEventListener(EVENT_IMAGE_UPDATE, this.updateImage);
    document.removeEventListener(EVENT_NEXT_IMAGE, this.next);
    document.removeEventListener("keyup", this.keyHandler);
    this._deactivateImages();
  }

  _activateImages() {
    this._images.forEach((image) => image.activate());
  }

  _deactivateImages() {
    this._images.forEach((image) => image.deactivate());
  }

  // ---------------------------------------------------------------------------
  // Image management
  // ---------------------------------------------------------------------------

  /**
   * Replaces the gallery contents from a plain data array.
   * Accepts objects with at least { filename, src } — no stale Image refs needed.
   *
   * @param {Array<{filename: string, src?: string, _dom?: Element}>} images
   * @param {string} sortOrder  "asc" | "desc"
   */
  setImages(images, sortOrder = "asc") {
    if (!images?.length) {
      this._removeListeners();
      this._images = [];
      this._current = null;
      this._gallery?.replaceChildren();
      return;
    }

    // Normalize to plain { filename, src } snapshots before clearing the gallery.
    //
    // Two possible inputs:
    //   1. Gallery Image instances (e.g. sort order change) — src lives in the
    //      live DOM as data-src (img.src is the loading gif while lazy-loading
    //      is pending). Must be read BEFORE replaceChildren() detaches the nodes.
    //   2. Plain API response objects (e.g. after save) — src comes directly
    //      from the server as image.src or image.url.
    const snapshots = images.map((image) => ({
      filename: image.filename,
      src:
        image.dom?.querySelector("img")?.getAttribute("data-src") ?? // Image instance
        image.src ?? // plain API object
        image.url ?? // fallback field name
        null,
    }));

    // Now safe to tear down
    this._removeListeners();
    this._images = [];
    this._current = null;
    this._gallery?.replaceChildren();

    const collator = new Intl.Collator("en", {
      numeric: true,
      sensitivity: "base",
    });

    snapshots
      .sort((a, b) => {
        const cmp = collator.compare(a.filename ?? "", b.filename ?? "");
        return sortOrder === "desc" ? -cmp : cmp;
      })
      .forEach(({ src, filename }) => {
        if (src && filename) {
          this.addImage(this._buildImageDom(src, filename));
        }
      });

    // Re-attach listeners now that images are in place
    if (this._active) {
      this._initListeners();
    }
  }

  /**
   * Adds a single image DOM node to the gallery. Idempotent with respect to
   * DOM insertion — won't insert if the node is already in the document.
   *
   * @param  {Element} dom
   * @returns {Image|null}
   */
  addImage(dom) {
    const image = this._buildImage(dom, this._active);
    if (!image) return null;

    if (!document.body.contains(dom) && this._gallery) {
      const existing = this._gallery.querySelectorAll(this._imageSelector);
      if (existing.length) {
        existing[existing.length - 1].after(dom);
      } else {
        this._gallery.appendChild(dom);
      }
    }

    this._images.push(image);
    this._imagesBackup = [...this._images];
    this._lazyload.update();
    return image;
  }

  /**
   * Marks an image for deletion (removes from active set, keeps DOM for revert).
   * @param {string|number} id
   * @returns {Image[]} updated images array
   */
  removeImageById(id) {
    const target = this._images.find((img) => img.id === id);
    if (target) {
      target.dom.classList.add("Image--markedfordeletion");
      this._images = this._images.filter((img) => img.id !== id);
    }
    return this._images;
  }

  /**
   * Reverts a deletion — restores image from backup into the active set.
   * @param {string|number} id
   * @returns {Image[]} updated images array
   */
  revertRemoveImageById(id) {
    const alreadyActive = this._images.some((img) => img.id === id);
    if (alreadyActive) return this._images;

    const match = this._imagesBackup.find((img) => img.id === id);
    if (match) {
      match.dom.classList.remove("Image--markedfordeletion");
      this._images.push(match);
    }
    return this._images;
  }

  // ---------------------------------------------------------------------------
  // Current image / navigation
  // ---------------------------------------------------------------------------

  updateImage(e) {
    const image = e?.detail?.image instanceof Image ? e.detail.image : null;
    this._setCurrentImage(image);
  }

  _setCurrentImage(image) {
    if (this._current instanceof Image) {
      this._current.status = false;
    }
    this._current = image;
    if (this._current instanceof Image) {
      this._current.status = true;
      this._current.dom.scrollIntoView({ behavior: "smooth" });
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  next() {
    if (!this._images.length) return;
    const index = this._images.indexOf(this._current);
    if (index === -1) {
      // Nothing selected — select first
      this._setCurrentImage(this._images[0]);
    } else if (index < this._images.length - 1) {
      this._setCurrentImage(this._images[index + 1]);
    } else {
      // Wrap around
      this._setCurrentImage(this._images[0]);
    }
  }

  prev() {
    if (!this._images.length) return;
    const index = this._images.indexOf(this._current);
    if (index === -1) {
      this._setCurrentImage(this._images[this._images.length - 1]);
    } else if (index > 0) {
      this._setCurrentImage(this._images[index - 1]);
    } else {
      // Wrap around
      this._setCurrentImage(this._images[this._images.length - 1]);
    }
  }

  keyHandler(e) {
    switch (e.key) {
      case "ArrowLeft":
        if (this._current) {
          e.preventDefault();
          this.prev();
        }
        break;
      case "ArrowRight":
        if (this._current) {
          e.preventDefault();
          this.next();
        }
        break;
      case "Escape":
        this.reset();
        break;
    }
  }

  reset() {
    document.dispatchEvent(new Event(EVENT_RESET));
  }

  // ---------------------------------------------------------------------------
  // Teardown
  // ---------------------------------------------------------------------------

  destroy() {
    this.deactivate(true);
    this._lazyload?.destroy();
    this._images = [];
    this._imagesBackup = [];
    this._current = null;
    this._gallery = null;
  }

  // ---------------------------------------------------------------------------
  // Accessors
  // ---------------------------------------------------------------------------

  set current(image) {
    this._setCurrentImage(image);
  }
  get current() {
    return this._current;
  }

  get images() {
    return this._images;
  }
  set images(images) {
    this._images = images;
  }

  // ---------------------------------------------------------------------------
  // Private: DOM builders
  // ---------------------------------------------------------------------------

  _initializeImages(selector, active) {
    const nodes = document.querySelectorAll(selector);
    const result = [];
    nodes.forEach((node) => {
      const image = this._buildImage(node, active);
      if (image) result.push(image);
    });
    return result;
  }

  /**
   * Constructs an Image instance from a DOM node.
   * Returns null if the node is invalid.
   * @param {Element} dom
   * @param {boolean} active
   * @returns {Image|null}
   */
  _buildImage(dom, active) {
    if (!dom || !isDomNode(dom)) return null;

    const imgEl = dom.querySelector("img");
    const datafilename = imgEl?.getAttribute("data-filename");
    const filename = datafilename
      ? basename(datafilename)
      : imgEl
        ? basename(imgEl.src)
        : null;

    const caption =
      dom.querySelector(".Image__caption span")?.innerHTML ?? null;

    return new Image({
      url: imgEl?.src ?? null,
      filename,
      caption,
      dom,
      active,
      editable: !active,
    });
  }

  _buildImageDom(src, filename) {
    if (!src) return null;
    return htmlToElement(`<div class="Image">
      <div class="Image__container">
        <img class="lazy miniarch" src="./assets/css/loading.gif" data-src="${src}" data-filename="${filename}" title="${filename} preview" />
      </div>
      <div class="Image__caption"><span contenteditable="true">${stripExtension(filename)}</span></div>
    </div>`);
  }
}

export default Gallery;
