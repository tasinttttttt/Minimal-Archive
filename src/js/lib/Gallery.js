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

    this._active = false;
    this._current = null;
    this._imageSelector = imageSelector;
    this._gallery = document.querySelector(gallerySelector);
    if (!this._gallery) {
      console.warn(
        `[Gallery] No DOM node found for selector "${gallerySelector}". Adding images may fail.`,
      );
    }

    this._images = this._initializeImages(imageSelector, active);
    this._imagesBackup = [...this._images];
    this._lazyload = new LazyLoad({ elements_selector: lazyloadSelector });

    this[active ? "activate" : "deactivate"](true);
  }

  // ---------------------------------------------------------------------------
  // Activation lifecycle
  // ---------------------------------------------------------------------------

  activate(force = false) {
    if (!force && this._active) return;
    this._active = true;
    this._updateGalleryClasses();
    this._initActiveListeners();
  }

  deactivate(force = false) {
    if (!force && !this._active) return;
    this._active = false;
    this._updateGalleryClasses();
    this._removeActiveListeners();
    this._deactivateImages();
  }

  toggleActive() {
    this[!this._active ? "activate" : "deactivate"](true);
  }

  _updateGalleryClasses() {
    this._gallery?.classList.toggle("Gallery--active", this._active);
    this._gallery?.classList.toggle("Gallery--inactive", !this._active);
  }

  // ---------------------------------------------------------------------------
  // Listener setup / teardown
  // ---------------------------------------------------------------------------

  _initActiveListeners() {
    document.addEventListener(EVENT_IMAGE_UPDATE, this.updateImage);
    document.addEventListener(EVENT_NEXT_IMAGE, this.next);
    document.addEventListener("keyup", this.keyHandler);
    this._activateImages();
  }

  _removeActiveListeners() {
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
   * @param {Array<{filename: string, src?: string, _dom?: Element}>} images
   * @param {string} sortOrder "asc" | "desc"
   */
  setImages(images, sortOrder = "asc") {
    if (!images?.length) {
      this._removeActiveListeners();
      this._images = [];
      this._current = null;
      this._gallery?.replaceChildren();
      return;
    }

    const snapshots = images.map((image) => ({
      filename: image.filename,
      src:
        image.dom?.querySelector("img")?.getAttribute("data-src") ??
        image.src ??
        image.url ??
        null,
    }));

    this._removeActiveListeners();
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

    if (this._active) this._initActiveListeners();
  }

  addImage(dom) {
    const image = this._buildImage(dom, this._active);
    if (!image) return null;

    if (!document.body.contains(dom) && this._gallery) {
      const existing = this._gallery.querySelectorAll(this._imageSelector);
      existing.length
        ? existing[existing.length - 1].after(dom)
        : this._gallery.appendChild(dom);
    }

    this._images.push(image);
    this._imagesBackup = [...this._images];
    this._lazyload.update();
    return image;
  }

  removeImageById(id) {
    const target = this._images.find((img) => img.id === id);
    if (target) {
      target.dom.classList.add("Image--markedfordeletion");
      this._images = this._images.filter((img) => img.id !== id);
    }
    return this._images;
  }

  revertRemoveImageById(id) {
    if (this._images.some((img) => img.id === id)) return this._images;

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
    const newImage = e?.detail?.image instanceof Image ? e.detail.image : null;
    if (newImage && newImage !== this._current) {
      this._setCurrentImage(newImage);
    }
  }

  _setCurrentImage(image) {
    if (this._current instanceof Image && this._current !== image) {
      this._current.status = false;
    }
    this._current = image;
    if (this._current instanceof Image) {
      if (this._current.status !== true) {
        this._current.status = true;
      }
      this._current.dom.scrollIntoView({
        block: "center",
        inline: "center",
      });
    } else {
      window.scrollTo({ top: 0 });
    }
  }

  next() {
    if (!this._images.length) return;
    const index = this._images.indexOf(this._current);
    const nextIndex = index === -1 ? 0 : (index + 1) % this._images.length;
    this._setCurrentImage(this._images[nextIndex]);
  }

  prev() {
    if (!this._images.length) return;
    const index = this._images.indexOf(this._current);
    const prevIndex =
      index === -1
        ? this._images.length - 1
        : (index - 1 + this._images.length) % this._images.length;
    this._setCurrentImage(this._images[prevIndex]);
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
    return [...document.querySelectorAll(selector)]
      .map((node) => this._buildImage(node, active))
      .filter(Boolean);
  }

  _buildImage(dom, active) {
    if (!dom || !isDomNode(dom)) return null;

    const imgEl = dom.querySelector("img");
    const filename = imgEl?.getAttribute("data-filename")
      ? basename(imgEl.getAttribute("data-filename"))
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
    return htmlToElement(`
      <div class="Image">
        <div class="Image__container">
          <img class="lazy miniarch" src="./assets/css/loading.gif" data-src="${src}" data-filename="${filename}" title="${filename} preview" />
        </div>
        <div class="Image__caption"><span contenteditable="true">${stripExtension(filename)}</span></div>
      </div>
    `);
  }
}

export default Gallery;
