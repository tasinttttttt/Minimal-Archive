(function () {
  'use strict';

  const runningOnBrowser = typeof window !== 'undefined';

  const isBot =
    (runningOnBrowser && !('onscroll' in window)) ||
    (typeof navigator !== 'undefined' &&
      /(gle|ing|ro)bot|crawl|spider/i.test(navigator.userAgent));

  const supportsIntersectionObserver =
    runningOnBrowser && 'IntersectionObserver' in window;

  const supportsClassList =
    runningOnBrowser && 'classList' in document.createElement('p');

  const defaultSettings = {
    elements_selector: 'img',
    container: isBot || runningOnBrowser ? document : null,
    threshold: 300,
    thresholds: null,
    data_src: 'src',
    data_srcset: 'srcset',
    data_sizes: 'sizes',
    data_bg: 'bg',
    class_loading: 'loading',
    class_loaded: 'loaded',
    class_error: 'error',
    load_delay: 0,
    auto_unobserve: true,
    callback_enter: null,
    callback_exit: null,
    callback_reveal: null,
    callback_loaded: null,
    callback_error: null,
    callback_finish: null
  };

  var getInstanceSettings = customSettings => {
    return Object.assign({}, defaultSettings, customSettings)
  };

  const dataPrefix = 'data-';
  const processedDataName = 'was-processed';
  const timeoutDataName = 'll-timeout';
  const trueString = 'true';

  const getData = (element, attribute) => {
    return element.getAttribute(dataPrefix + attribute)
  };

  const setData = (element, attribute, value) => {
    var attrName = dataPrefix + attribute;
    if (value === null) {
      element.removeAttribute(attrName);
      return
    }
    element.setAttribute(attrName, value);
  };

  const setWasProcessedData = element =>
    setData(element, processedDataName, trueString);

  const getWasProcessedData = element =>
    getData(element, processedDataName) === trueString;

  const setTimeoutData = (element, value) =>
    setData(element, timeoutDataName, value);

  const getTimeoutData = element => getData(element, timeoutDataName);

  const purgeProcessedElements = elements => {
    return elements.filter(element => !getWasProcessedData(element))
  };

  const purgeOneElement = (elements, elementToPurge) => {
    return elements.filter(element => element !== elementToPurge)
  };

  /* Creates instance and notifies it through the window element */
  const createInstance = function (classObj, options) {
    var event;
    let eventString = 'LazyLoad::Initialized';
    let instance = new classObj(options);
    try {
      // Works in modern browsers
      event = new CustomEvent(eventString, { detail: { instance } });
    } catch (err) {
      // Works in Internet Explorer (all versions)
      event = document.createEvent('CustomEvent');
      event.initCustomEvent(eventString, false, false, { instance });
    }
    window.dispatchEvent(event);
  };

  /* Auto initialization of one or more instances of lazyload, depending on the
      options passed in (plain object or an array) */
  function autoInitialize (classObj, options) {
    if (!options) {
      return
    }
    if (!options.length) {
      // Plain object
      createInstance(classObj, options);
    } else {
      // Array of objects
      for (let i = 0, optionsItem; (optionsItem = options[i]); i += 1) {
        createInstance(classObj, optionsItem);
      }
    }
  }

  const callbackIfSet = (callback, argument) => {
    if (callback) {
      callback(argument);
    }
  };

  const updateLoadingCount = (instance, plusMinus) => {
    instance._loadingCount += plusMinus;
    if (instance._elements.length === 0 && instance._loadingCount === 0) {
      callbackIfSet(instance._settings.callback_finish);
    }
  };

  const getSourceTags = parentTag => {
    let sourceTags = [];
    for (let i = 0, childTag; (childTag = parentTag.children[i]); i += 1) {
      if (childTag.tagName === 'SOURCE') {
        sourceTags.push(childTag);
      }
    }
    return sourceTags
  };

  const setAttributeIfValue = (element, attrName, value) => {
    if (!value) {
      return
    }
    element.setAttribute(attrName, value);
  };

  const setImageAttributes = (element, settings) => {
    setAttributeIfValue(
      element,
      'sizes',
      getData(element, settings.data_sizes)
    );
    setAttributeIfValue(
      element,
      'srcset',
      getData(element, settings.data_srcset)
    );
    setAttributeIfValue(element, 'src', getData(element, settings.data_src));
  };

  const setSourcesImg = (element, settings) => {
    const parent = element.parentNode;

    if (parent && parent.tagName === 'PICTURE') {
      let sourceTags = getSourceTags(parent);
      sourceTags.forEach(sourceTag => {
        setImageAttributes(sourceTag, settings);
      });
    }

    setImageAttributes(element, settings);
  };

  const setSourcesIframe = (element, settings) => {
    setAttributeIfValue(element, 'src', getData(element, settings.data_src));
  };

  const setSourcesVideo = (element, settings) => {
    let sourceTags = getSourceTags(element);
    sourceTags.forEach(sourceTag => {
      setAttributeIfValue(
        sourceTag,
        'src',
        getData(sourceTag, settings.data_src)
      );
    });
    setAttributeIfValue(element, 'src', getData(element, settings.data_src));
    element.load();
  };

  const setSourcesBgImage = (element, settings) => {
    const srcDataValue = getData(element, settings.data_src);
    const bgDataValue = getData(element, settings.data_bg);

    if (srcDataValue) {
      element.style.backgroundImage = `url("${srcDataValue}")`;
    }

    if (bgDataValue) {
      element.style.backgroundImage = bgDataValue;
    }
  };

  const setSourcesFunctions = {
    IMG: setSourcesImg,
    IFRAME: setSourcesIframe,
    VIDEO: setSourcesVideo
  };

  const setSources = (element, instance) => {
    const settings = instance._settings;
    const tagName = element.tagName;
    const setSourcesFunction = setSourcesFunctions[tagName];
    if (setSourcesFunction) {
      setSourcesFunction(element, settings);
      updateLoadingCount(instance, 1);
      instance._elements = purgeOneElement(instance._elements, element);
      return
    }
    setSourcesBgImage(element, settings);
  };

  const addClass = (element, className) => {
    if (supportsClassList) {
      element.classList.add(className);
      return
    }
    element.className += (element.className ? ' ' : '') + className;
  };

  const removeClass = (element, className) => {
    if (supportsClassList) {
      element.classList.remove(className);
      return
    }
    element.className = element.className
      .replace(new RegExp('(^|\\s+)' + className + '(\\s+|$)'), ' ')
      .replace(/^\s+/, '')
      .replace(/\s+$/, '');
  };

  const genericLoadEventName = 'load';
  const mediaLoadEventName = 'loadeddata';
  const errorEventName = 'error';

  const addEventListener = (element, eventName, handler) => {
    element.addEventListener(eventName, handler);
  };

  const removeEventListener = (element, eventName, handler) => {
    element.removeEventListener(eventName, handler);
  };

  const addEventListeners = (element, loadHandler, errorHandler) => {
    addEventListener(element, genericLoadEventName, loadHandler);
    addEventListener(element, mediaLoadEventName, loadHandler);
    addEventListener(element, errorEventName, errorHandler);
  };

  const removeEventListeners = (element, loadHandler, errorHandler) => {
    removeEventListener(element, genericLoadEventName, loadHandler);
    removeEventListener(element, mediaLoadEventName, loadHandler);
    removeEventListener(element, errorEventName, errorHandler);
  };

  const eventHandler = function (event, success, instance) {
    var settings = instance._settings;
    const className = success ? settings.class_loaded : settings.class_error;
    const callback = success
      ? settings.callback_loaded
      : settings.callback_error;
    const element = event.target;

    removeClass(element, settings.class_loading);
    addClass(element, className);
    callbackIfSet(callback, element);

    updateLoadingCount(instance, -1);
  };

  const addOneShotEventListeners = (element, instance) => {
    const loadHandler = event => {
      eventHandler(event, true, instance);
      removeEventListeners(element, loadHandler, errorHandler);
    };
    const errorHandler = event => {
      eventHandler(event, false, instance);
      removeEventListeners(element, loadHandler, errorHandler);
    };
    addEventListeners(element, loadHandler, errorHandler);
  };

  const managedTags = ['IMG', 'IFRAME', 'VIDEO'];

  const onEnter = (element, instance) => {
    const settings = instance._settings;
    callbackIfSet(settings.callback_enter, element);
    if (!settings.load_delay) {
      revealAndUnobserve(element, instance);
      return
    }
    delayLoad(element, instance);
  };

  const revealAndUnobserve = (element, instance) => {
    var observer = instance._observer;
    revealElement(element, instance);
    if (observer && instance._settings.auto_unobserve) {
      observer.unobserve(element);
    }
  };

  const onExit = (element, instance) => {
    const settings = instance._settings;
    callbackIfSet(settings.callback_exit, element);
    if (!settings.load_delay) {
      return
    }
    cancelDelayLoad(element);
  };

  const cancelDelayLoad = element => {
    var timeoutId = getTimeoutData(element);
    if (!timeoutId) {
      return // do nothing if timeout doesn't exist
    }
    clearTimeout(timeoutId);
    setTimeoutData(element, null);
  };

  const delayLoad = (element, instance) => {
    var loadDelay = instance._settings.load_delay;
    var timeoutId = getTimeoutData(element);
    if (timeoutId) {
      return // do nothing if timeout already set
    }
    timeoutId = setTimeout(function () {
      revealAndUnobserve(element, instance);
      cancelDelayLoad(element);
    }, loadDelay);
    setTimeoutData(element, timeoutId);
  };

  const revealElement = (element, instance, force) => {
    var settings = instance._settings;
    if (!force && getWasProcessedData(element)) {
      return // element has already been processed and force wasn't true
    }
    if (managedTags.indexOf(element.tagName) > -1) {
      addOneShotEventListeners(element, instance);
      addClass(element, settings.class_loading);
    }
    setSources(element, instance);
    setWasProcessedData(element);
    callbackIfSet(settings.callback_reveal, element);
    callbackIfSet(settings.callback_set, element);
  };

  const isIntersecting = entry =>
    entry.isIntersecting || entry.intersectionRatio > 0;

  const getObserverSettings = settings => ({
    root: settings.container === document ? null : settings.container,
    rootMargin: settings.thresholds || settings.threshold + 'px'
  });

  const setObserver = instance => {
    if (!supportsIntersectionObserver) {
      return false
    }
    instance._observer = new IntersectionObserver(entries => {
      entries.forEach(entry =>
        isIntersecting(entry)
          ? onEnter(entry.target, instance)
          : onExit(entry.target, instance)
      );
    }, getObserverSettings(instance._settings));
    return true
  };

  const LazyLoad = function (customSettings, elements) {
    this._settings = getInstanceSettings(customSettings);
    this._loadingCount = 0;
    setObserver(this);
    this.update(elements);
  };

  LazyLoad.prototype = {
    update: function (elements) {
      const settings = this._settings;
      const _elements =
        elements ||
        settings.container.querySelectorAll(settings.elements_selector);

      this._elements = purgeProcessedElements(
        Array.prototype.slice.call(_elements) // NOTE: nodeset to array for IE compatibility
      );

      if (isBot || !this._observer) {
        this.loadAll();
        return
      }

      this._elements.forEach(element => {
        this._observer.observe(element);
      });
    },

    destroy: function () {
      if (this._observer) {
        this._elements.forEach(element => {
          this._observer.unobserve(element);
        });
        this._observer = null;
      }
      this._elements = null;
      this._settings = null;
    },

    load: function (element, force) {
      revealElement(element, this, force);
    },

    loadAll: function () {
      var elements = this._elements;
      elements.forEach(element => {
        revealAndUnobserve(element, this);
      });
    }
  };

  /* Automatic instances creation if required (useful for async script loading) */
  if (runningOnBrowser) {
    autoInitialize(LazyLoad, window.lazyLoadOptions);
  }

  /* global crypto, fetch, performance, requestAnimationFrame, window, Element, HTMLDocument */


  /**
   * Returns url basename
   * @param  {string} url
   * @return {string}
   */
  const basename = (url) => {
    return url.split(/[\\/]/).pop();
  };

  /**
   * Returns the base url for a specified url part
   * @param  {string} segment
   * @return {string}
   */
  const baseUrl = (segment = "") => {
    const pathArray = window.location.pathname.split("/");
    const indexOfSegment = !segment ? -1 : pathArray.indexOf(segment);
    // make base_url be the origin plus the path to the segment
    return window.location.origin + pathArray.slice(0, indexOfSegment).join("/");
  };

  /**
   * Converts html string to dom node
   * @param  {string} html HTML string to be processed
   * @return {DOMNode}      valid DOMNode
   */
  const htmlToElement = (html) => {
    const template = document.createElement("template");

    // removing extra white spaces
    html = html.trim();
    template.innerHTML = html;
    return template.content.firstChild;
  };

  /**
   * Tests if input is a DOMNode
   * @param  {any} input input
   * @return {Boolean}
   */
  const isDomNode = (input) => {
    return input instanceof Element || input instanceof HTMLDocument;
  };

  /**
   * Removes HTML content from string
   * @param  {String} str input
   * @return {String}     output
   */
  const removeHtml = (str) => {
    const tmp = document.createElement("div");
    tmp.innerHTML = str;
    return tmp.textContent || tmp.innerText;
  };

  /**
   * Removes extension from filename
   * @param  {String} str input
   * @return {String}     output
   */
  const stripExtension = (str) => {
    return str.replace(/\.[^/.]+$/, "");
  };

  /**
   * Merges an option object values with a default one if key exists in default
   * @param  {Object} options
   * @return {Object}
   */
  const mergeSettings = (options, defaults = {}) => {
    if (!options) {
      return defaults;
    }
    for (const attrName in options) {
      defaults[attrName] = options[attrName];
    }

    return defaults;
  };

  /**
   * Returns a UUIDv4 string
   * @return {String}
   */
  const uuidv4 = () => {
    return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, (c) =>
      (
        c ^
        (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))
      ).toString(16)
    );
  };

  baseUrl() + "/api";

  const EVENT_IMAGE_UPDATE = "image-update";
  const EVENT_STATUS_CHANGE = "status-change";
  const EVENT_RESET = "reset";
  const EVENT_NEXT_IMAGE = "next-image";

  /* global CustomEvent, Event */


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

  /* global Event */


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

  document.addEventListener("DOMContentLoaded", () => {
    const gallery = new Gallery({
      image_selector: ".Image",
      lazyload_selector: ".lazy",
    });

    gallery.reset();
  });

})();
