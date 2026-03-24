(function () {
  'use strict';

  /* global crypto, fetch, performance, requestAnimationFrame, window, Element, HTMLDocument */

  /**
   * Tests two Objects / arrays equality
   * @param  {Object | Array} a [description]
   * @param  {Object | Array} other [description]
   * @return {Boolean}
   */
  const areObjectsEqual = (a, b) => {
    const type = Object.prototype.toString.call(a);

    if (type !== Object.prototype.toString.call(b)) {
      return false;
    }

    if (["[object Array]", "[object Object]"].indexOf(type) < 0) {
      return false;
    }

    const aLen = type === "[object Array]" ? a.length : Object.keys(a).length;
    const bLen = type === "[object Array]" ? b.length : Object.keys(b).length;
    if (aLen !== bLen) {
      return false;
    }

    const compare = function (item1, item2) {
      const itemType = Object.prototype.toString.call(item1);

      // If an object or array, compare recursively
      if (["[object Array]", "[object Object]"].indexOf(itemType) >= 0) {
        if (!areObjectsEqual(item1, item2)) {
          return false;
        }
      } else {
        if (itemType !== Object.prototype.toString.call(item2)) {
          return false;
        }
        if (itemType === "[object Function]") {
          if (item1.toString() !== item2.toString()) {
            return false;
          }
        } else {
          if (item1 !== item2) {
            return false;
          }
        }
      }
    };

    // Compare properties
    if (type === "[object Array]") {
      for (var i = 0; i < aLen; i++) {
        if (compare(a[i], b[i]) === false) {
          return false;
        }
      }
    } else {
      for (var key in a) {
        if (a.hasOwnProperty(key)) {
          if (compare(a[key], b[key]) === false) {
            return false;
          }
        }
      }
    }

    return true;
  };

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
   * Interface to fetch api
   * methods:
   *   newRequest -> takes a url with data, credentials and headers and executes request
   */
  class Fetch {
    newRequest(
      url,
      request,
      credentials = "same-origin",
      headers = { Accept: "application/json", "Content-Type": "application/json" }
    ) {
      function processResponse(response) {
        return new Promise((resolve, reject) => {
          // will resolve or reject depending on status, will pass both "status" and "data" in either case
          let func;
          response.status < 400 ? (func = resolve) : (func = reject);
          response.json().then((data) =>
            func({
              status: response.status,
              code: data.code,
              data: data.data,
              message: data.message,
            })
          );
        });
      }

      return new Promise((resolve, reject) => {
        fetch(url, {
          method: "POST",
          body: request,
          credentials: credentials,
          headers: {
            headers,
          },
        })
          .then(processResponse)
          .then((response) => {
            resolve(response);
          })
          .catch((response) => {
            console.log(response);
            reject(response.message);
          });
      });
    }
  }

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
   * Tests if input is function
   * @param  {any} input
   * @return {Boolean}
   */
  const isFunction = (input) => {
    return input instanceof Function;
  };

  const isHexColor = (input) => {
    const regex = new RegExp(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/);
    return regex.test(input);
  };

  /**
   * Provides preventDefault shorthand
   * @param  {event} event
   * @return {[type]}       [description]
   */
  const preventDefaults = (event) => {
    if (event && event.target) {
      event.preventDefault();
      event.stopPropagation();
    }
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
   * Replace content editable entities by better ones
   * @param  {string} str [description]
   * @return {string}     [description]
   */
  const processContentEditable = (str) => {
    let processed = str.trim();
    processed = processed.replace(/(<div><br>)*<\/div>/g, "<br/>");
    processed = processed.replace(/<div>/g, "");

    return processed;
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

  class Menu {
    constructor (options) {
      this.config = mergeSettings(options, {});
      this.init();
    }

    init () {
      this._buttons = [];
      this._callback = null;
    }

    getButtonOptions (options) {
      const result = {
        domNode: undefined,
        callback: undefined,
        type: 'simple',
        domNode2: undefined,
        callback2: undefined
      };

      for (const attrName in options) {
        result[attrName] = options[attrName];
      }
      return result
    }

    addButton (options) {
      const id = uuidv4();
      const {
        domNode,
        callback,
        type,
        domNode2,
        callback2
      } = this.getButtonOptions(options);

      if (isDomNode(domNode)) {
        this._buttons[id] = {};
        this._buttons[id].dom = domNode;

        if (type === 'simple') {
          if (isFunction(callback)) {
            this._buttons[id].callback = callback;
            this._buttons[id].dom.classList.add('clickable');
            domNode.addEventListener('click', this._buttons[id].callback);
          }
        }

        if (type === 'toggle') {
          this._buttons[id].state = false;
          this._buttons[id].dom.classList.add('clickable');
          domNode.addEventListener('click', () => this.toggleButtonById(id));
          if (isFunction(callback)) {
            this._buttons[id].callback = callback;
            domNode.addEventListener('click', this._buttons[id].callback);
          }
          if (isDomNode(domNode2)) {
            this._buttons[id].dom2 = domNode2;
            this._buttons[id].dom2.classList.add('clickable');
            domNode2.addEventListener('click', () => this.toggleButtonById(id));
            if (isFunction(callback2)) {
              this._buttons[id].callback2 = callback2;
              domNode2.addEventListener('click', this._buttons[id].callback2);
            }
          }
        }

        if (type === 'input') {
          if (isFunction(callback)) {
            this._buttons[id].callback = callback;
            domNode.addEventListener('change', this._buttons[id].callback);
          }
        }
        return id
      }
    }

    toggleButtonById (id) {
      if (this._buttons[id]) {
        this._buttons[id].state = !this._buttons[id].state;

        const on = this._buttons[id].state ? 'button--off' : 'button--on';
        const off = this._buttons[id].state ? 'button--on' : 'button--off';
        this._buttons[id].dom.classList.add(on);
        this._buttons[id].dom.classList.remove(off);
        this._buttons[id].dom2.classList.add(off);
        this._buttons[id].dom2.classList.remove(on);
      }
    }

    removeButton (id) {
      if (this._buttons[id]) {
        if (this._buttons[id].dom) {
          this._buttons[id].dom.removeEventListener('click', this._buttons[id].callback);
        }
        if (this._buttons[id].dom2) {
          this._buttons[id].dom2.removeEventListener('click', this._buttons[id].callback2);
        }
        this._buttons.remove(id);
        return true
      }
      return false
    }
  }

  const API_URL = baseUrl() + "/api";
  const API_UPLOAD = "upload";
  const API_SAVE = "save";

  const SELECTOR_TITLE = "main header .title";
  const SELECTOR_NOTE = ".note";

  const EVENT_IMAGE_UPDATE = "image-update";
  const EVENT_LOADED = "loaded";
  const EVENT_LOADING = "loading";
  const EVENT_MODAL_UPDATE = "modal-update";
  const EVENT_STATUS_CHANGE = "status-change";
  const EVENT_RESET = "reset";
  const EVENT_NEXT_IMAGE = "next-image";

  /* global CustomEvent */


  class Modal {
    constructor (options) {
      const defaults = {
        target: false,
        content: null,
        customClass: null,
        active: false,
        triggers: null
      };
      this.config = mergeSettings(options, defaults);
      this.keyHandler = this.keyHandler.bind(this);
      this.init();
    }

    init () {
      const {
        target,
        content,
        active,
        triggers
      } = this.config;

      this._active = false;
      this._id = uuidv4();
      this._triggers = triggers && isDomNode(triggers) ? [triggers] : triggers && typeof triggers === 'string' ? document.querySelectorAll(triggers) : false;
      this._content = content && isDomNode(content) ? content : content && content !== false ? htmlToElement(content) : null;
      this._target = target && isDomNode(target) ? target : target && typeof target === 'string' ? document.querySelector(target) : false;

      this._dom = this.setupDom(this._target, this._content, this._id);
      this._bodyoverflow = document.body.style.overflow;
      this.setupListeners();

      if (active) {
        this.activate();
      } else {
        this.deactivate();
      }
    }

    activate () {
      this.dispatchStatusUpdate(true);
    }

    deactivate () {
      this.dispatchStatusUpdate(false);
    }

    toggle () {
      this.dispatchStatusUpdate(!this._active);
    }

    setupListeners () {
      if (this._triggers) {
        let i = -1;
        while (++i < this._triggers.length) {
          this._triggers[i].addEventListener('click', this.toggle.bind(this));
        }
      }

      document.addEventListener('keyup', this.keyHandler);
      document.addEventListener(EVENT_MODAL_UPDATE, (e) => {
        if (e && e.detail && e.detail.id === this._id) {
          this._active = e.detail.status;
          this.updateView();
        }
      });
    }

    updateView () {
      if (this._active) {
        this._bodyoverflow = document.body.style.overflow;
        this._dom.style.opacity = 1;
        this._dom.style.visibility = 'visible';
        document.body.style.position = 'fixed';
        document.body.style.overflow = 'hidden';
      } else {
        this._dom.style.opacity = 0;
        this._dom.style.visibility = 'hidden';
        document.body.style.position = 'relative';
        document.body.style.overflow = this._bodyoverflow;
      }
    }

    dispatchStatusUpdate (status) {
      document.dispatchEvent(new CustomEvent(EVENT_MODAL_UPDATE, {
        detail: {
          id: this._id,
          status: status
        }
      }));
    }

    keyHandler (e) {
      switch (e.key) {
        case 'Escape':
          if (this._active) {
            this.deactivate();
          }
          break
      }
    }

    setupDom (target, content, id) {
      if (target) {
        if (content) {
          target.innerHTML = content;
        }
        return target
      } else {
        const okContent = content || '';
        const container = htmlToElement(`
        <aside>
          <div class="modal">
            <label class="modal__bg" for="${id}"></label>
            <div class="modal__inner">
                <label class="modal__close" for="${id}"></label>
                ${okContent}
            </div>
          </div>
        </aside>
      `);
        document.body.appendChild(container);
        return container
      }
    }

    get active () {
      return this._active
    }
  }

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

  /* global Event, FormData, FileReader */


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
      (() =>
        new Modal({
          target: ".modal",
          active: true,
          triggers: ".modal__bg, .modal__close",
        }))();

      // Apply initial display properties
      this._applyBgColor(bgColor);
      this._applyTextColor(textColor);
      this._applyFontFamily(fontFamily);

      // Snapshot state after DOM is ready — this is the restore point for Cancel
      this._state = this._readStateFromDom();
      this._backup = this._cloneState(this._state);

      this.initListeners();

      const sortOrderSelect = document.querySelector("#sort_order");
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
        document.body.addEventListener(eventName, preventDefaults, false);
      });

      if (this._fullscreenDropZone) {
        document.addEventListener(
          "dragenter",
          () => this._dropArea.classList.add("active"),
          true,
        );
        this._dropArea.addEventListener("dragleave", () =>
          this._dropArea.classList.remove("active"),
        );
        this._dropArea.addEventListener("drop", () =>
          this._dropArea.classList.remove("active"),
        );
      }

      ["dragenter", "dragover"].forEach((eventName) => {
        this._dropArea.addEventListener(eventName, () => this.highlight(), false);
      });
      ["dragleave", "drop"].forEach((eventName) => {
        this._dropArea.addEventListener(
          eventName,
          () => this.unhighlight(),
          false,
        );
      });

      this._dropArea.addEventListener("drop", (e) => this.handleDrop(e), false);

      if (this._fileInput) {
        this._fileInput.addEventListener("change", (e) => {
          if (e.target?.files) {
            this.handleFiles(e.target.files);
          }
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
      while (
        this._uploadQueue.length > 0 &&
        this._activeUploads < MAX_CONCURRENT_UPLOADS
      ) {
        const file = this._uploadQueue.shift();
        this._activeUploads++;

        this._uploadFile(file)
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

            const isQueueEmpty = this._uploadQueue.length === 0;
            const isProcessingComplete =
              this._activeUploads === 0 && isQueueEmpty;

            this._uploadToast?.update(
              isProcessingComplete
                ? `Uploaded ${this._uploadTotal} ${this._uploadTotal === 1 ? "file" : "files"}`
                : `Uploading… ${this._uploadDone} / ${this._uploadTotal}`,
            );

            if (isProcessingComplete) {
              const toast = this._uploadToast;
              this._uploadToast = null;
              this._uploadTotal = 0;
              this._uploadDone = 0;
              setTimeout(() => toast?.dismiss(), 1200);
            }

            this._processUploadQueue();
          });
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

      const sortOrderEl = document.querySelector("#sort_order");
      if (sortOrderEl) state.sortorder = sortOrderEl.value;

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

      const sortOrderEl = document.querySelector("#sort_order");
      if (sortOrderEl) state.sortorder = sortOrderEl.value;

      return state;
    }

    _cloneState(state) {
      // Deep clone via JSON — state contains only serializable data
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
      this._dropArea.classList.remove("highlight");
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

  class Loader {
    constructor (options) {
      this.config = mergeSettings(options, { loaderClass: 'Loader' });
      this.init();
    }

    init () {
      const {
        loaderClass
      } = this.config;
      const content = document.createElement('div');

      content.classList.add('content');
      content.innerHTML = 'Loading...';

      this.dom = document.createElement('aside');
      this.dom.classList.add(loaderClass);
      this.dom.appendChild(content);

      document.body.appendChild(this.dom);
      this.initListeners();
    }

    initListeners () {
      document.addEventListener(EVENT_LOADING, () => {
        this.start();
      });
      document.addEventListener(EVENT_LOADED, () => {
        setTimeout(() => {
          this.stop();
        }, 1000);
      });
    }

    start () {
      this.dom.classList.remove('transition-end');
      this.dom.classList.remove(EVENT_LOADED);
      this.dom.classList.add('transition-start');
      setTimeout(() => {
        this.dom.classList.add(EVENT_LOADING);
      }, 0.25);
    }

    stop () {
      this.dom.classList.remove('transition-start');
      this.dom.classList.remove(EVENT_LOADING);
      this.dom.classList.add(EVENT_LOADED);
      setTimeout(() => {
        this.dom.classList.add('transition-end');
      }, 0.25);
    }
  }

  const getCsrfToken = (domNode) => {
    if (domNode && isDomNode(domNode)) {
      const inputElement = domNode.querySelector('[name=csrf_token]');
      return inputElement && inputElement.value
    }
  };

  document.addEventListener('DOMContentLoaded', () => {
   (() => new Loader())();
    const editor = new Editor({
      bgColor: bg_color.value,
      textColor: text_color.value,
      onUpdate: (newState, oldState) => {
        bg_color.value = newState.bgcolor;
        bg_color.nextSibling.innerHTML = newState.bgcolor;
        text_color.value = newState.textcolor;
        text_color.nextSibling.innerHTML = newState.textcolor;
      }
    });

    // Save button
    editor.addButton({
      domNode: savebtn,
      callback: () => {
        editor.actionSave(getCsrfToken(savebtn));
      },
      csrf_token: getCsrfToken(savebtn)
    });

    // Cancel button
    editor.addButton({
      domNode: cancelbtn,
      callback: () => {
        window.location.reload();
      },
      csrf_token: getCsrfToken(cancelbtn)
    });

    // Preview button
    editor.addButton({
      domNode: previewbtn,
      callback: () => { window.location = baseUrl(); },
      csrf_token: getCsrfToken(previewbtn)
    });

    // Background color selector
    editor.addButton({
      domNode: bg_color,
      type: 'input',
      callback: (e) => {
        editor.bgColor = e.target.value;
        e.target.nextSibling.innerHTML = editor.bgColor;
      }
    });

    // Text color selector
    editor.addButton({
      domNode: text_color,
      type: 'input',
      callback: (e) => {
        editor.textColor = e.target.value;
        e.target.nextSibling.innerHTML = editor.textColor;
      }
    });

    // Font family selector
    editor.addButton({
      domNode: font_family,
      type: 'input',
      callback: (e) => {
        editor.fontFamily = e.target.value;
      }
    });
  });

})();
