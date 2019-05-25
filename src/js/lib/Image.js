import {
  isDomNode,
  uuidv4
} from './Helpers.js'
import {
  EVENT_RESET,
  EVENT_STATUS_CHANGE,
  EVENT_IMAGE_UPDATE
} from './Constants.js'

const mergeSettings = (options) => {
  const settings = {
    image: null,
    active: true,
    imageSelector: '.Image',
    lazyloadSelector: '.lazy'
  }

  for (const attrName in options) {
    settings[attrName] = options[attrName]
  }

  return settings
}

class Image {
  constructor (options) {
    this.config = mergeSettings(options)

    const {
      image,
      active
    } = this.config

    if (!isDomNode(image)) {
      console.error('%o is not a dom element! aborting image creation', image)
    } else {
      this.id = uuidv4()
      this.dom = image
      this.url = image.querySelector('img').src

      const datafilename = image.querySelector('img').getAttribute('data-filename')
      if (datafilename) {
        this.file = datafilename.substring(datafilename.lastIndexOf('/') + 1)
      } else {
        this.file = image.querySelector('img').src.substring(image.querySelector('img').src.lastIndexOf('/') + 1)
      }

      this.active = active
      this.stat = false
      this.applyStyle()
      this.initListeners()
      this.dispatchStatusUpdate = this.dispatchStatusUpdate.bind(this)
    }
  }

  initListeners () {
    if (this.active) {
      this.dom.addEventListener('click', this.toggleStatus.bind(this))
      this.dom.addEventListener(EVENT_STATUS_CHANGE, this.applyStyle.bind(this))
    }
    document.addEventListener(EVENT_RESET, (e) => {
      this.stat = false
      this.dispatchStatusUpdate()
    })
  }

  toggleStatus (event) {
    this.stat = !this.stat
    this.dispatchStatusUpdate()
  }

  dispatchStatusUpdate (event) {
    this.dom.dispatchEvent(new Event(EVENT_STATUS_CHANGE))
    document.dispatchEvent(new CustomEvent(EVENT_IMAGE_UPDATE, {
      detail: {
        image: this.stat ? this : null
      }
    }))
  }

  applyStyle () {
    if (this.stat) {
      this.dom.classList.add('Image--active')
      this.dom.classList.remove('Image--inactive')
    } else {
      this.dom.classList.remove('Image--active')
      this.dom.classList.add('Image--inactive')
    }
  }

  getId () {
    return this.id
  }

  set image (image) {
    this.dom = image
  }

  get image () {
    return this.dom
  }

  set status (status) {
    this.stat = status
    this.dom.dispatchEvent(new Event(EVENT_STATUS_CHANGE))
  }

  get status () {
    return this.stat
  }

  set filename (filename) {
    this.file = filename
  }

  get filename () {
    return this.file
  }

  set src (src) {
    this.url = src
  }
  get src () {
    return this.url
  }
}

export default Image
