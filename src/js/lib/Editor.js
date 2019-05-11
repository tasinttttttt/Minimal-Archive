import {
  API_URL,
  API_SAVE,
  API_UPLOAD,
  SELECTOR_TITLE,
  SELECTOR_NOTE
} from './Constants.js'
import ProgressBar from './ProgressBar.js'
import {
  isDomNode,
  htmlToElement,
  Fetch,
  stripHtmlTags
} from './Helpers.js'

const mergeSettings = (options) => {
  const settings = {
    dropAreaSelector: '#drop-area',
    fileInputSelector: '#file-input',
    progressBarSelector: '.progress-bar',
    previewBtnSelector: '.editbutton.preview',
    cancelBtnSelector: '.editbutton.cancel',
    saveBtnSelector: '.editbutton.save',
    gallery: null,
    fullscreenDropZone: true
  }

  for (const attrName in options) {
    settings[attrName] = options[attrName]
  }

  return settings
}

class Editor {
  constructor (options) {
    this.config = mergeSettings(options)
    this.uploadFile = this.uploadFile.bind(this)
    this.previewFile = this.previewFile.bind(this)
    this.files = []
    this.init()
  }

  init () {
    const {
      gallery,
      dropAreaSelector,
      fullscreenDropZone,
      fileInputSelector,
      progressBarSelector,
      previewBtnSelector,
      cancelBtnSelector,
      saveBtnSelector
    } = this.config

    this.gallery = gallery
    this.dropArea = document.querySelector(dropAreaSelector)
    this.fileInput = document.querySelector(fileInputSelector)
    this.fullscreenDropZone = Boolean(fullscreenDropZone)
    this.cancelBtn = document.querySelector(cancelBtnSelector)
    this.previewBtn = document.querySelector(previewBtnSelector)
    this.saveBtn = document.querySelector(saveBtnSelector)

    if (!this.gallery) {
      console.warn(`\nModule: Editor.js\nError: Can't create editor.\nCause: No Gallery provided.\nResult: Editor can't initialize.`)
      return
    }
    if (!this.dropArea) {
      console.warn(`\nModule: Editor.js\nError: Can't create editor.\nCause: No drop area with selector [${dropAreaSelector}] found in document.\nResult: Editor can't initialize.`)
      return
    }
    if (!this.fileInput) {
      console.warn(`\nModule: Editor.js\nWarning: Can't create file input listener.\nCause: No file input with selector [${fileInputSelector}] found in document.\nResult: Upload by file input button is disabled.`)
    }
    if (!this.saveBtn) {
      console.warn(`Module: Editor.js\nWarning: Can't add preview functionality.\nCause: No preview button with selector [${previewBtnSelector}] found in document.\nResult: Previewing is disabled.`)
    }
    if (!this.saveBtn) {
      console.warn(`Module: Editor.js\nWarning: Can't add save functionality.\nCause: No save button with selector [${saveBtnSelector}] found in document.\nResult: Saving is disabled.`)
    }
    if (!this.cancelBtn) {
      console.warn(`Module: Editor.js\nWarning: Can't add cancel functionality.\nCause: No cancel button with selector [${cancelBtnSelector}] found in document.\nResult: Undoing changes is disabled.`)
    }
    this.progressbar = new ProgressBar(progressBarSelector)
    this.initListeners()
  }

  initListeners () {
    // Prevent default drag behaviors
    ;['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      this.dropArea.addEventListener(eventName, this.preventDefaults, false)
      document.body.addEventListener(eventName, this.preventDefaults, false)
    })

    if (this.fullscreenDropZone) {
      ;['dragenter'].forEach(eventName => {
        document.addEventListener(eventName, (e) => {
          this.dropArea.classList.add('active')
        }, true)
      })
      ;['dragleave', 'drop'].forEach(eventName => {
        this.dropArea.addEventListener(eventName, (e) => {
          this.dropArea.classList.remove('active')
        }, true)
      })
    }
    // Highlight drop area when item is dragged over it
    ;['dragenter', 'dragover'].forEach(eventName => {
      this.dropArea.addEventListener(eventName, () => {
        this.highlight()
      }, false)
    })

    ;['dragleave', 'drop'].forEach(eventName => {
      this.dropArea.addEventListener(eventName, () => {
        this.unhighlight()
      }, false)
    })

    // Handle dropped files
    this.dropArea.addEventListener('drop', (e) => {
      this.handleDrop(e)
    }, false)

    if (this.fileInput) {
      this.fileInput.addEventListener('change', (e) => {
        if (e.target && e.target.files) {
          this.handleFiles(e.target.files)
        }
      })
    }

    if (this.cancelBtn) {
      this.cancelBtn.addEventListener('click', (e) => {
        this.cancelChanges()
      })
    }

    if (this.saveBtn) {
      this.saveBtn.addEventListener('click', (e) => {
        this.saveChanges()
      })
    }

    if (this.previewBtn) {
      this.previewBtn.addEventListener('click', (e) => {
        this.previewChanges()
      })
    }
  }

  cancelChanges () {
    if (this.files.length) {
      this.files.forEach(file => {
        console.log(file)
      })
    }
  }

  saveChanges () {
    const data = {
      title: '',
      note: ''
    }
    const title = document.querySelector(SELECTOR_TITLE)
    const note = document.querySelector(SELECTOR_NOTE)

    if (title) {
      data.title = stripHtmlTags(title.innerHTML)
    }
    if (note) {
      data.note = stripHtmlTags(note.innerHTML)
    }

    this.saveMeta(data, this.getCsrfToken(this.saveBtn))
      .then(res => console.log(res))
      .catch(err => console.log(err))
  }

  previewChanges () {
    window.location = '/'
  }

  saveMeta (data, csrfToken) {
    return new Promise((resolve, reject) => {
      const api = new Fetch()
      const url = API_URL
      const formData = new FormData()

      formData.append('data', JSON.stringify(data))
      formData.append('action', API_SAVE)
      formData.append('csrf_token', csrfToken)
      api.newRequest(url, formData)
        .then(data => resolve(data))
        .catch(err => reject(err))
    })
  }
  uploadFile (file, csrfToken, i) {
    return new Promise((resolve, reject) => {
      const api = new Fetch()
      const url = API_URL
      const formData = new FormData()

      formData.append('file', file)
      formData.append('action', API_UPLOAD)
      formData.append('csrf_token', csrfToken)
      api.newRequest(url, formData)
        .then(data => resolve(data))
        .catch(err => reject(err))
    })
  }

  previewFile (file, filename) {
    const reader = new FileReader()
    reader.readAsDataURL(file)

    reader.onloadend = () => {
      this.gallery.addImage(this.getPreviewDom(reader.result, filename))
    }
  }

  getPreviewDom (src, filename) {
    if (src) {
      return htmlToElement(`<div class="Image">
        <div class="Image__container">
          <img class="lazy miniarch" src="/assets/css/loading.gif" data-src="${src}" title="${filename} preview" />
        </div>
        <div class="Image__caption"><span contenteditable="true">${filename}</span></div>
        </div>`)
    }
  }

  handleFiles (files) {
    files = [...files]
    this.progressbar.initializeProgress(files.length)
    files.forEach(file => {
      this.uploadFile(file, this.getCsrfToken(this.dropArea)).then((result) => {
        if (result && result.data && result.data.length && result.data[0]) {
          this.previewFile(file, result.data[0].name)
          this.files.push(result.data[0])
        }
      })
    })
  }

  handleDrop (e) {
    const files = e.dataTransfer.files
    const imageFiles = []

    let i = -1
    while (++i < files.length) {
      if (files[i].type.match(/image.*/)) {
        imageFiles.push(files[i])
      }
    }
    if (imageFiles.length > 0) {
      this.handleFiles(imageFiles)
    }
  }

  getCsrfToken (domNode) {
    if (domNode && isDomNode(domNode)) {
      const inputElement = domNode.querySelector('[name=csrf_token]')
      return inputElement && inputElement.value
    }
    return undefined
  }

  preventDefaults (e) {
    e.preventDefault()
    e.stopPropagation()
  }

  highlight (e) {
    this.dropArea.classList.add('highlight')
  }

  unhighlight (e) {
    this.dropArea.classList.remove('highlight')
  }
}

export default Editor
