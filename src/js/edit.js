import Editor from './lib/Editor.js'
import Loader from './lib/Loader.js'
import {
  baseUrl,
  isDomNode
} from './lib/Helpers.js'

const getCsrfToken = (domNode) => {
  if (domNode && isDomNode(domNode)) {
    const inputElement = domNode.querySelector('[name=csrf_token]')
    return inputElement && inputElement.value
  }
}

document.addEventListener('DOMContentLoaded', () => {
  ; (() => new Loader())()
  const editor = new Editor({
    bgColor: bg_color.value,
    textColor: text_color.value,
    onUpdate: (newState, oldState) => {
      bg_color.value = newState.bgcolor
      bg_color.nextSibling.innerHTML = newState.bgcolor
      text_color.value = newState.textcolor
      text_color.nextSibling.innerHTML = newState.textcolor
    }
  })

  // Save button
  editor.addButton({
    domNode: savebtn,
    callback: () => {
      editor.actionSave(getCsrfToken(savebtn))
    },
    csrf_token: getCsrfToken(savebtn)
  })

  // Cancel button
  editor.addButton({
    domNode: cancelbtn,
    callback: () => {
      editor.actionCancel(getCsrfToken(cancelbtn))
    },
    csrf_token: getCsrfToken(cancelbtn)
  })

  // Preview button
  editor.addButton({
    domNode: previewbtn,
    callback: () => { window.location = baseUrl() },
    csrf_token: getCsrfToken(previewbtn)
  })

  // Background color selector
  editor.addButton({
    domNode: bg_color,
    type: 'input',
    callback: (e) => {
      editor.bgColor = e.target.value
      e.target.nextSibling.innerHTML = editor.bgColor
    }
  })

  // Text color selector
  editor.addButton({
    domNode: text_color,
    type: 'input',
    callback: (e) => {
      editor.textColor = e.target.value
      e.target.nextSibling.innerHTML = editor.textColor
    }
  })

  // Font family selector
  editor.addButton({
    domNode: font_family,
    type: 'input',
    callback: (e) => {
      editor.fontFamily = e.target.value
    }
  })
})
