if (!globalThis.__cipheraFillListenerInstalled) {
  globalThis.__cipheraFillListenerInstalled = true
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.action !== 'ciphera_fill' || !message.login) return false
    const visible = (element) => Boolean(element.offsetWidth || element.offsetHeight || element.getClientRects().length)
    const password = [...document.querySelectorAll('input[type="password"]')].find(visible)
    if (!password) {
      sendResponse({ ok: false, error: 'No visible password field found' })
      return false
    }
    const form = password.closest('form') || document
    const usernameSelectors = [
      'input[autocomplete="username"]',
      'input[type="email"]',
      'input[name*="user" i]',
      'input[name*="email" i]',
      'input[type="text"]',
    ]
    const username = usernameSelectors
      .flatMap((selector) => [...form.querySelectorAll(selector)])
      .find((element) => visible(element) && element !== password)
    const setValue = (element, value) => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
      setter?.call(element, value)
      element.dispatchEvent(new Event('input', { bubbles: true }))
      element.dispatchEvent(new Event('change', { bubbles: true }))
    }
    if (username) setValue(username, message.login.username)
    setValue(password, message.login.password)
    password.focus()
    sendResponse({ ok: true })
    return false
  })
}
