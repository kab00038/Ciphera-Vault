const HOST_NAME = 'com.ciphera.browser'
const GITHUB_PATH = 'M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12'
const status = document.querySelector('#status')
const statusDot = document.querySelector('#status-dot')
const site = document.querySelector('#site')
const results = document.querySelector('#results')
const empty = document.querySelector('#empty')
const error = document.querySelector('#error')
const refresh = document.querySelector('#refresh')

function sendNativeMessage(request) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST_NAME, request, (response) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message))
      else resolve(response)
    })
  })
}

function getActiveTab() {
  return new Promise((resolve) => chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => resolve(tab)))
}

function renderLogin(login, tabId) {
  const button = document.createElement('button')
  button.className = 'login'
  button.type = 'button'
  const icon = document.createElement('span')
  icon.className = 'login-icon'
  if (login.url === 'github.com') {
    const logo = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    logo.setAttribute('viewBox', '0 0 24 24')
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('d', GITHUB_PATH)
    logo.append(path)
    icon.append(logo)
  } else {
    icon.textContent = login.title.slice(0, 2).toUpperCase()
  }
  const identity = document.createElement('span')
  const title = document.createElement('strong')
  const username = document.createElement('span')
  title.textContent = login.title
  username.textContent = login.username
  identity.append(title, username)
  const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  arrow.setAttribute('viewBox', '0 0 24 24')
  const arrowPath = document.createElementNS('http://www.w3.org/2000/svg', 'path')
  arrowPath.setAttribute('d', 'm9 18 6-6-6-6')
  arrow.append(arrowPath)
  button.append(icon, identity, arrow)
  button.addEventListener('click', async () => {
    button.disabled = true
    try {
      const response = await sendNativeMessage({ action: 'get_login', id: login.id })
      if (!response?.ok) throw new Error(response?.error || 'Could not retrieve login')
      await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] })
      await chrome.tabs.sendMessage(tabId, { action: 'ciphera_fill', login: response.login })
      window.close()
    } catch (cause) {
      status.textContent = cause instanceof Error ? cause.message : 'Fill failed'
      button.disabled = false
    }
  })
  results.append(button)
}

async function load() {
  results.replaceChildren()
  empty.hidden = true
  error.hidden = true
  status.textContent = 'Connecting…'
  statusDot.classList.remove('connected')
  try {
    const bridge = await sendNativeMessage({ action: 'status' })
    if (!bridge?.ok || !bridge.connected) throw new Error('Desktop app unavailable')
    if (!bridge.unlocked) throw new Error('Vault is locked')
    status.textContent = 'Connected · vault unlocked'
    statusDot.classList.add('connected')
    const tab = await getActiveTab()
    if (!tab?.id || !tab.url) throw new Error('This page cannot be filled')
    const hostname = new URL(tab.url).hostname
    site.textContent = hostname
    const response = await sendNativeMessage({ action: 'find_logins', url: tab.url })
    if (!response?.ok) throw new Error(response?.error || 'Lookup failed')
    if (!response.logins?.length) empty.hidden = false
    else response.logins.forEach((login) => renderLogin(login, tab.id))
  } catch (cause) {
    status.textContent = cause instanceof Error ? cause.message : 'Connection failed'
    error.hidden = false
  }
}

refresh.addEventListener('click', load)
load()
