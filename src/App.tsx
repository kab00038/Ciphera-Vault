import { useCallback, useEffect, useMemo, useState } from 'react'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import { relaunch } from '@tauri-apps/plugin-process'
import { check, type Update } from '@tauri-apps/plugin-updater'
import {
  Activity, AlertTriangle, ArrowRight, Asterisk, BadgeCheck,
  Check, ChevronDown, ChevronRight, Clipboard, Clock3, Copy, Download,
  Eye, EyeOff, Fingerprint, FolderTree, Grid2X2, HardDrive, History,
  KeyRound, LayoutDashboard, Lock, Menu, MoreHorizontal, Paperclip, Pencil,
  Plus, RefreshCw, RotateCcw, Search, Settings, ShieldCheck, Smartphone,
  Sparkles, Star, Trash2, WandSparkles, WifiOff, X, Puzzle, FolderOpen,
  Sun, Moon, type LucideIcon,
} from 'lucide-react'
import { siFigma, siGithub, siLinear, siNotion, siProtonmail, siVisa, type SimpleIcon } from 'simple-icons'
import './App.css'
import { generatePassphrase, generatePassword, ratePassword, type PasswordOptions } from './security'

type View = 'vault' | 'generator' | 'security' | 'two-factor' | 'settings'
type Theme = 'light' | 'dark'
const BRAND_ICON_BY_TITLE: Record<string, SimpleIcon> = {
  GitHub: siGithub,
  Notion: siNotion,
  Figma: siFigma,
  Linear: siLinear,
  'Personal Visa': siVisa,
  'Proton Mail': siProtonmail,
}

function getInitialTheme(): Theme {
  const saved = localStorage.getItem('ciphera-theme')
  if (saved === 'light' || saved === 'dark') return saved
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}
type EntryCategory = 'Login' | 'Card' | 'Identity' | 'Secure note'
type VaultGroup = { id: string; parentId: string | null; name: string }
type EntryHistory = { index: number; title: string; username: string; url: string; updatedAt: string | null }
type AttachmentSummary = { name: string; size: number }
type BackupInfo = { index: number; path: string; size: number; modifiedAt: string | null }
type VaultRecord = {
  id: string
  groupId: string
  title: string
  username: string
  url: string
  category: EntryCategory
  favorite: boolean
  health: 'safe' | 'weak' | 'reused' | 'old'
  updatedAt: string | null
}
type VaultItem = VaultRecord & { color: string; initials: string; updated: string }
type EntryDetail = VaultRecord & { password: string; notes: string; totp: string | null; attachments: AttachmentSummary[] }
type EntryInput = {
  groupId: string | null
  title: string
  username: string
  password: string
  url: string
  notes: string
  category: EntryCategory
  favorite: boolean
  totp: string | null
}
type TotpCode = { id: string; title: string; username: string; code: string; validFor: number; period: number }
type PinUnlockStatus = { configured: boolean; attemptsRemaining: number; retryAfterSeconds: number; masterPasswordRequired: boolean }
type VaultStatus = { path: string; exists: boolean; unlocked: boolean; pinUnlock: PinUnlockStatus }

function decorateItem(item: VaultRecord): VaultItem {
  const colors: Record<string, string> = { GitHub: '#111827', Notion: '#111827', Figma: '#f24e1e', Linear: '#5e6ad2', 'AWS Console': '#ff9900', LinkedIn: '#0a66c2', 'Proton Mail': '#6d4aff' }
  return { ...item, color: colors[item.title] || '#6c5ce7', initials: item.title.slice(0, 2).toUpperCase() || '•', updated: item.updatedAt ? new Date(item.updatedAt).toLocaleString() : 'Unknown' }
}

function detailInput(detail: EntryDetail, changes: Partial<EntryInput> = {}): EntryInput {
  return { groupId: detail.groupId, title: detail.title, username: detail.username, password: detail.password, url: detail.url, notes: detail.notes, category: detail.category, favorite: detail.favorite, totp: detail.totp, ...changes }
}

function errorMessage(cause: unknown): string {
  if (cause && typeof cause === 'object' && 'message' in cause) return String(cause.message)
  return cause instanceof Error ? cause.message : String(cause)
}

const navItems: { id: View; label: string; icon: LucideIcon; badge?: string }[] = [
  { id: 'vault', label: 'Vault', icon: LayoutDashboard },
  { id: 'generator', label: 'Generator', icon: WandSparkles },
  { id: 'security', label: 'Security center', icon: ShieldCheck },
  { id: 'two-factor', label: '2FA codes', icon: Clock3 },
]


function App() {
  const [view, setView] = useState<View>('vault')
  const [selected, setSelected] = useState<VaultItem | null>(null)
  const [selectedDetail, setSelectedDetail] = useState<EntryDetail | null>(null)
  const [vaultItems, setVaultItems] = useState<VaultItem[]>([])
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('All items')
  const [groups, setGroups] = useState<VaultGroup[]>([])
  const [groupFilter, setGroupFilter] = useState('')
  const [groupsOpen, setGroupsOpen] = useState(false)
  const [editor, setEditor] = useState<'add' | 'edit' | null>(null)
  const [gate, setGate] = useState<'loading' | 'create' | 'unlock' | 'open' | 'desktop'>('loading')
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null)
  const [toast, setToast] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [theme, setTheme] = useState<Theme>(getInitialTheme)
  const updater = useUpdateController()
  const breach = useBreachController(gate === 'open')

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
    localStorage.setItem('ciphera-theme', theme)
  }, [theme])

  useEffect(() => {
    if (!isTauri()) {
      setGate('desktop')
      return
    }
    invoke<VaultStatus>('vault_status', { path: null }).then((status) => {
      setVaultStatus(status)
      setGate(status.unlocked ? 'open' : status.exists ? 'unlock' : 'create')
    }).catch(() => setGate('unlock'))
  }, [])

  const loadItems = async () => {
    const [records, nextGroups] = await Promise.all([
      invoke<VaultRecord[]>('list_vault_entries', { query: null }),
      invoke<VaultGroup[]>('list_vault_groups'),
    ])
    const next = records.map(decorateItem)
    setVaultItems(next)
    setGroups(nextGroups)
    setGroupFilter((current) => nextGroups.some((group) => group.id === current) ? current : '')
    setSelected((current) => next.find((item) => item.id === current?.id) || next[0] || null)
  }

  useEffect(() => {
    if (gate === 'open') loadItems().catch((cause) => setToast(errorMessage(cause)))
  }, [gate])

  useEffect(() => {
    if (!selected || gate !== 'open') {
      setSelectedDetail(null)
      return
    }
    let active = true
    setSelectedDetail(null)
    invoke<EntryDetail>('get_vault_entry', { id: selected.id }).then((detail) => {
      if (active) setSelectedDetail(detail)
    }).catch((cause) => {
      if (active) setToast(errorMessage(cause))
    })
    return () => { active = false }
  }, [selected, gate])

  const lock = async () => {
    await invoke('lock_vault').catch(() => undefined)
    setSelectedDetail(null)
    setVaultItems([])
    setSelected(null)
    setGate('unlock')
  }

  useEffect(() => {
    if (gate !== 'open') return
    let timer = window.setTimeout(lock, 10 * 60_000)
    const reset = () => {
      window.clearTimeout(timer)
      timer = window.setTimeout(lock, 10 * 60_000)
    }
    const events: (keyof WindowEventMap)[] = ['pointerdown', 'keydown', 'focus']
    events.forEach((event) => window.addEventListener(event, reset))
    return () => {
      window.clearTimeout(timer)
      events.forEach((event) => window.removeEventListener(event, reset))
    }
  }, [gate])

  const copy = async (value: string, message = 'Copied securely') => {
    await navigator.clipboard.writeText(value)
    setToast(message)
    window.setTimeout(() => setToast(''), 1800)
    window.setTimeout(async () => {
      try {
        if (await navigator.clipboard.readText() === value) await navigator.clipboard.writeText('')
      } catch {
        await navigator.clipboard.writeText('').catch(() => undefined)
      }
    }, 60_000)
  }

  const filteredItems = useMemo(() => vaultItems.filter((item) => {
    const matchesQuery = `${item.title} ${item.username} ${item.url}`.toLowerCase().includes(query.toLowerCase())
    const matchesCategory = category === 'All items' || category === 'Favorites' && item.favorite || category === item.category
    const matchesGroup = !groupFilter || item.groupId === groupFilter
    return matchesQuery && matchesCategory && matchesGroup
  }), [vaultItems, query, category, groupFilter])

  const navigate = (next: View) => {
    setView(next)
    setSidebarOpen(false)
  }

  const saveEntry = async (input: EntryInput) => {
    const detail = editor === 'edit' && selected ? await invoke<EntryDetail>('update_vault_entry', { id: selected.id, input }) : await invoke<EntryDetail>('add_vault_entry', { input })
    await loadItems()
    setSelected(decorateItem(detail))
    setSelectedDetail(detail)
    setEditor(null)
    setToast('Item encrypted and saved')
  }

  const toggleFavorite = async (id: string) => {
    const detail = selectedDetail?.id === id ? selectedDetail : await invoke<EntryDetail>('get_vault_entry', { id })
    const updated = await invoke<EntryDetail>('update_vault_entry', { id, input: detailInput(detail, { favorite: !detail.favorite }) })
    await loadItems()
    if (selected?.id === id) setSelectedDetail(updated)
  }

  const deleteSelected = async () => {
    if (!selected || !window.confirm(`Delete “${selected.title}”? A deletion tombstone will be retained in the encrypted vault.`)) return
    await invoke('delete_vault_entry', { id: selected.id })
    setSelectedDetail(null)
    await loadItems()
    setToast('Item deleted; an encrypted tombstone was retained')
  }

  const applyDetail = async (detail: EntryDetail, message: string) => {
    await loadItems()
    setSelected(decorateItem(detail))
    setSelectedDetail(detail)
    setToast(message)
  }

  if (gate !== 'open') {
    return <><VaultGate mode={gate} status={vaultStatus} onOpen={async () => {
      const status = await invoke<VaultStatus>('vault_status', { path: vaultStatus?.path || null })
      setVaultStatus(status)
      setGate('open')
    }} /><UpdatePrompt controller={updater} /></>
  }

  return (
    <div className="app-shell">
      <Sidebar view={view} navigate={navigate} open={sidebarOpen} onClose={() => setSidebarOpen(false)} updateAvailable={Boolean(updater.update)} />
      <main className="main-area">
        <Topbar theme={theme} onTheme={() => setTheme((current) => current === 'light' ? 'dark' : 'light')} onMenu={() => setSidebarOpen(true)} onLock={lock} />
        {view === 'vault' && <VaultView items={filteredItems} selected={selected} detail={selectedDetail} groups={groups} groupFilter={groupFilter} onGroupFilter={setGroupFilter} onManageGroups={() => setGroupsOpen(true)} onSelect={setSelected} query={query} onQuery={setQuery} category={category} onCategory={setCategory} onAdd={() => setEditor('add')} onEdit={() => setEditor('edit')} onDelete={deleteSelected} onCopy={copy} onToggleFavorite={toggleFavorite} onDetailChanged={applyDetail} />}
        {view === 'generator' && <GeneratorView onCopy={copy} />}
        {view === 'security' && <SecurityView items={vaultItems} breach={breach} onOpenItem={(item) => { setSelected(item); setView('vault') }} />}
        {view === 'two-factor' && <TwoFactorView onCopy={copy} />}
        {view === 'settings' && <SettingsView updater={updater} breach={breach} onVaultRestored={async () => { await loadItems(); setToast('Previous encrypted vault snapshot restored') }} />}
      </main>
      {editor && <EntryModal initial={editor === 'edit' ? selectedDetail : null} groups={groups} onClose={() => setEditor(null)} onSave={saveEntry} />}
      {groupsOpen && <GroupManager groups={groups} onClose={() => setGroupsOpen(false)} onChanged={loadItems} />}
      {toast && <div className="toast"><Check size={16} />{toast}</div>}
      <UpdatePrompt controller={updater} />
    </div>
  )
}

type UpdateController = {
  update: Update | null
  state: 'idle' | 'checking' | 'ready' | 'installing' | 'error'
  progress: number
  error: string
  dismissed: boolean
  checkNow: () => Promise<void>
  install: () => Promise<void>
  dismiss: () => void
}

function useUpdateController(): UpdateController {
  const [update, setUpdate] = useState<Update | null>(null)
  const [state, setState] = useState<UpdateController['state']>('idle')
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState('')
  const [dismissed, setDismissed] = useState(false)

  const checkNow = useCallback(async () => {
    if (!isTauri()) return
    setState('checking')
    setError('')
    try {
      const available = await check()
      setUpdate(available)
      setDismissed(false)
      setState(available ? 'ready' : 'idle')
    } catch (cause) {
      setError(errorMessage(cause))
      setState('error')
    }
  }, [])

  useEffect(() => {
    if (!isTauri()) return
    const initial = window.setTimeout(checkNow, 2_000)
    const recurring = window.setInterval(checkNow, 6 * 60 * 60_000)
    return () => {
      window.clearTimeout(initial)
      window.clearInterval(recurring)
    }
  }, [checkNow])

  const install = useCallback(async () => {
    if (!update) return
    setState('installing')
    setError('')
    let downloaded = 0
    let contentLength = 0
    try {
      await update.downloadAndInstall((event) => {
        if (event.event === 'Started') contentLength = event.data.contentLength ?? 0
        if (event.event === 'Progress') {
          downloaded += event.data.chunkLength
          if (contentLength > 0) setProgress(Math.min(100, Math.round(downloaded / contentLength * 100)))
        }
        if (event.event === 'Finished') setProgress(100)
      })
      await relaunch()
    } catch (cause) {
      setError(errorMessage(cause))
      setState('error')
    }
  }, [update])

  return { update, state, progress, error, dismissed, checkNow, install, dismiss: () => setDismissed(true) }
}

function UpdatePrompt({ controller }: { controller: UpdateController }) {
  const { update, state, progress, error, dismissed, install, dismiss } = controller
  if (!update || dismissed) return null
  return <div className="update-prompt" role="status">
    <Download size={21} />
    <div><strong>Ciphera {update.version} is available</strong><span>{state === 'installing' ? `Downloading and verifying… ${progress}%` : error || 'Install the signed update without downloading an installer manually.'}</span></div>
    <button className="secondary-button" onClick={install} disabled={state === 'installing'}>{state === 'installing' ? 'Installing…' : state === 'error' ? 'Retry' : 'Update and restart'}</button>
    {state !== 'installing' && <button className="icon-button" aria-label="Dismiss update" onClick={dismiss}><X size={17} /></button>}
  </div>
}

type BreachEntry = { id: string; exposureCount: number }
type BreachResult = { checkedPasswords: number; breachedEntries: BreachEntry[] }
type BreachController = {
  enabled: boolean
  state: 'idle' | 'checking' | 'ready' | 'error'
  result: BreachResult | null
  error: string
  setEnabled: (enabled: boolean) => void
  checkNow: () => Promise<void>
}

function useBreachController(unlocked: boolean): BreachController {
  const [enabled, setEnabledState] = useState(() => localStorage.getItem('ciphera-breach-monitoring') === 'enabled')
  const [state, setState] = useState<BreachController['state']>('idle')
  const [result, setResult] = useState<BreachResult | null>(null)
  const [error, setError] = useState('')

  const checkNow = useCallback(async () => {
    if (!isTauri() || !unlocked) return
    setState('checking')
    setError('')
    try {
      setResult(await invoke<BreachResult>('check_breached_passwords'))
      setState('ready')
    } catch (cause) {
      setError(errorMessage(cause))
      setState('error')
    }
  }, [unlocked])

  useEffect(() => {
    if (!enabled || !unlocked) return
    checkNow()
    const recurring = window.setInterval(checkNow, 24 * 60 * 60_000)
    return () => window.clearInterval(recurring)
  }, [checkNow, enabled, unlocked])

  const setEnabled = (next: boolean) => {
    setEnabledState(next)
    localStorage.setItem('ciphera-breach-monitoring', next ? 'enabled' : 'disabled')
    if (!next) {
      setResult(null)
      setState('idle')
      setError('')
    }
  }
  return { enabled, state, result, error, setEnabled, checkNow }
}

function Sidebar({ view, navigate, open, onClose, updateAvailable }: { view: View; navigate: (view: View) => void; open: boolean; onClose: () => void; updateAvailable: boolean }) {
  return (
    <>
      {open && <button className="sidebar-scrim" onClick={onClose} aria-label="Close menu" />}
      <aside className={`sidebar ${open ? 'open' : ''}`}>
        <div className="brand"><div className="brand-mark"><ShieldCheck size={21} /></div><span>Ciphera</span><button className="close-sidebar" onClick={onClose}><X size={20} /></button></div>
        <div className="workspace-switch"><div className="workspace-avatar"><Lock size={16} /></div><div><strong>Local vault</strong><span>Encrypted KDBX file</span></div></div>
        <nav>
          <div className="nav-label">Workspace</div>
          {navItems.map(({ id, label, icon: Icon, badge }) => (
            <button key={id} className={view === id ? 'nav-item active' : 'nav-item'} onClick={() => navigate(id)}>
              <Icon size={18} strokeWidth={1.8} /><span>{label}</span>{badge && <b className="nav-badge">{badge}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button className={view === 'settings' ? 'nav-item active' : 'nav-item'} onClick={() => navigate('settings')}><span className="settings-nav-icon"><Settings size={18} />{updateAvailable && <i className="update-dot" />}</span>Settings</button>
          <div className="sync-status"><span><Check size={12} /></span>Saved locally</div>
        </div>
      </aside>
    </>
  )
}

function Topbar({ theme, onTheme, onMenu, onLock }: { theme: Theme; onTheme: () => void; onMenu: () => void; onLock: () => void }) {
  return <header className="topbar">
    <button className="icon-button menu-button" onClick={onMenu}><Menu size={20} /></button>
    <div className="command-search"><Search size={17} /><span>Search your vault</span><kbd>⌘ K</kbd></div>
    <div className="top-actions">
      <div className="shield-pill"><ShieldCheck size={15} /><span>Protected</span></div>
      <button className="icon-button theme-button" onClick={onTheme} aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}>{theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}</button>
      <button className="icon-button" onClick={onLock} aria-label="Lock vault"><Lock size={18} /></button>
    </div>
  </header>
}

function ServiceIcon({ title, initials, color, large = false }: { title: string; initials: string; color: string; large?: boolean }) {
  const icon = BRAND_ICON_BY_TITLE[title]
  const className = `service-icon brand-icon${large ? ' large' : ''}`
  if (icon) return <span className={className} style={{ background: color }} title={icon.title}><svg viewBox="0 0 24 24" aria-hidden="true"><path d={icon.path} /></svg></span>
  if (title === 'AWS Console') return <span className={`${className} aws-icon`} style={{ background: color }} title="Amazon Web Services"><svg viewBox="0 0 48 28" aria-hidden="true"><text x="3" y="17">aws</text><path d="M8 21c8 5 22 6 33 0M36 20l5 1-2 4" /></svg></span>
  if (title === 'LinkedIn') return <span className={`${className} linkedin-icon`} style={{ background: color }} title="LinkedIn">in</span>
  return <span className={className} style={{ background: color }}>{initials}</span>
}

function VaultView({ items, selected, detail, groups, groupFilter, onGroupFilter, onManageGroups, onSelect, query, onQuery, category, onCategory, onAdd, onEdit, onDelete, onCopy, onToggleFavorite, onDetailChanged }: {
  items: VaultItem[]; selected: VaultItem | null; detail: EntryDetail | null; groups: VaultGroup[]; groupFilter: string; onGroupFilter: (value: string) => void; onManageGroups: () => void; onSelect: (item: VaultItem) => void; query: string; onQuery: (value: string) => void; category: string; onCategory: (value: string) => void; onAdd: () => void; onEdit: () => void; onDelete: () => void; onCopy: (value: string, message?: string) => void; onToggleFavorite: (id: string) => void; onDetailChanged: (detail: EntryDetail, message: string) => Promise<void>
}) {
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [historyEntries, setHistoryEntries] = useState<EntryHistory[]>([])
  const [historyError, setHistoryError] = useState('')
  const categories = ['All items', 'Favorites', 'Login', 'Card', 'Identity', 'Secure note']
  useEffect(() => setPasswordVisible(false), [selected?.id])
  const risks = items.filter((item) => item.health !== 'safe').length
  const score = items.length ? Math.round((items.length - risks) / items.length * 100) : 100
  const showHistory = async () => {
    if (!selected) return
    setHistoryOpen(true)
    setHistoryError('')
    try {
      setHistoryEntries(await invoke<EntryHistory[]>('vault_entry_history', { id: selected.id }))
    } catch (cause) {
      setHistoryError(errorMessage(cause))
    }
  }
  const restoreHistory = async (index: number) => {
    if (!selected || !window.confirm('Restore this encrypted entry version? The current version will remain in history.')) return
    try {
      const restored = await invoke<EntryDetail>('restore_vault_entry_history', { id: selected.id, index })
      await onDetailChanged(restored, 'Previous entry version restored')
      setHistoryOpen(false)
    } catch (cause) {
      setHistoryError(errorMessage(cause))
    }
  }
  const addAttachment = async () => {
    if (!selected) return
    const path = await open({ multiple: false, directory: false, title: 'Attach a file (20 MiB maximum)' })
    if (typeof path !== 'string') return
    try {
      const updated = await invoke<EntryDetail>('add_vault_attachment', { id: selected.id, path })
      await onDetailChanged(updated, 'Attachment encrypted into the vault')
    } catch (cause) {
      setHistoryError(errorMessage(cause))
    }
  }
  const saveAttachment = async (attachment: AttachmentSummary) => {
    if (!selected) return
    const path = await save({ defaultPath: attachment.name, title: 'Save decrypted attachment' })
    if (!path) return
    try {
      await invoke('save_vault_attachment', { id: selected.id, name: attachment.name, path })
      onCopy('', `Attachment saved to ${path}`)
    } catch (cause) {
      setHistoryError(errorMessage(cause))
    }
  }
  const removeAttachment = async (attachment: AttachmentSummary) => {
    if (!selected || !window.confirm(`Remove “${attachment.name}” from this entry?`)) return
    try {
      const updated = await invoke<EntryDetail>('remove_vault_attachment', { id: selected.id, name: attachment.name })
      await onDetailChanged(updated, 'Attachment removed')
    } catch (cause) {
      setHistoryError(errorMessage(cause))
    }
  }
  return <>
    <div className="vault-page">
      <section className="vault-browser">
        <div className="page-title-row"><div><p className="eyebrow">LOCAL VAULT</p><h1>Your vault</h1><p>Encrypted records stored in your local KDBX file.</p></div><button className="primary-button" onClick={onAdd}><Plus size={18} />New item</button></div>
        <div className="vault-stats">
          <div><span className="stat-icon lavender"><KeyRound /></span><p><strong>{items.length}</strong><span>Visible items</span></p></div>
          <div><span className="stat-icon mint"><ShieldCheck /></span><p><strong>{score}%</strong><span>Security score</span></p></div>
          <div><span className="stat-icon peach"><AlertTriangle /></span><p><strong>{risks}</strong><span>Need attention</span></p></div>
        </div>
        <div className="filter-row">
          <label className="search-input"><Search size={17} /><input value={query} onChange={(event) => onQuery(event.target.value)} placeholder="Search items" />{query && <button onClick={() => onQuery('')}><X size={15} /></button>}</label>
          <label className="select-wrap"><Grid2X2 size={16} /><select value={category} onChange={(event) => onCategory(event.target.value)}>{categories.map((option) => <option key={option}>{option}</option>)}</select><ChevronDown size={14} /></label>
          <label className="select-wrap group-select"><FolderTree size={16} /><select value={groupFilter} onChange={(event) => onGroupFilter(event.target.value)}><option value="">All groups</option>{groups.map((group) => <option value={group.id} key={group.id}>{group.name}</option>)}</select><ChevronDown size={14} /></label>
          <button className="sort-button" onClick={onManageGroups}><Settings size={14} />Groups</button>
        </div>
        <div className="item-table">
          <div className="item-table-head"><span>Item</span><span>Category</span><span>Updated</span><span /></div>
          {items.map((item) => <button key={item.id} className={`item-row ${selected?.id === item.id ? 'selected' : ''}`} onClick={() => onSelect(item)}>
            <div className="item-identity"><ServiceIcon title={item.title} initials={item.initials} color={item.color} /><p><strong>{item.title}</strong><span>{item.username}</span></p></div>
            <span className="category-cell">{item.category}</span><span className="updated-cell">{item.updated}</span>
            <span className="row-actions">{item.favorite && <Star size={15} fill="currentColor" />}<MoreHorizontal size={17} /></span>
          </button>)}
          {!items.length && <div className="empty-state"><KeyRound size={28} /><strong>No matching vault items</strong><span>Change the filters or add an encrypted record.</span></div>}
        </div>
      </section>
      <aside className="detail-panel">
        {!selected && <div className="empty-state"><Lock size={30} /><strong>No item selected</strong><span>Select or add a vault item.</span></div>}
        {selected && <>
          <div className="detail-head"><ServiceIcon title={selected.title} initials={selected.initials} color={selected.color} large /><div><h2>{selected.title}</h2>{selected.url && <a href={selected.url.includes('://') ? selected.url : `https://${selected.url}`} target="_blank" rel="noreferrer">{selected.url}<ArrowRight size={12} /></a>}</div><button className="icon-button" onClick={() => onToggleFavorite(selected.id)}><Star size={18} fill={selected.favorite ? 'currentColor' : 'none'} /></button><button className="icon-button" onClick={onEdit} disabled={!detail} aria-label="Edit item"><Pencil size={17} /></button></div>
          <div className="detail-status"><ShieldCheck size={16} />Protected in your KDBX vault<span>Stored locally</span></div>
          <div className="field-block"><label>USERNAME</label><div><span>{selected.username}</span><button onClick={() => onCopy(selected.username, 'Username copied')}><Copy size={16} /></button></div></div>
          <div className="field-block"><label>PASSWORD</label><div><span className={passwordVisible ? '' : 'masked'}>{detail ? passwordVisible ? detail.password : '••••••••••••••' : 'Loading…'}</span><button disabled={!detail} onClick={() => setPasswordVisible((value) => !value)}>{passwordVisible ? <EyeOff size={16} /> : <Eye size={16} />}</button><button disabled={!detail} onClick={() => detail && onCopy(detail.password, 'Password copied; clipboard clears in 60s')}><Copy size={16} /></button></div></div>
          <div className="password-health"><div><span>Strength</span><strong className={selected.health === 'safe' ? 'safe' : 'warning'}>{selected.health === 'safe' ? 'Excellent' : 'Needs attention'}</strong></div><div className="mini-bars">{[0, 1, 2, 3].map((value) => <i key={value} className={selected.health === 'safe' || value < 2 ? 'filled' : ''} />)}</div></div>
          <div className="field-block"><label>WEBSITE</label><div><span>{selected.url || 'Not set'}</span><button onClick={() => onCopy(selected.url)}><Copy size={16} /></button></div></div>
          <div className="field-block"><label>ONE-TIME PASSWORD</label><button className="add-totp" onClick={onEdit}><Plus size={15} />{detail?.totp ? 'Edit 2FA code' : 'Add 2FA code'}</button></div>
          {detail?.notes && <div className="notes"><label>NOTES</label><p>{detail.notes}</p></div>}
          <div className="attachment-block"><div><label>ATTACHMENTS</label><button onClick={addAttachment} disabled={!detail}><Paperclip size={14} />Add</button></div>{detail?.attachments.length ? detail.attachments.map((attachment) => <div className="attachment-row" key={attachment.name}><Paperclip size={15} /><span><strong>{attachment.name}</strong><small>{attachment.size < 1024 ? `${attachment.size} B` : `${(attachment.size / 1024).toFixed(1)} KiB`}</small></span><button onClick={() => saveAttachment(attachment)} aria-label={`Save ${attachment.name}`}><Download size={15} /></button><button onClick={() => removeAttachment(attachment)} aria-label={`Remove ${attachment.name}`}><Trash2 size={15} /></button></div>) : <p>No files attached</p>}</div>
          {historyError && <p className="form-error detail-error">{historyError}</p>}
          <div className="detail-footer"><span><Clock3 size={14} />Updated {selected.updated}</span><button onClick={showHistory}><History size={15} />History</button><button onClick={onDelete}><Trash2 size={15} />Delete</button></div>
        </>}
      </aside>
    </div>
    {historyOpen && <div className="modal-backdrop"><div className="modal history-modal"><button type="button" className="modal-close" onClick={() => setHistoryOpen(false)}><X size={20} /></button><span className="modal-icon"><History /></span><h2>Entry history</h2><p>Encrypted versions are stored inside the KDBX database.</p>{historyError && <p className="form-error">{historyError}</p>}<div className="history-list">{historyEntries.map((entry) => <div className="history-version" key={entry.index}><History size={16} /><div><strong>{entry.title || 'Untitled item'}</strong><span>{entry.updatedAt ? new Date(entry.updatedAt).toLocaleString() : 'Unknown date'} · {entry.username || 'No username'}</span></div><button className="secondary-button" onClick={() => restoreHistory(entry.index)}><RotateCcw size={14} />Restore</button></div>)}{!historyError && !historyEntries.length && <div className="empty-state"><History size={24} /><strong>No earlier versions</strong><span>History appears after an item is edited.</span></div>}</div></div></div>}
  </>
}

function GroupManager({ groups, onClose, onChanged }: { groups: VaultGroup[]; onClose: () => void; onChanged: () => Promise<void> }) {
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const createGroup = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    try {
      await invoke('create_vault_group', { parentId: null, name })
      setName('')
      await onChanged()
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }
  const renameGroup = async (group: VaultGroup) => {
    const next = window.prompt('Rename group', group.name)?.trim()
    if (!next || next === group.name) return
    setError('')
    try {
      await invoke('rename_vault_group', { id: group.id, name: next })
      await onChanged()
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }
  const deleteGroup = async (group: VaultGroup) => {
    if (!window.confirm(`Delete empty group “${group.name}”?`)) return
    setError('')
    try {
      await invoke('delete_vault_group', { id: group.id })
      await onChanged()
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }
  const editable = groups.filter((group) => group.parentId)
  return <div className="modal-backdrop"><div className="modal group-modal"><button type="button" className="modal-close" onClick={onClose}><X size={20} /></button><span className="modal-icon"><FolderTree /></span><h2>Organize groups</h2><p>Groups remain compatible with other KDBX applications.</p><form className="group-create" onSubmit={createGroup}><input value={name} onChange={(event) => setName(event.target.value)} placeholder="New group name" required /><button className="primary-button"><Plus size={15} />Add group</button></form>{error && <p className="form-error">{error}</p>}<div className="group-list">{editable.map((group) => <div className="group-row" key={group.id}><FolderTree size={16} /><strong>{group.name}</strong><button onClick={() => renameGroup(group)} aria-label={`Rename ${group.name}`}><Pencil size={15} /></button><button onClick={() => deleteGroup(group)} aria-label={`Delete ${group.name}`}><Trash2 size={15} /></button></div>)}{!editable.length && <div className="empty-state"><FolderTree size={24} /><strong>No custom groups</strong><span>Create one to organize vault items.</span></div>}</div></div></div>
}

function GeneratorView({ onCopy }: { onCopy: (value: string, message?: string) => void }) {
  const [mode, setMode] = useState<'password' | 'passphrase'>('password')
  const [options, setOptions] = useState<PasswordOptions>({ length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true })
  const [words, setWords] = useState(5)
  const make = () => mode === 'password' ? generatePassword(options) : generatePassphrase(words)
  const [value, setValue] = useState(() => generatePassword(options))
  const [history, setHistory] = useState<string[]>([])
  const strength = ratePassword(value)
  const regenerate = () => { const next = make(); setValue(next); setHistory((current) => [value, ...current].slice(0, 4)) }
  const switchMode = (nextMode: 'password' | 'passphrase') => {
    setMode(nextMode)
    setValue(nextMode === 'password' ? generatePassword(options) : generatePassphrase(words))
  }

  return <div className="content-page generator-page">
    <div className="page-title-row"><div><p className="eyebrow">SECURE TOOLS</p><h1>Password generator</h1><p>Create unique credentials with cryptographically secure randomness.</p></div><span className="local-badge"><WifiOff size={15} />Generated on this device</span></div>
    <div className="generator-grid">
      <section className="card generator-card">
        <div className="segment-control"><button className={mode === 'password' ? 'active' : ''} onClick={() => switchMode('password')}>Random password</button><button className={mode === 'passphrase' ? 'active' : ''} onClick={() => switchMode('passphrase')}>Memorable phrase</button></div>
        <div className="generated-output"><span>{value}</span><button onClick={regenerate} aria-label="Generate another"><RefreshCw size={19} /></button><button className="copy-primary" onClick={() => onCopy(value, 'Generated password copied')}><Copy size={18} />Copy</button></div>
        <div className="strength-summary"><div><span>Strength</span><strong>{strength.label}</strong></div><div className="strength-track">{[0, 1, 2, 3, 4].map((level) => <i key={level} className={level <= strength.score ? `level-${strength.score}` : ''} />)}</div><div className="entropy"><span>{strength.entropy} bits entropy</span><span>Estimated crack time: <strong>{strength.timeToCrack}</strong></span></div></div>
        {mode === 'password' ? <div className="generator-controls">
          <div className="range-heading"><label>Password length</label><output>{options.length}</output></div><input type="range" min="8" max="64" value={options.length} onChange={(event) => setOptions({ ...options, length: Number(event.target.value) })} />
          <div className="toggle-grid">
            <Toggle label="Uppercase" hint="A–Z" checked={options.uppercase} onChange={(checked) => setOptions({ ...options, uppercase: checked })} />
            <Toggle label="Lowercase" hint="a–z" checked={options.lowercase} onChange={(checked) => setOptions({ ...options, lowercase: checked })} />
            <Toggle label="Numbers" hint="0–9" checked={options.numbers} onChange={(checked) => setOptions({ ...options, numbers: checked })} />
            <Toggle label="Symbols" hint="!@#$" checked={options.symbols} onChange={(checked) => setOptions({ ...options, symbols: checked })} />
            <Toggle label="Avoid ambiguous" hint="I, l, 1, O, 0" checked={options.avoidAmbiguous} onChange={(checked) => setOptions({ ...options, avoidAmbiguous: checked })} wide />
          </div>
        </div> : <div className="generator-controls"><div className="range-heading"><label>Number of words</label><output>{words}</output></div><input type="range" min="3" max="8" value={words} onChange={(event) => setWords(Number(event.target.value))} /><div className="phrase-tip"><Sparkles size={18} /><div><strong>Easy to remember, hard to guess</strong><span>Five random words provide strong protection without sacrificing usability.</span></div></div></div>}
        <button className="generate-large" onClick={regenerate}><RefreshCw size={17} />Generate new {mode === 'password' ? 'password' : 'phrase'}</button>
      </section>
      <aside className="generator-side">
        <div className="card"><div className="side-card-title"><Clock3 size={18} /><h3>Recent generations</h3><button onClick={() => setHistory([])}>Clear</button></div>{history.length ? history.map((entry, index) => <button className="history-row" key={`${entry}-${index}`} onClick={() => onCopy(entry)}><span>{entry}</span><Copy size={15} /></button>) : <div className="history-empty"><Asterisk size={22} /><span>Generated passwords appear here for this session only.</span></div>}</div>
        <div className="card security-note"><ShieldCheck size={22} /><div><h3>Private by design</h3><p>Generation runs locally with <code>crypto.getRandomValues</code>. Values never leave this device unless you save them.</p></div></div>
      </aside>
    </div>
  </div>
}

function Toggle({ label, hint, checked, onChange, wide }: { label: string; hint: string; checked: boolean; onChange: (value: boolean) => void; wide?: boolean }) {
  return <label className={`toggle-row ${wide ? 'wide' : ''}`}><span><strong>{label}</strong><small>{hint}</small></span><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><i /></label>
}

function SecurityView({ items, breach, onOpenItem }: { items: VaultItem[]; breach: BreachController; onOpenItem: (item: VaultItem) => void }) {
  const exposureById = new Map(breach.result?.breachedEntries.map((entry) => [entry.id, entry.exposureCount]) || [])
  const risks = items.filter((item) => item.health !== 'safe' || exposureById.has(item.id))
  const count = (health: VaultItem['health']) => items.filter((item) => item.health === health).length
  const score = items.length ? Math.round((items.length - risks.length) / items.length * 100) : 100
  return <div className="content-page security-page">
    <div className="page-title-row"><div><p className="eyebrow">SECURITY REVIEW</p><h1>Your security posture</h1><p>Local password analysis with optional privacy-preserving breach monitoring.</p></div>{breach.enabled && <button className="secondary-button" disabled={breach.state === 'checking'} onClick={breach.checkNow}><RefreshCw size={15} />{breach.state === 'checking' ? 'Checking…' : 'Check breaches'}</button>}</div>
    <section className="score-hero card"><div className="score-ring"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" /><circle className="progress" cx="60" cy="60" r="52" style={{ strokeDashoffset: 327 - 327 * score / 100 }} /></svg><div><strong>{score}</strong><span>{score >= 80 ? 'Strong' : 'Review'}</span></div></div><div className="score-copy"><h2>{risks.length ? `${risks.length} item${risks.length === 1 ? ' needs' : 's need'} attention` : 'No password risks detected'}</h2><p>{breach.enabled ? 'Breach checks send only the first five SHA-1 characters to Pwned Passwords with response padding; matching stays on this device.' : 'Local review checks weak, reused, and old passwords. Enable daily breach monitoring in Settings.'}</p><div className="score-pills"><span><Check size={14} />Local risk analysis</span><span><Check size={14} />Passwords never transmitted</span></div></div></section>
    <div className="risk-grid"><div className="risk-card"><span className="risk-icon amber"><Activity /></span><div><strong>{count('weak')}</strong><span>Weak passwords</span></div></div><div className="risk-card"><span className="risk-icon violet"><Copy /></span><div><strong>{count('reused')}</strong><span>Reused passwords</span></div></div><div className="risk-card"><span className="risk-icon blue"><Clock3 /></span><div><strong>{count('old')}</strong><span>Old passwords</span></div></div><div className="risk-card"><span className="risk-icon danger"><AlertTriangle /></span><div><strong>{breach.result?.breachedEntries.length ?? '—'}</strong><span>Known breaches</span></div></div></div>
    {breach.state === 'error' && <p className="form-error">{breach.error}</p>}
    <div className="security-grid">
      <section className="card issues-card"><div className="section-heading"><div><h2>Needs your attention</h2><p>Open an item to update its credentials.</p></div></div>
        {risks.map((item) => {
          const exposureCount = exposureById.get(item.id)
          const detail = exposureCount ? `Password appears ${exposureCount.toLocaleString()} times in the Pwned Passwords corpus` : item.health === 'weak' ? 'Password does not meet local strength checks' : item.health === 'reused' ? 'Password is reused in this vault' : 'Password has not changed for over a year'
          return <button className="issue-row" key={item.id} onClick={() => onOpenItem(item)}><ServiceIcon title={item.title} initials={item.initials} color={item.color} /><div><strong>{item.title}</strong><span>{detail}</span></div><span className={`severity ${exposureCount ? 'breached' : item.health}`}>{exposureCount ? 'Change now' : item.health === 'old' ? 'Review' : 'Fix now'}</span><ChevronRight size={17} /></button>
        })}
        {!risks.length && <div className="empty-state"><ShieldCheck size={27} /><strong>No risks found</strong><span>Keep using a unique password for every account.</span></div>}
      </section>
    </div>
  </div>
}


function TwoFactorView({ onCopy }: { onCopy: (value: string, message?: string) => void }) {
  const [entries, setEntries] = useState<TotpCode[]>([])
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    const refresh = () => invoke<TotpCode[]>('vault_totp_codes').then((codes) => {
      if (active) {
        setEntries(codes)
        setError('')
      }
    }).catch((cause) => {
      if (active) setError(errorMessage(cause))
    })
    refresh()
    const timer = window.setInterval(refresh, 1000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])
  return <div className="content-page twofa-page">
    <div className="page-title-row"><div><p className="eyebrow">AUTHENTICATOR</p><h1>Two-factor codes</h1><p>Codes are generated in Rust without exposing TOTP secrets to the interface.</p></div></div>
    <div className="twofa-layout"><section className="card totp-list"><div className="section-heading"><div><h2>Your accounts</h2><p>{entries.length} accounts with one-time codes</p></div></div>
      {error && <div className="empty-state"><AlertTriangle size={24} /><strong>Codes unavailable</strong><span>{error}</span></div>}
      {!error && !entries.length && <div className="empty-state"><Clock3 size={24} /><strong>No authenticator codes</strong><span>Add a TOTP setup key while editing a vault item.</span></div>}
      {entries.map((entry) => {
        const item = decorateItem({ id: entry.id, groupId: '', title: entry.title, username: entry.username, url: '', category: 'Login', favorite: false, health: 'safe', updatedAt: null })
        const progress = Math.max(0, Math.min(100, entry.validFor / entry.period * 100))
        return <div className="totp-row" key={entry.id}><ServiceIcon title={entry.title} initials={item.initials} color={item.color} large /><div className="totp-name"><strong>{entry.title}</strong><span>{entry.username}</span></div><button className="totp-code" onClick={() => onCopy(entry.code, 'Verification code copied')}><span>{entry.code.slice(0, 3)} {entry.code.slice(3)}</span><Copy size={16} /></button><div className="totp-timer"><svg viewBox="0 0 36 36"><circle cx="18" cy="18" r="15" /><circle className="timer-progress" cx="18" cy="18" r="15" style={{ strokeDashoffset: 94 - 94 * progress / 100 }} /></svg><span>{entry.validFor}</span></div></div>
      })}
    </section>
      <aside className="twofa-side"><div className="card twofa-info"><div className="info-illustration"><Smartphone size={32} /><span><ShieldCheck size={18} /></span></div><h3>Keep vault recovery separate</h3><p>Use a hardware security key or separate authenticator for recovery. Never keep the only recovery factor inside the vault it protects.</p></div></aside>
    </div>
  </div>
}

function SettingsView({ updater, breach, onVaultRestored }: { updater: UpdateController; breach: BreachController; onVaultRestored: () => Promise<void> }) {
  const [status, setStatus] = useState<VaultStatus | null>(null)
  const [pinPassword, setPinPassword] = useState('')
  const [pin, setPin] = useState('')
  const [confirmPin, setConfirmPin] = useState('')
  const [pinOpen, setPinOpen] = useState(false)
  const [passwordOpen, setPasswordOpen] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [backups, setBackups] = useState<BackupInfo[]>([])
  const refresh = async () => {
    const [nextStatus, nextBackups] = await Promise.all([
      invoke<VaultStatus>('vault_status', { path: null }),
      invoke<BackupInfo[]>('vault_backups'),
    ])
    setStatus(nextStatus)
    setBackups(nextBackups)
  }
  useEffect(() => {
    refresh().catch((cause) => setError(errorMessage(cause)))
  }, [])
  const disablePinUnlock = async () => {
    try {
      await invoke('disable_pin_unlock', { path: status?.path || null })
      await refresh()
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }
  const enablePinUnlock = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    if (pin !== confirmPin) {
      setError('PINs do not match')
      return
    }
    if (!/^(?:\d{4}|\d{6})$/.test(pin)) {
      setError('PIN must contain exactly 4 or 6 digits')
      return
    }
    try {
      await invoke('enable_pin_unlock', { path: status?.path || null, password: pinPassword, pin })
      setPinPassword('')
      setPin('')
      setConfirmPin('')
      setPinOpen(false)
      await refresh()
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }
  const changePassword = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    if (newPassword !== confirmPassword) {
      setError('New master passwords do not match')
      return
    }
    try {
      await invoke('change_vault_password', { currentPassword, newPassword })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setPasswordOpen(false)
      await refresh()
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }
  const restoreBackup = async (backup: BackupInfo) => {
    if (!window.confirm(`Restore the vault snapshot from ${backup.modifiedAt ? new Date(backup.modifiedAt).toLocaleString() : backup.path}? The current vault will be preserved as a new backup.`)) return
    setError('')
    try {
      await invoke('restore_vault_backup', { index: backup.index })
      await refresh()
      await onVaultRestored()
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }
  return <div className="content-page settings-page">
    <div className="page-title-row"><div><p className="eyebrow">PREFERENCES</p><h1>Settings</h1><p>Security controls backed by the native vault process.</p></div></div>
    <div className="settings-layout">
      <section className="card settings-card">
        <div className="section-heading"><div><h2>Security</h2><p>Protection on this device</p></div><ShieldCheck size={23} /></div>
        <div className="setting-row"><span className="setting-icon"><Clock3 size={19} /></span><div><strong>Automatic lock</strong><span>Ciphera locks after 10 minutes of inactivity</span></div><BadgeCheck size={18} /></div>
        <div className="setting-row"><span className="setting-icon"><Clipboard size={19} /></span><div><strong>Clear clipboard</strong><span>Copied secrets clear after 60 seconds</span></div><BadgeCheck size={18} /></div>
        <div className="setting-row"><span className="setting-icon"><Fingerprint size={19} /></span><div><strong>PIN quick unlock</strong><span>{status?.pinUnlock.configured ? status.pinUnlock.masterPasswordRequired ? 'Master password required after too many failed PIN attempts' : `Protected by the OS credential vault · ${status.pinUnlock.attemptsRemaining} attempts available` : 'Not configured on this device'}</span></div>{status?.pinUnlock.configured ? <button className="text-button" onClick={disablePinUnlock}>Disable</button> : <button className="text-button" onClick={() => setPinOpen(true)}>Enable</button>}</div>
        <div className="setting-row"><span className="setting-icon"><KeyRound size={19} /></span><div><strong>Master password</strong><span>Re-encrypt the vault with a new master password</span></div><button className="text-button" onClick={() => setPasswordOpen(true)}>Change</button></div>
        <div className="setting-row"><span className="setting-icon"><RefreshCw size={19} /></span><div><strong>Application updates</strong><span>{updater.update ? `Ciphera ${updater.update.version} is ready to install` : updater.state === 'checking' ? 'Checking GitHub Releases…' : updater.state === 'error' ? updater.error : 'Ciphera checks automatically every six hours'}</span></div>{updater.update ? <button className="text-button" disabled={updater.state === 'installing'} onClick={updater.install}>{updater.state === 'installing' ? `${updater.progress}%` : 'Update'}</button> : <button className="text-button" disabled={updater.state === 'checking'} onClick={updater.checkNow}>Check now</button>}</div>
        <div className="setting-row"><span className="setting-icon"><ShieldCheck size={19} /></span><div><strong>Daily password breach check</strong><span>{breach.enabled ? breach.state === 'checking' ? 'Checking password hash prefixes…' : breach.state === 'error' ? breach.error : 'Enabled · checks at launch and every 24 hours while Ciphera is open' : 'Disabled · enabling sends five-character hash prefixes to Pwned Passwords'}</span></div><button className="text-button" onClick={() => breach.setEnabled(!breach.enabled)}>{breach.enabled ? 'Disable' : 'Enable'}</button></div>
      </section>
      <aside className="card encryption-card">
        <div className="encryption-orbit"><Lock size={29} /></div><h3>Local KDBX 4.1 encryption</h3><p>Your vault file is encrypted on this device. Browser filling is served only by the unlocked native process.</p>
        <div><span><Check size={14} />AES-256 outer encryption</span><span><Check size={14} />Device-calibrated Argon2id</span><span><Check size={14} />Atomic saves with five rotating backups</span></div>
      </aside>
    </div>
    <BrowserIntegrationCard />
    <section className="card devices-card">
      <div className="section-heading"><div><h2>Vault file</h2><p>User-owned encrypted storage</p></div><HardDrive size={22} /></div>
      <div className="device-row"><span><HardDrive /></span><div><strong>{status?.path || 'Loading…'}</strong><small>Local KDBX 4.1 database · offline-first</small></div><b>Active</b></div>
    </section>
    <section className="card backup-card">
      <div className="section-heading"><div><h2>Recovery snapshots</h2><p>Five encrypted prior versions rotate beside your vault file</p></div><History size={22} /></div>
      <div className="backup-list">{backups.map((backup) => <div className="backup-row" key={backup.index}><span><History size={16} /></span><div><strong>{backup.index === 0 ? 'Most recent prior save' : `Earlier save ${backup.index + 1}`}</strong><small>{backup.modifiedAt ? new Date(backup.modifiedAt).toLocaleString() : backup.path} · {(backup.size / 1024).toFixed(1)} KiB</small></div><button className="secondary-button" onClick={() => restoreBackup(backup)}><RotateCcw size={14} />Restore</button></div>)}{!backups.length && <div className="empty-state compact"><History size={22} /><strong>No recovery snapshots yet</strong><span>A snapshot is created before each successful vault change.</span></div>}</div>
    </section>
    {pinOpen && <div className="modal-backdrop"><form className="modal small-modal add-modal" onSubmit={enablePinUnlock}><button type="button" className="modal-close" onClick={() => setPinOpen(false)}><X size={20} /></button><span className="modal-icon"><Fingerprint /></span><h2>Enable PIN quick unlock</h2><p>Confirm your master password, then choose a 4 or 6 digit PIN. Five failed attempts require the master password again.</p><label>MASTER PASSWORD<input type="password" value={pinPassword} onChange={(event) => setPinPassword(event.target.value)} autoFocus autoComplete="current-password" required /></label><label>PIN<input type="password" inputMode="numeric" pattern="(?:[0-9]{4}|[0-9]{6})" value={pin} onChange={(event) => setPin(event.target.value.replace(/\D/g, '').slice(0, 6))} autoComplete="new-password" required /></label><label>CONFIRM PIN<input type="password" inputMode="numeric" pattern="(?:[0-9]{4}|[0-9]{6})" value={confirmPin} onChange={(event) => setConfirmPin(event.target.value.replace(/\D/g, '').slice(0, 6))} autoComplete="new-password" required /></label>{error && <p className="form-error">{error}</p>}<button className="primary-button modal-save">Enable PIN unlock</button></form></div>}
    {passwordOpen && <div className="modal-backdrop"><form className="modal small-modal add-modal" onSubmit={changePassword}><button type="button" className="modal-close" onClick={() => setPasswordOpen(false)}><X size={20} /></button><span className="modal-icon"><KeyRound /></span><h2>Change master password</h2><p>The vault will be verified, backed up, and atomically re-encrypted.</p><label>CURRENT PASSWORD<input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} autoFocus required /></label><label>NEW PASSWORD<input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required /></label><label>CONFIRM NEW PASSWORD<input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required /></label>{error && <p className="form-error">{error}</p>}<button className="primary-button modal-save">Change master password</button></form></div>}
    {!pinOpen && !passwordOpen && error && <p className="form-error settings-error">{error}</p>}
  </div>
}

function BrowserIntegrationCard() {
  const desktop = isTauri()
  const [state, setState] = useState<'loading' | 'ready' | 'installed' | 'error'>(desktop ? 'loading' : 'error')
  const [detail, setDetail] = useState(desktop ? 'Checking the native messaging bridge…' : 'Browser integration is available in the standalone desktop app.')
  const [extensionDirectory, setExtensionDirectory] = useState('')
  const [firefoxExtensionDirectory, setFirefoxExtensionDirectory] = useState('')

  useEffect(() => {
    if (!desktop) return
    invoke<{ running: boolean; hostName: string }>('browser_integration_status')
      .then((status) => {
        setState(status.running ? 'ready' : 'error')
        setDetail(status.running ? `Native host ${status.hostName} is running locally.` : 'The native messaging bridge is unavailable.')
      })
      .catch(() => {
        setState('error')
        setDetail('The native messaging bridge could not be started.')
      })
  }, [desktop])

  const install = async () => {
    setState('loading')
    setDetail('Installing the private native host and extension files…')
    try {
      const result = await invoke<{ extensionDirectory: string; firefoxExtensionDirectory: string; installedManifests: string[] }>('install_browser_integration')
      setExtensionDirectory(result.extensionDirectory)
      setFirefoxExtensionDirectory(result.firefoxExtensionDirectory)
      setState('installed')
      setDetail(`Registered ${result.installedManifests.length} native browser manifests.`)
    } catch (cause) {
      setState('error')
      setDetail(cause instanceof Error ? cause.message : String(cause))
    }
  }

  return <section className="card browser-card">
    <div className="browser-icon"><Puzzle size={24} /></div>
    <div className="browser-copy">
      <div className="section-heading"><div><span className="new-badge">DESKTOP INTEGRATION</span><h2>Browser extension</h2><p>Fill logins through an authenticated local bridge. Vault data never passes through a web server.</p></div><span className={`integration-state ${state}`}><i />{state === 'installed' ? 'Installed' : state === 'ready' ? 'Bridge ready' : state === 'loading' ? 'Working' : desktop ? 'Needs attention' : 'Desktop only'}</span></div>
      <div className="bridge-detail"><ShieldCheck size={16} /><span>{detail}</span></div>
      {extensionDirectory && <><div className="extension-path"><FolderOpen size={15} /><code>{extensionDirectory}</code><span>Chromium: load this folder as an unpacked extension.</span></div><div className="extension-path"><FolderOpen size={15} /><code>{firefoxExtensionDirectory}</code><span>Firefox: load this folder from about:debugging → This Firefox.</span></div></>}
    </div>
    <button className="primary-button install-extension" disabled={!desktop || state === 'loading'} onClick={install}>{state === 'installed' ? 'Reinstall files' : 'Install extension'}</button>
  </section>
}


function EntryModal({ initial, groups, onClose, onSave }: { initial: EntryDetail | null; groups: VaultGroup[]; onClose: () => void; onSave: (input: EntryInput) => Promise<void> }) {
  const [title, setTitle] = useState(initial?.title || '')
  const [username, setUsername] = useState(initial?.username || '')
  const [password, setPassword] = useState(initial?.password || generatePassword({ length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true }))
  const [url, setUrl] = useState(initial?.url || '')
  const [notes, setNotes] = useState(initial?.notes || '')
  const [totp, setTotp] = useState(initial?.totp || '')
  const [category, setCategory] = useState<EntryCategory>(initial?.category || 'Login')
  const [groupId, setGroupId] = useState(initial?.groupId || groups.find((group) => !group.parentId)?.id || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const strength = ratePassword(password)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setSaving(true)
    setError('')
    try {
      await onSave({ groupId: groupId || null, title, username, password, url, notes, category, favorite: initial?.favorite || false, totp: totp || null })
    } catch (cause) {
      setError(errorMessage(cause))
      setSaving(false)
    }
  }
  return <div className="modal-backdrop"><form className="modal add-modal" onSubmit={submit}><button type="button" className="modal-close" onClick={onClose}><X size={20} /></button><span className="modal-icon">{initial ? <Pencil /> : <Plus />}</span><h2>{initial ? 'Edit item' : 'Add an item'}</h2><p>Changes are encrypted and atomically saved to your local KDBX file.</p>
    <label>NAME<input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="e.g. Acme workspace" autoFocus required /></label>
    <label>CATEGORY<select value={category} onChange={(event) => setCategory(event.target.value as EntryCategory)}>{['Login', 'Card', 'Identity', 'Secure note'].map((value) => <option key={value}>{value}</option>)}</select></label>
    <label>GROUP<select value={groupId} onChange={(event) => setGroupId(event.target.value)}>{groups.map((group) => <option value={group.id} key={group.id}>{group.name}</option>)}</select></label>
    <label>USERNAME<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" /></label>
    <label>PASSWORD<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /><span className="input-hint">{strength.label} · {strength.entropy} bits</span></label>
    <label>WEBSITE<input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" /></label>
    <label>NOTES<textarea value={notes} onChange={(event) => setNotes(event.target.value)} /></label>
    <label>TOTP SETUP KEY OR OTpauth URI<input type="password" value={totp} onChange={(event) => setTotp(event.target.value)} autoComplete="off" /></label>
    {error && <p className="form-error">{error}</p>}
    <button className="primary-button modal-save" disabled={saving}>{saving ? 'Saving…' : initial ? 'Save changes' : 'Encrypt and save'}</button>
  </form></div>
}

function PinDialPad({ value, onChange, disabled }: { value: string; onChange: (value: string) => void; disabled: boolean }) {
  const append = (digit: string) => {
    if (!disabled && value.length < 6) onChange(`${value}${digit}`)
  }
  return <div className="pin-dial-pad" aria-label="PIN keypad">
    {['1', '2', '3', '4', '5', '6', '7', '8', '9'].map((digit) => <button type="button" key={digit} disabled={disabled} onClick={() => append(digit)}>{digit}</button>)}
    <button type="button" className="pin-clear" disabled={disabled || !value} onClick={() => onChange('')}>Clear</button>
    <button type="button" disabled={disabled} onClick={() => append('0')}>0</button>
    <button type="button" className="pin-backspace" aria-label="Delete last PIN digit" disabled={disabled || !value} onClick={() => onChange(value.slice(0, -1))}>⌫</button>
  </div>
}

function VaultGate({ mode, status, onOpen }: { mode: 'loading' | 'create' | 'unlock' | 'desktop'; status: VaultStatus | null; onOpen: () => Promise<void> }) {
  const [path, setPath] = useState(status?.path || '')
  const [creating, setCreating] = useState(mode === 'create')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [pin, setPin] = useState('')
  const [pinStatus, setPinStatus] = useState(status?.pinUnlock)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    if (status?.path) setPath(status.path)
  }, [status?.path])
  useEffect(() => {
    setPinStatus(status?.pinUnlock)
  }, [status?.pinUnlock])
  useEffect(() => {
    setCreating(mode === 'create')
  }, [mode])
  if (mode === 'loading') return <div className="lock-screen"><div className="lock-card"><div className="brand-mark large-mark"><ShieldCheck size={28} /></div><h1>Opening Ciphera</h1><p>Locating your encrypted local vault…</p></div></div>
  if (mode === 'desktop') return <div className="lock-screen"><div className="lock-card"><div className="brand-mark large-mark"><ShieldCheck size={28} /></div><h1>Desktop app required</h1><p>Vault keys remain in the native Ciphera process. Run <code>npm run desktop</code> to use your vault.</p></div></div>
  const create = creating
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (create && password !== confirmPassword) {
      setError('Master passwords do not match')
      return
    }
    setWorking(true)
    setError('')
    try {
      await invoke(create ? 'create_vault' : 'unlock_vault', { path: path || null, password })
      setPassword('')
      setConfirmPassword('')
      await onOpen()
    } catch (cause) {
      setError(errorMessage(cause))
      setWorking(false)
    }
  }
  const unlockWithPin = async () => {
    setWorking(true)
    setError('')
    try {
      await invoke('pin_unlock_vault', { path: path || null, pin })
      setPin('')
      await onOpen()
    } catch (cause) {
      setError(errorMessage(cause))
      const next = await invoke<VaultStatus>('vault_status', { path: path || null }).catch(() => null)
      if (next) setPinStatus(next.pinUnlock)
      setWorking(false)
    }
  }
  const chooseVaultFile = async () => {
    const filters = [{ name: 'KeePass database', extensions: ['kdbx'] }]
    const chosen = create
      ? await save({ defaultPath: path || 'Ciphera Vault.kdbx', filters, title: 'Create encrypted vault' })
      : await open({ multiple: false, directory: false, filters, title: 'Open encrypted vault' })
    if (typeof chosen === 'string') {
      setPath(chosen)
      if (!create) {
        const next = await invoke<VaultStatus>('vault_status', { path: chosen }).catch(() => null)
        if (next) setPinStatus(next.pinUnlock)
      }
    }
  }
  return <div className="lock-screen"><form className="lock-card vault-gate" onSubmit={submit}><div className="brand-mark large-mark"><ShieldCheck size={28} /></div><h1>{create ? 'Create your vault' : 'Welcome back'}</h1><p>{create ? 'Choose a master password. Ciphera cannot recover it.' : 'Unlock your encrypted local KDBX vault.'}</p>
    <label>VAULT FILE<div className="path-picker"><input value={path} onChange={(event) => setPath(event.target.value)} placeholder="/path/to/vault.kdbx" /><button type="button" onClick={chooseVaultFile}><FolderOpen size={17} />Browse</button></div></label>
    {!create && pinStatus?.configured && !pinStatus.masterPasswordRequired && <div className="pin-unlock-panel"><label>QUICK-UNLOCK PIN<input type="password" inputMode="numeric" pattern="(?:[0-9]{4}|[0-9]{6})" value={pin} onChange={(event) => setPin(event.target.value.replace(/\D/g, '').slice(0, 6))} onKeyDown={(event) => { if (event.key === 'Enter' && (pin.length === 4 || pin.length === 6)) { event.preventDefault(); unlockWithPin() } }} autoFocus autoComplete="current-password" /></label><PinDialPad value={pin} onChange={setPin} disabled={working} /><button type="button" className="biometric-button" disabled={working || ![4, 6].includes(pin.length)} onClick={unlockWithPin}><Fingerprint size={22} />{working ? 'Working…' : 'Unlock with PIN'}</button><span>{pinStatus.attemptsRemaining} attempts remaining{pinStatus.retryAfterSeconds ? ` · wait ${pinStatus.retryAfterSeconds}s` : ''}</span><div className="gate-divider">or use your master password</div></div>}
    {!create && pinStatus?.masterPasswordRequired && <p className="pin-master-required"><AlertTriangle size={16} />Too many failed PIN attempts. Unlock once with your master password to re-enable the PIN.</p>}
    <label>MASTER PASSWORD<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoFocus={create || !pinStatus?.configured || pinStatus.masterPasswordRequired} autoComplete={create ? 'new-password' : 'current-password'} required /></label>
    {create && <label>CONFIRM PASSWORD<input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" required /></label>}
    {error && <p className="form-error">{error}</p>}
    <button className="biometric-button" disabled={working}><Lock size={22} />{working ? 'Working…' : create ? 'Create encrypted vault' : 'Unlock with master password'}</button>
    <button type="button" className="text-button" disabled={working} onClick={() => { setCreating((value) => !value); setError('') }}>{create ? 'Open an existing KDBX file' : 'Create a new vault instead'}</button>
    <span><Lock size={13} />Offline · KDBX 4.1 · Argon2id</span>
  </form></div>
}

export default App
