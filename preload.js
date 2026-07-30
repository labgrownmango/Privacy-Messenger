const { contextBridge, ipcRenderer } = require('electron')

const API_TOKEN = process.env.PM_API_TOKEN || ''
const API = 'http://127.0.0.1:49155'

const apiFetch = (path, opts = {}) => {
  const headers = { 'Content-Type': 'application/json', 'X-API-Token': API_TOKEN, ...(opts.headers || {}) }
  return fetch(`${API}${path}`, { ...opts, headers }).then(r => r.json())
}

// QR code generation (pure Node.js)
let _qr = null
try { _qr = require('qrcode') } catch (e) { console.warn('qrcode module not found:', e.message) }

contextBridge.exposeInMainWorld('electronAPI', {
  minimize:  () => ipcRenderer.send('window-minimize'),
  maximize:  () => ipcRenderer.send('window-maximize'),
  close:     () => ipcRenderer.send('window-close'),
  quit:      () => ipcRenderer.send('window-quit'),
  notify:    (title, body) => ipcRenderer.send('show-notification', { title, body }),
})

contextBridge.exposeInMainWorld('messenger', {
  // Identity
  getIdentity:    () => apiFetch('/identity'),
  createIdentity: (display_name) => apiFetch('/identity', { method: 'POST', body: JSON.stringify({ display_name }) }),
  updateName:     (display_name) => apiFetch('/identity/name', { method: 'PATCH', body: JSON.stringify({ display_name }) }),
  getFingerprint: () => apiFetch('/fingerprint'),
  exportIdentity: () => apiFetch('/export-identity'),

  // Contacts
  getContacts:   () => apiFetch('/contacts'),
  addContact:    (data) => apiFetch('/contacts', { method: 'POST', body: JSON.stringify(data) }),
  deleteContact: (id)  => apiFetch(`/contacts/${id}`, { method: 'DELETE' }),

  // Groups
  getGroups:         () => apiFetch('/groups'),
  createGroup:       (data) => apiFetch('/groups', { method: 'POST', body: JSON.stringify(data) }),
  addGroupMember:    (gid, data) => apiFetch(`/groups/${gid}/members`, { method: 'POST', body: JSON.stringify(data) }),
  removeGroupMember: (gid, uid) => apiFetch(`/groups/${gid}/members/${uid}`, { method: 'DELETE' }),
  exportGroupKey:    (gid) => apiFetch(`/groups/${gid}/export-key`),
  sendGroupMessage:  (gid, data) => apiFetch(`/groups/${gid}/send`, { method: 'POST', body: JSON.stringify(data) }),

  // Messages
  getMessages:       (cid, limit = 100) => apiFetch(`/messages/${cid}?limit=${limit}`),
  sendMessage:       (data) => apiFetch('/messages/send', { method: 'POST', body: JSON.stringify(data) }),
  receiveMessage:    (data) => apiFetch('/messages/receive', { method: 'POST', body: JSON.stringify(data) }),
  updateStatus:      (msg_id, status) => apiFetch('/messages/status', { method: 'PATCH', body: JSON.stringify({ msg_id, status }) }),
  deleteMessage:     (msg_id) => apiFetch(`/messages/single/${msg_id}`, { method: 'DELETE' }),
  editMessage:       (msg_id, content) => apiFetch(`/messages/single/${msg_id}`, { method: 'PATCH', body: JSON.stringify({ content }) }),
  clearConversation: (cid) => apiFetch(`/messages/${cid}`, { method: 'DELETE' }),
  setAutoDelete:     (cid, secs) => apiFetch('/messages/auto-delete', { method: 'POST', body: JSON.stringify({ conversation_id: cid, seconds: secs }) }),
  searchMessages:    (q) => apiFetch(`/messages/search?q=${encodeURIComponent(q)}`),

  // Reactions
  addReaction:    (msg_id, emoji) => apiFetch(`/messages/${msg_id}/react`, { method: 'POST', body: JSON.stringify({ emoji }) }),
  removeReaction: (msg_id) => apiFetch(`/messages/${msg_id}/react`, { method: 'DELETE' }),
  getReactions:   (msg_id) => apiFetch(`/messages/${msg_id}/reactions`),

  // Relay
  connectRelay: (urls) => apiFetch('/relay/connect', { method: 'POST', body: JSON.stringify({ urls }) }),
  relayStatus:  () => apiFetch('/relay/status'),

  // Ratchet
  getRatchetInfo: (cid) => apiFetch(`/sessions/${cid}/ratchet-info`),

  // Backup / Restore
  exportBackup: () => apiFetch('/backup/export'),
  importBackup: (data_b64) => apiFetch('/backup/import', { method: 'POST', body: JSON.stringify({ data: data_b64 }) }),

  // WebSocket with API Token Query Param
  connectWS: (onMessage) => {
    const ws = new WebSocket(`ws://127.0.0.1:49155/ws?token=${API_TOKEN}`)
    ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
    ws.onclose = () => setTimeout(() => window.messenger.connectWS(onMessage), 2000)
    return ws
  },

  // QR Code
  generateQR: async (text) => {
    if (_qr) {
      try {
        return await _qr.toDataURL(text, { width: 256, margin: 2, color: { dark: '#5865f0', light: '#12151f' } })
      } catch (e) { console.warn('QR gen failed:', e) }
    }
    return null
  },

  // File helpers
  readFileAsBase64: (file) => new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result.split(',')[1])
    reader.onerror = reject
    reader.readAsDataURL(file)
  }),

  compressImage: (file, maxWidth = 1280, quality = 0.82) => new Promise((resolve) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      const img = new Image()
      img.onload = () => {
        const canvas = document.createElement('canvas')
        let w = img.width, h = img.height
        if (w > maxWidth) { h = Math.round((h * maxWidth) / w); w = maxWidth }
        canvas.width = w; canvas.height = h
        const ctx = canvas.getContext('2d')
        ctx.drawImage(img, 0, 0, w, h)
        resolve(canvas.toDataURL('image/jpeg', quality).split(',')[1])
      }
      img.src = e.target.result
    }
    reader.readAsDataURL(file)
  })
})
