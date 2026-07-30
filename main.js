const { app, BrowserWindow, ipcMain, shell, Tray, Menu, Notification, nativeImage } = require('electron')
const path = require('path')
const { spawn } = require('child_process')
const http = require('http')

let mainWindow
let tray
let backendProcess
let isQuitting = false

const BACKEND_PORT = 49155

// ─── Screen Security ─────────────────────────────────────────────────────────
// setContentProtection is macOS-only; on Windows we use a workaround via BrowserWindow options
const IS_WIN = process.platform === 'win32'

// ─── Backend ─────────────────────────────────────────────────────────────────
function startBackend() {
  const bundledExe = path.join(process.resourcesPath || __dirname, 'pm-backend.exe')
  const devExe     = path.join(__dirname, 'backend-dist', 'pm-backend.exe')
  const pyScript   = path.join(__dirname, 'backend', 'server.py')

  let usePython = true
  let cmd = 'python'
  let args = [pyScript]
  let opts = { stdio: ['ignore', 'pipe', 'pipe'] }

  if (require('fs').existsSync(bundledExe)) {
    cmd = bundledExe
    args = []
    usePython = false
    console.log('[Backend] Attempting bundled exe:', bundledExe)
  } else if (require('fs').existsSync(devExe)) {
    cmd = devExe
    args = []
    usePython = false
    console.log('[Backend] Attempting dev exe:', devExe)
  } else {
    console.log('[Backend] No exe found, using python script:', pyScript)
  }

  const run = (executable, runArgs) => {
    console.log(`[Backend] Spawning: ${executable} ${runArgs.join(' ')}`)
    backendProcess = spawn(executable, runArgs, opts)
    
    backendProcess.on('error', (err) => {
      console.error('[Backend] Process spawn error:', err)
      if (!usePython) {
        console.log('[Backend] EXE execution blocked/failed. Falling back to system python...')
        usePython = true
        run('python', [pyScript])
      }
    })

    backendProcess.stdout?.on('data', d => console.log('[Backend]', d.toString().trim()))
    backendProcess.stderr?.on('data', d => console.error('[Backend]', d.toString().trim()))
    
    backendProcess.on('exit', (code) => {
      console.log(`[Backend] exited with code: ${code}`)
      if (code !== 0 && code !== null && !usePython) {
        console.log('[Backend] EXE exited unexpectedly. Falling back to system python...')
        usePython = true
        run('python', [pyScript])
      }
    })
  }

  run(cmd, args)
}


function waitForBackend(retries = 30) {
  return new Promise((resolve, reject) => {
    const check = (n) => {
      http.get(`http://127.0.0.1:${BACKEND_PORT}/identity`, () => resolve())
        .on('error', () => {
          if (n <= 0) return reject(new Error('Backend did not start'))
          setTimeout(() => check(n - 1), 500)
        })
    }
    check(retries)
  })
}

// ─── Tray ─────────────────────────────────────────────────────────────────────
function createTray() {
  let icon
  try {
    const iconPath = path.join(__dirname, 'assets', 'icon.png')
    if (require('fs').existsSync(iconPath)) {
      icon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 })
    } else {
      // Fallback: Valid 16x16 PNG base64 (a simple gray square icon)
      const pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAMklEQVR42mNgGAWjYBSMglEwCkbBSAcMYGJiYPn/n4GBAc6HieECmJiQxDFlgGgAAAr4CD4qv17lAAAAAElFTkSuQmCC'
      icon = nativeImage.createFromBuffer(Buffer.from(pngBase64, 'base64'))
    }
    
    tray = new Tray(icon)
    tray.setToolTip('Privacy Messenger 🔐')

    const menu = Menu.buildFromTemplate([
      { label: 'Privacy Messenger', enabled: false },
      { type: 'separator' },
      { label: '🔓 Öffnen', click: () => { mainWindow.show(); mainWindow.focus() } },
      { type: 'separator' },
      { label: '🚪 Beenden', click: () => { isQuitting = true; app.quit() } }
    ])
    tray.setContextMenu(menu)

    tray.on('double-click', () => {
      mainWindow.show()
      mainWindow.focus()
    })
  } catch (err) {
    console.error('Failed to create tray icon:', err)
    tray = null // Ensure it is null so window close falls back to normal exit
  }
}

// ─── Notifications ────────────────────────────────────────────────────────────
function showNotification(title, body) {
  if (!Notification.isSupported()) return
  new Notification({
    title,
    body,
    silent: false,
    urgency: 'normal'
  }).show()
}

// ─── Window ───────────────────────────────────────────────────────────────────
async function createWindow() {
  startBackend()
  try { await waitForBackend() }
  catch (e) { console.error('Backend failed:', e) }

  mainWindow = new BrowserWindow({
    width: 1120,
    height: 740,
    minWidth: 820,
    minHeight: 580,
    frame: false,
    backgroundColor: '#0c0e14',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    show: false   // show after ready-to-show
  })

  mainWindow.once('ready-to-show', () => mainWindow.show())
  mainWindow.loadFile('index.html')

  // Minimize to tray instead of closing
  mainWindow.on('close', (e) => {
    if (!isQuitting && tray) {
      e.preventDefault()
      mainWindow.hide()
      tray.displayBalloon?.({
        title: 'Privacy Messenger läuft',
        content: 'App minimiert ins System-Tray. Doppelklick zum Öffnen.'
      })
    } else {
      isQuitting = true
      if (backendProcess) backendProcess.kill()
      app.quit()
    }
  })

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: 'deny' }
  })

  createTray()
}

app.whenReady().then(createWindow)

app.on('window-all-closed', () => {
  // Don't quit on macOS, and keep alive in tray on Windows
  if (process.platform !== 'darwin' && isQuitting) {
    if (backendProcess) backendProcess.kill()
    app.quit()
  }
})

app.on('before-quit', () => {
  isQuitting = true
  if (backendProcess) backendProcess.kill()
})

app.on('activate', () => {
  if (mainWindow) { mainWindow.show(); mainWindow.focus() }
})

// ─── IPC ─────────────────────────────────────────────────────────────────────
ipcMain.on('window-minimize', () => mainWindow.minimize())
ipcMain.on('window-maximize', () => mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize())
ipcMain.on('window-close',    () => { mainWindow.hide() })   // hide to tray
ipcMain.on('window-quit',     () => { isQuitting = true; app.quit() })

// Push notification from renderer
ipcMain.on('show-notification', (_, { title, body }) => showNotification(title, body))
