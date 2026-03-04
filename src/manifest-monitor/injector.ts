/**
 * Manifest Monitor Injector
 *
 * This module provides:
 * 1. A local HTTP server that receives permission data from the browser
 * 2. Auto-writes to manifest.json when permissions are collected/managed
 * 3. An injectable browser script with a slide-out developer UI
 */

import http from 'http'
import fs from 'fs-extra'
import path from 'path'
import chalk from 'chalk'

interface ProtocolPermission {
  protocolID: [number, string]
  counterparty: string
  description: string
}

interface BasketAccess {
  basket: string
  description: string
}

interface CertificateAccess {
  type: string
  certifier?: string
  description: string
}

interface GroupPermissions {
  protocolPermissions?: ProtocolPermission[]
  basketAccess?: BasketAccess[]
  certificateAccess?: CertificateAccess[]
  [key: string]: unknown
}

interface ManifestFile {
  [key: string]: unknown
  babbage?: {
    [key: string]: unknown
    groupPermissions?: GroupPermissions
  }
}

interface PactProtocolGroup {
  key: string
  protocolID: [number, string]
  description: string
  enabled: boolean
  counterparties: Set<string>
}

interface CollectorState {
  protocolPermissions: ProtocolPermission[]
  basketAccess: BasketAccess[]
  certificateAccess: CertificateAccess[]
  pactGroups: Map<string, PactProtocolGroup>
  groupPermissionExtras: Record<string, unknown>
  manifestBase: ManifestFile | null
}

type CollectPayload = {
  type: 'protocol' | 'basket' | 'certificate'
  permission: unknown
}

type RemovePayload = {
  type: 'protocol' | 'basket' | 'certificate' | 'pact'
  key: string
}

type TogglePactPayload = {
  key: string
  enabled: boolean
}

/**
 * Default descriptions for common protocols.
 */
const PROTOCOL_DESCRIPTIONS: Record<string, string> = {
  'auth message signature': 'Needs permission for secure communication with server services.',
  'server hmac': 'Needs permission for nonce generation and HMAC creation.',
  messagebox: 'Needs permission for message delivery and communication.',
  '3241645161d8': 'Needs permission for peer-to-peer payments.',
  'identity key retrieval': 'Needs permission for identity key retrieval.',
  'certificate list': 'Needs permission for certificate registry access.',
  contact: 'Needs permission for contact management and encryption.',
  'wallet settings': 'Needs permission for wallet settings access.',
  PushDrop: 'Needs permission for token-related operations.'
}

const PERMISSION_MONITOR_OVERLAY_CSS = `
#lars-permission-monitor-root {
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 2147483000;
  font-family: "IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif;
  color: #101828;
  pointer-events: none;
}

.lars-permission-monitor-toggle {
  pointer-events: auto;
  border: 0;
  border-radius: 999px;
  background: linear-gradient(135deg, #0f766e, #0ea5a3);
  color: #ffffff;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.02em;
  padding: 11px 14px;
  cursor: pointer;
  box-shadow: 0 12px 28px rgba(15, 118, 110, 0.28);
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-left: auto;
}

.lars-permission-monitor-badge {
  background: rgba(255, 255, 255, 0.24);
  border-radius: 999px;
  font-size: 11px;
  line-height: 1;
  padding: 4px 6px;
  min-width: 22px;
  text-align: center;
}

.lars-permission-monitor-panel {
  pointer-events: auto;
  width: min(460px, calc(100vw - 24px));
  max-height: min(78vh, 760px);
  margin-top: 12px;
  border-radius: 14px;
  background: #ffffff;
  border: 1px solid #d0d5dd;
  box-shadow: 0 20px 60px rgba(16, 24, 40, 0.25);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  transform: translateX(112%);
  opacity: 0;
  transition: transform 180ms ease, opacity 180ms ease;
}

.lars-permission-monitor-panel.open {
  transform: translateX(0);
  opacity: 1;
}

.lars-permission-monitor-header {
  background: linear-gradient(135deg, #ecfdf3, #d1fae5);
  padding: 12px 14px;
  border-bottom: 1px solid #d0d5dd;
  display: grid;
  gap: 8px;
}

.lars-permission-monitor-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.lars-permission-monitor-title {
  font-size: 13px;
  font-weight: 800;
  color: #065f46;
  margin: 0;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.lars-permission-monitor-status {
  font-size: 11px;
  font-weight: 700;
  border-radius: 999px;
  padding: 3px 8px;
  background: #dcfce7;
  color: #166534;
}

.lars-permission-monitor-status.offline {
  background: #fee2e2;
  color: #991b1b;
}

.lars-permission-monitor-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 6px;
}

.lars-permission-monitor-summary-item {
  background: rgba(255, 255, 255, 0.85);
  border: 1px solid #d0d5dd;
  border-radius: 8px;
  padding: 6px;
  text-align: center;
}

.lars-permission-monitor-summary-value {
  margin: 0;
  font-size: 14px;
  font-weight: 800;
  color: #0f172a;
}

.lars-permission-monitor-summary-label {
  margin: 0;
  font-size: 10px;
  color: #475467;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.lars-permission-monitor-breakdown {
  margin: 0;
  font-size: 11px;
  font-weight: 600;
  color: #065f46;
}

.lars-permission-monitor-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.lars-permission-monitor-action-button {
  border: 1px solid #d0d5dd;
  border-radius: 8px;
  background: #ffffff;
  color: #344054;
  font-size: 11px;
  font-weight: 700;
  padding: 6px 10px;
  cursor: pointer;
}

.lars-permission-monitor-action-button:hover {
  border-color: #98a2b3;
  background: #f9fafb;
}

.lars-permission-monitor-content {
  overflow: auto;
  padding: 12px;
  display: grid;
  gap: 12px;
  background: radial-gradient(circle at top right, rgba(15, 118, 110, 0.04), transparent 35%), #ffffff;
}

.lars-permission-monitor-section {
  border: 1px solid #eaecf0;
  border-radius: 10px;
  overflow: hidden;
  background: #ffffff;
}

.lars-permission-monitor-section-title {
  margin: 0;
  padding: 9px 10px;
  font-size: 12px;
  font-weight: 800;
  background: #f9fafb;
  border-bottom: 1px solid #eaecf0;
  color: #1d2939;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.lars-permission-monitor-list {
  display: grid;
  gap: 0;
}

.lars-permission-monitor-empty {
  padding: 10px;
  font-size: 12px;
  color: #667085;
  font-style: italic;
}

.lars-permission-monitor-item {
  padding: 10px;
  border-top: 1px solid #f2f4f7;
  display: grid;
  gap: 6px;
}

.lars-permission-monitor-item:first-child {
  border-top: none;
}

.lars-permission-monitor-item-main {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.lars-permission-monitor-item-title {
  margin: 0;
  font-size: 12px;
  font-weight: 700;
  color: #101828;
  word-break: break-word;
}

.lars-permission-monitor-item-meta {
  margin: 0;
  font-size: 11px;
  color: #475467;
  word-break: break-word;
}

.lars-permission-monitor-item-desc {
  margin: 0;
  font-size: 11px;
  color: #344054;
  word-break: break-word;
}

.lars-permission-monitor-remove {
  border: 1px solid #fecaca;
  background: #fef2f2;
  color: #b42318;
  border-radius: 6px;
  padding: 3px 7px;
  font-size: 10px;
  font-weight: 700;
  cursor: pointer;
  flex-shrink: 0;
}

.lars-permission-monitor-remove:hover {
  background: #fee4e2;
}

.lars-permission-monitor-pact-toggle {
  width: 16px;
  height: 16px;
  cursor: pointer;
}

.lars-permission-monitor-counterparties {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.lars-permission-monitor-chip {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 999px;
  border: 1px solid #d0d5dd;
  background: #f9fafb;
  font-size: 10px;
  color: #344054;
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 640px) {
  #lars-permission-monitor-root {
    right: 8px;
    left: 8px;
    bottom: 8px;
  }

  .lars-permission-monitor-panel {
    width: 100%;
    max-height: 76vh;
  }

  .lars-permission-monitor-summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
`

let collectorServer: http.Server | null = null
let manifestPath = ''
let appName = 'MyApp'

const state: CollectorState = {
  protocolPermissions: [],
  basketAccess: [],
  certificateAccess: [],
  pactGroups: new Map(),
  groupPermissionExtras: {},
  manifestBase: null
}

const seen = {
  protocol: new Set<string>(),
  basket: new Set<string>(),
  cert: new Set<string>()
}

function getProtocolKey(protocolID: [number, string]): string {
  return `${protocolID[0]}:${protocolID[1]}`
}

function getProtocolPermissionKey(permission: ProtocolPermission): string {
  return `${permission.protocolID[0]}:${permission.protocolID[1]}:${permission.counterparty}`
}

function getCertificateKey(permission: CertificateAccess): string {
  return `${permission.type}:${permission.certifier || ''}`
}

function getProtocolDescription(protocolID: [number, string], fallbackMethod?: string): string {
  const protocolName = protocolID[1]
  return PROTOCOL_DESCRIPTIONS[protocolName] || (fallbackMethod ? `${fallbackMethod} using "${protocolName}"` : `Permission for protocol "${protocolName}"`)
}

function getPactDescription(protocolID: [number, string]): string {
  const protocolName = protocolID[1]
  const defaultDescription = PROTOCOL_DESCRIPTIONS[protocolName]
  if (defaultDescription) {
    return defaultDescription
  }
  return `PACT grouped permission for protocol "${protocolName}".`
}

function cloneManifest(manifest: ManifestFile): ManifestFile {
  return JSON.parse(JSON.stringify(manifest)) as ManifestFile
}

function normalizeProtocolPermission(permission: unknown): ProtocolPermission | null {
  if (!permission || typeof permission !== 'object') {
    return null
  }
  const record = permission as Record<string, unknown>
  const protocolID = record.protocolID as unknown
  const counterparty = record.counterparty
  const description = record.description

  if (!Array.isArray(protocolID) || protocolID.length !== 2) {
    return null
  }

  const securityLevel = Number(protocolID[0])
  const protocolName = String(protocolID[1])
  if (!Number.isFinite(securityLevel) || !protocolName) {
    return null
  }

  const normalizedProtocolID: [number, string] = [securityLevel, protocolName]
  let normalizedCounterparty = 'self'
  if (Object.prototype.hasOwnProperty.call(record, 'counterparty')) {
    normalizedCounterparty = String(counterparty ?? '')
  }

  return {
    protocolID: normalizedProtocolID,
    counterparty: normalizedCounterparty,
    description: typeof description === 'string'
      ? description
      : getProtocolDescription(normalizedProtocolID)
  }
}

function normalizeBasketAccess(permission: unknown): BasketAccess | null {
  if (!permission || typeof permission !== 'object') {
    return null
  }
  const record = permission as Record<string, unknown>
  if (typeof record.basket !== 'string' || record.basket.length === 0) {
    return null
  }
  return {
    basket: record.basket,
    description: typeof record.description === 'string'
      ? record.description
      : `Access to "${record.basket}" basket`
  }
}

function normalizeCertificateAccess(permission: unknown): CertificateAccess | null {
  if (!permission || typeof permission !== 'object') {
    return null
  }
  const record = permission as Record<string, unknown>
  if (typeof record.type !== 'string' || record.type.length === 0) {
    return null
  }
  const certifier = typeof record.certifier === 'string' ? record.certifier : undefined
  return {
    type: record.type,
    certifier,
    description: typeof record.description === 'string'
      ? record.description
      : `Certificate permission for type "${record.type}"`
  }
}

function ensurePactGroup(options: {
  protocolID: [number, string]
  description?: string
  enabled?: boolean
  counterparty?: string
}): PactProtocolGroup {
  const key = getProtocolKey(options.protocolID)
  let group = state.pactGroups.get(key)

  if (!group) {
    group = {
      key,
      protocolID: options.protocolID,
      description: options.description || getPactDescription(options.protocolID),
      enabled: options.enabled ?? true,
      counterparties: new Set<string>()
    }
    state.pactGroups.set(key, group)
  }

  if (typeof options.description === 'string' && options.description.trim().length > 0) {
    group.description = options.description
  }

  if (typeof options.enabled === 'boolean') {
    group.enabled = options.enabled
  }

  if (options.counterparty && options.counterparty.trim().length > 0) {
    group.counterparties.add(options.counterparty)
  }

  return group
}

function addProtocolPermission(permission: ProtocolPermission, options: {
  autoCreatePactGroup: boolean
  log: boolean
}): boolean {
  // Empty counterparty represents PACT grouped permission
  if (permission.counterparty === '') {
    const existingGroup = state.pactGroups.get(getProtocolKey(permission.protocolID))
    const group = ensurePactGroup({
      protocolID: permission.protocolID,
      description: permission.description,
      enabled: true
    })
    const changed =
      !existingGroup ||
      !existingGroup.enabled ||
      (typeof permission.description === 'string' &&
        permission.description.trim().length > 0 &&
        permission.description !== existingGroup.description)

    if (options.log && changed) {
      console.log(chalk.green(`  ✓ PACT Group: [${group.protocolID[0]}, "${group.protocolID[1]}"]`))
    }
    return changed
  }

  const key = getProtocolPermissionKey(permission)
  if (seen.protocol.has(key)) {
    return false
  }

  seen.protocol.add(key)
  state.protocolPermissions.push(permission)

  if (options.autoCreatePactGroup) {
    ensurePactGroup({
      protocolID: permission.protocolID,
      counterparty: permission.counterparty,
      enabled: true
    })
  }

  if (options.log) {
    console.log(chalk.green(`  ✓ Protocol: [${permission.protocolID[0]}, "${permission.protocolID[1]}"] → ${permission.counterparty}`))
  }

  return true
}

function addBasketAccess(permission: BasketAccess, log: boolean): boolean {
  if (seen.basket.has(permission.basket)) {
    return false
  }
  seen.basket.add(permission.basket)
  state.basketAccess.push(permission)

  if (log) {
    console.log(chalk.green(`  ✓ Basket: "${permission.basket}"`))
  }

  return true
}

function addCertificateAccess(permission: CertificateAccess, log: boolean): boolean {
  const key = getCertificateKey(permission)
  if (seen.cert.has(key)) {
    return false
  }

  seen.cert.add(key)
  state.certificateAccess.push(permission)

  if (log) {
    console.log(chalk.green(`  ✓ Certificate: "${permission.type}"`))
  }

  return true
}

function removeProtocolPermissionByKey(key: string): boolean {
  const index = state.protocolPermissions.findIndex(permission => getProtocolPermissionKey(permission) === key)
  if (index === -1) {
    return false
  }

  const [removed] = state.protocolPermissions.splice(index, 1)
  seen.protocol.delete(key)

  const protocolKey = getProtocolKey(removed.protocolID)
  const group = state.pactGroups.get(protocolKey)
  if (group) {
    group.counterparties.delete(removed.counterparty)
  }

  return true
}

function removeBasketByKey(key: string): boolean {
  const index = state.basketAccess.findIndex(permission => permission.basket === key)
  if (index === -1) {
    return false
  }

  const [removed] = state.basketAccess.splice(index, 1)
  seen.basket.delete(removed.basket)
  return true
}

function removeCertificateByKey(key: string): boolean {
  const index = state.certificateAccess.findIndex(permission => getCertificateKey(permission) === key)
  if (index === -1) {
    return false
  }

  const [removed] = state.certificateAccess.splice(index, 1)
  seen.cert.delete(getCertificateKey(removed))
  return true
}

function removePactGroupByKey(key: string): boolean {
  const group = state.pactGroups.get(key)
  if (!group) {
    return false
  }
  group.enabled = false
  return true
}

function resetCollectorState(): void {
  state.protocolPermissions.length = 0
  state.basketAccess.length = 0
  state.certificateAccess.length = 0
  state.pactGroups.clear()
  state.groupPermissionExtras = {}
  state.manifestBase = null

  seen.protocol.clear()
  seen.basket.clear()
  seen.cert.clear()
}

function getDefaultManifest(): ManifestFile {
  return {
    short_name: appName,
    name: appName,
    icons: [
      {
        src: 'favicon.ico',
        sizes: '64x64 32x32 24x24 16x16',
        type: 'image/x-icon'
      }
    ],
    start_url: '.',
    display: 'standalone',
    theme_color: '#000000',
    background_color: '#ffffff',
    babbage: {
      groupPermissions: {
        protocolPermissions: [],
        basketAccess: []
      }
    }
  }
}

function loadExistingManifestIntoState(): void {
  let manifest: ManifestFile = getDefaultManifest()

  if (fs.existsSync(manifestPath)) {
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8')) as ManifestFile
    } catch {
      manifest = getDefaultManifest()
    }
  }

  state.manifestBase = cloneManifest(manifest)

  const groupPermissions = ((manifest.babbage as Record<string, unknown> | undefined)?.groupPermissions || {}) as GroupPermissions

  state.groupPermissionExtras = Object.fromEntries(
    Object.entries(groupPermissions).filter(([key]) => {
      return key !== 'protocolPermissions' && key !== 'basketAccess' && key !== 'certificateAccess'
    })
  )

  const protocolPermissions = Array.isArray(groupPermissions.protocolPermissions)
    ? groupPermissions.protocolPermissions
    : []

  for (const permission of protocolPermissions) {
    const normalized = normalizeProtocolPermission(permission)
    if (!normalized) {
      continue
    }

    if (normalized.counterparty === '') {
      ensurePactGroup({
        protocolID: normalized.protocolID,
        description: normalized.description,
        enabled: true
      })
      continue
    }

    addProtocolPermission(normalized, {
      autoCreatePactGroup: false,
      log: false
    })

    const existingGroup = state.pactGroups.get(getProtocolKey(normalized.protocolID))
    if (existingGroup) {
      existingGroup.counterparties.add(normalized.counterparty)
    }
  }

  const basketAccess = Array.isArray(groupPermissions.basketAccess)
    ? groupPermissions.basketAccess
    : []
  for (const permission of basketAccess) {
    const normalized = normalizeBasketAccess(permission)
    if (normalized) {
      addBasketAccess(normalized, false)
    }
  }

  const certificateAccess = Array.isArray(groupPermissions.certificateAccess)
    ? groupPermissions.certificateAccess
    : []
  for (const permission of certificateAccess) {
    const normalized = normalizeCertificateAccess(permission)
    if (normalized) {
      addCertificateAccess(normalized, false)
    }
  }
}

function getManifestProtocolPermissions(): ProtocolPermission[] {
  const pactPermissions = Array.from(state.pactGroups.values())
    .filter(group => group.enabled)
    .map(group => {
      return {
        protocolID: group.protocolID,
        counterparty: '',
        description: group.description || getPactDescription(group.protocolID)
      }
    })

  return [...state.protocolPermissions, ...pactPermissions]
}

function saveManifest(): void {
  const baseManifest = state.manifestBase ? cloneManifest(state.manifestBase) : getDefaultManifest()

  if (!baseManifest.babbage || typeof baseManifest.babbage !== 'object') {
    baseManifest.babbage = {}
  }

  const babbage = baseManifest.babbage as Record<string, unknown>
  const groupPermissions: GroupPermissions = {
    ...state.groupPermissionExtras,
    protocolPermissions: getManifestProtocolPermissions(),
    basketAccess: state.basketAccess
  }

  if (state.certificateAccess.length > 0) {
    groupPermissions.certificateAccess = state.certificateAccess
  }

  babbage.groupPermissions = groupPermissions

  fs.ensureDirSync(path.dirname(manifestPath))
  fs.writeFileSync(manifestPath, JSON.stringify(baseManifest, null, 2))

  state.manifestBase = cloneManifest(baseManifest)
}

function getStateResponse(): Record<string, unknown> {
  const pactGroups = Array.from(state.pactGroups.values()).map(group => {
    return {
      key: group.key,
      protocolID: group.protocolID,
      description: group.description,
      enabled: group.enabled,
      counterparties: Array.from(group.counterparties.values()),
      counterpartyCount: group.counterparties.size
    }
  })

  const manifestProtocolPermissions = getManifestProtocolPermissions()

  return {
    appName,
    manifestPath,
    protocolPermissions: state.protocolPermissions,
    basketAccess: state.basketAccess,
    certificateAccess: state.certificateAccess,
    pactGroups,
    manifestProtocolPermissions,
    summary: {
      directProtocolPermissions: state.protocolPermissions.length,
      pactProtocolPermissions: pactGroups.filter(group => group.enabled).length,
      protocolPermissionsInManifest: manifestProtocolPermissions.length,
      basketAccess: state.basketAccess.length,
      certificateAccess: state.certificateAccess.length
    },
    updatedAt: new Date().toISOString()
  }
}

function sendJson(res: http.ServerResponse, statusCode: number, body: unknown): void {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

function parseRequestBody<T>(req: http.IncomingMessage): Promise<T | null> {
  return new Promise(resolve => {
    let body = ''
    req.on('data', chunk => {
      body += chunk
    })
    req.on('end', () => {
      if (!body.trim()) {
        resolve(null)
        return
      }

      try {
        resolve(JSON.parse(body) as T)
      } catch {
        resolve(null)
      }
    })
  })
}

async function handleCollect(payload: CollectPayload): Promise<boolean> {
  if (payload.type === 'protocol') {
    const permission = normalizeProtocolPermission(payload.permission)
    if (!permission) {
      return false
    }

    return addProtocolPermission(permission, {
      autoCreatePactGroup: true,
      log: true
    })
  }

  if (payload.type === 'basket') {
    const permission = normalizeBasketAccess(payload.permission)
    if (!permission) {
      return false
    }

    return addBasketAccess(permission, true)
  }

  if (payload.type === 'certificate') {
    const permission = normalizeCertificateAccess(payload.permission)
    if (!permission) {
      return false
    }

    return addCertificateAccess(permission, true)
  }

  return false
}

function handleRemove(payload: RemovePayload): boolean {
  if (payload.type === 'protocol') {
    return removeProtocolPermissionByKey(payload.key)
  }

  if (payload.type === 'basket') {
    return removeBasketByKey(payload.key)
  }

  if (payload.type === 'certificate') {
    return removeCertificateByKey(payload.key)
  }

  if (payload.type === 'pact') {
    return removePactGroupByKey(payload.key)
  }

  return false
}

function handleTogglePact(payload: TogglePactPayload): boolean {
  const keyParts = payload.key.split(':')
  if (keyParts.length < 2) {
    return false
  }

  const securityLevel = Number(keyParts[0])
  const protocolName = keyParts.slice(1).join(':')
  if (!Number.isFinite(securityLevel) || !protocolName) {
    return false
  }

  const key = `${securityLevel}:${protocolName}`
  const existingGroup = state.pactGroups.get(key)
  if (existingGroup) {
    const previousValue = existingGroup.enabled
    existingGroup.enabled = payload.enabled
    return previousValue !== payload.enabled
  }

  ensurePactGroup({
    protocolID: [securityLevel, protocolName],
    enabled: payload.enabled
  })
  return payload.enabled
}

function handleClear(): void {
  let existingManifest: ManifestFile = getDefaultManifest()
  if (fs.existsSync(manifestPath)) {
    try {
      existingManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8')) as ManifestFile
    } catch {
      existingManifest = getDefaultManifest()
    }
  }

  const existingGroupPermissions = ((existingManifest.babbage as Record<string, unknown> | undefined)?.groupPermissions || {}) as GroupPermissions
  const extras = Object.fromEntries(
    Object.entries(existingGroupPermissions).filter(([key]) => {
      return key !== 'protocolPermissions' && key !== 'basketAccess' && key !== 'certificateAccess'
    })
  )

  resetCollectorState()
  state.manifestBase = existingManifest
  state.groupPermissionExtras = extras
}

/*******************************************************************************
 * Public API
 ******************************************************************************/

export function startCollectorServer(options: {
  port?: number
  outputPath: string
  name: string
}): Promise<void> {
  const port = options.port || 3399
  manifestPath = options.outputPath
  appName = options.name

  resetCollectorState()
  loadExistingManifestIntoState()
  saveManifest()

  return new Promise((resolve, reject) => {
    collectorServer = http.createServer(async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*')
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

      if (req.method === 'OPTIONS') {
        res.writeHead(204)
        res.end()
        return
      }

      if (req.method === 'GET' && req.url === '/state') {
        sendJson(res, 200, getStateResponse())
        return
      }

      if (req.method === 'POST' && req.url === '/collect') {
        const payload = await parseRequestBody<CollectPayload>(req)
        if (!payload) {
          sendJson(res, 400, { error: 'Invalid JSON' })
          return
        }

        const changed = await handleCollect(payload)
        if (changed) {
          saveManifest()
        }

        sendJson(res, 200, {
          ok: true,
          changed,
          state: getStateResponse()
        })
        return
      }

      if (req.method === 'POST' && req.url === '/remove') {
        const payload = await parseRequestBody<RemovePayload>(req)
        if (!payload || typeof payload.key !== 'string') {
          sendJson(res, 400, { error: 'Invalid JSON' })
          return
        }

        const changed = handleRemove(payload)
        if (changed) {
          saveManifest()
        }

        sendJson(res, 200, {
          ok: true,
          changed,
          state: getStateResponse()
        })
        return
      }

      if (req.method === 'POST' && req.url === '/toggle-pact') {
        const payload = await parseRequestBody<TogglePactPayload>(req)
        if (!payload || typeof payload.key !== 'string' || typeof payload.enabled !== 'boolean') {
          sendJson(res, 400, { error: 'Invalid JSON' })
          return
        }

        const changed = handleTogglePact(payload)
        if (changed) {
          saveManifest()
        }

        sendJson(res, 200, {
          ok: true,
          changed,
          state: getStateResponse()
        })
        return
      }

      if (req.method === 'POST' && req.url === '/clear') {
        handleClear()
        saveManifest()
        sendJson(res, 200, {
          ok: true,
          changed: true,
          state: getStateResponse()
        })
        return
      }

      sendJson(res, 404, { error: 'Not found' })
    })

    collectorServer.listen(port, () => {
      console.log(chalk.yellow('\n🔍 Permission Monitor Active'))
      console.log(chalk.gray(`   Collector server on http://localhost:${port}`))
      console.log(chalk.gray(`   Writing to: ${manifestPath}`))
      console.log(chalk.gray('   Overlay UI injected into your app (bottom-right toggle)\n'))
      resolve()
    })

    collectorServer.on('error', reject)
  })
}

export function stopCollectorServer(): void {
  if (!collectorServer) {
    return
  }

  collectorServer.close()
  collectorServer = null

  console.log(chalk.yellow('\n🛑 Permission Monitor stopped'))
  printSummary()
}

function printSummary(): void {
  const enabledPactCount = Array.from(state.pactGroups.values()).filter(group => group.enabled).length

  console.log(chalk.blue('\n📊 Permission Summary:'))
  console.log(chalk.gray(`   Direct protocol permissions: ${state.protocolPermissions.length}`))
  console.log(chalk.gray(`   PACT grouped permissions: ${enabledPactCount}`))
  console.log(chalk.gray(`   Basket access: ${state.basketAccess.length}`))
  console.log(chalk.gray(`   Certificate access: ${state.certificateAccess.length}`))
  console.log(chalk.blue(`\n📝 Manifest saved to: ${manifestPath}\n`))
}

/**
 * Get the browser injection script.
 *
 * The script:
 * - intercepts wallet fetch calls
 * - reports deduped permissions to the collector
 * - renders a bottom-right slide-out developer panel
 */
export function getInjectionScript(collectorPort: number = 3399): string {
  const overlayStyles = JSON.stringify(PERMISSION_MONITOR_OVERLAY_CSS)
  return `
<script>
(function () {
  if (window.__larsPermissionMonitorLoaded) {
    return;
  }
  window.__larsPermissionMonitorLoaded = true;

  const COLLECTOR_BASE = 'http://localhost:${collectorPort}';
  const ENDPOINTS = {
    collect: COLLECTOR_BASE + '/collect',
    state: COLLECTOR_BASE + '/state',
    remove: COLLECTOR_BASE + '/remove',
    togglePact: COLLECTOR_BASE + '/toggle-pact',
    clear: COLLECTOR_BASE + '/clear'
  };

  const protocolMethods = ['getPublicKey', 'encrypt', 'decrypt', 'createHmac', 'verifyHmac', 'createSignature', 'verifySignature', 'revealSpecificKeyLinkage'];
  const basketMethods = ['listOutputs', 'relinquishOutput'];
  const certMethods = ['listCertificates', 'acquireCertificate', 'proveCertificate', 'relinquishCertificate'];

  const protocolDescriptions = {
    'auth message signature': 'Needs permission for secure communication with server services.',
    'server hmac': 'Needs permission for nonce generation and HMAC creation.',
    'messagebox': 'Needs permission for message delivery and communication.',
    '3241645161d8': 'Needs permission for peer-to-peer payments.',
    'identity key retrieval': 'Needs permission for identity key retrieval.',
    'certificate list': 'Needs permission for certificate registry access.',
    'contact': 'Needs permission for contact management and encryption.',
    'wallet settings': 'Needs permission for wallet settings access.',
    'PushDrop': 'Needs permission for token-related operations.'
  };

  const localSeen = {
    protocol: new Set(),
    basket: new Set(),
    cert: new Set()
  };

  const monitorState = {
    appName: 'App',
    protocolPermissions: [],
    basketAccess: [],
    certificateAccess: [],
    pactGroups: [],
    summary: {
      directProtocolPermissions: 0,
      pactProtocolPermissions: 0,
      protocolPermissionsInManifest: 0,
      basketAccess: 0,
      certificateAccess: 0
    },
    online: true,
    updatedAt: null
  };

  const originalFetch = window.fetch.bind(window);

  function isValidProtocolPermission(permission) {
    return !!permission &&
      Array.isArray(permission.protocolID) &&
      permission.protocolID.length === 2 &&
      typeof permission.protocolID[1] === 'string';
  }

  function isValidBasketAccess(permission) {
    return !!permission &&
      typeof permission.basket === 'string' &&
      permission.basket.length > 0;
  }

  function isValidCertificateAccess(permission) {
    return !!permission &&
      typeof permission.type === 'string' &&
      permission.type.length > 0;
  }

  function isValidPactGroup(group) {
    return !!group &&
      Array.isArray(group.protocolID) &&
      group.protocolID.length === 2 &&
      typeof group.protocolID[1] === 'string' &&
      typeof group.key === 'string';
  }

  function protocolKey(protocolID) {
    return String(protocolID[0]) + ':' + String(protocolID[1]);
  }

  function protocolPermissionKey(permission) {
    return protocolKey(permission.protocolID) + ':' + String(permission.counterparty);
  }

  function certificateKey(permission) {
    return String(permission.type) + ':' + String(permission.certifier || '');
  }

  function getDescription(protocolName, method) {
    return protocolDescriptions[protocolName] || (method + ' using "' + protocolName + '"');
  }

  function parseBodyAsJson(body) {
    if (typeof body !== 'string' || body.length === 0) {
      return {};
    }
    try {
      return JSON.parse(body);
    } catch (_err) {
      return {};
    }
  }

  function getRequestUrl(input) {
    if (typeof input === 'string') {
      return input;
    }
    if (input && typeof input.url === 'string') {
      return input.url;
    }
    if (input && typeof input.href === 'string') {
      return input.href;
    }
    return '';
  }

  function isWalletRequest(url) {
    return url.includes('localhost:3321') || url.includes('127.0.0.1:3321');
  }

  async function postJson(url, body) {
    return originalFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  async function refreshState() {
    try {
      const response = await originalFetch(ENDPOINTS.state, { method: 'GET' });
      if (!response.ok) {
        throw new Error('State request failed');
      }

      const data = await response.json();
      monitorState.appName = data.appName || monitorState.appName;
      monitorState.protocolPermissions = Array.isArray(data.protocolPermissions)
        ? data.protocolPermissions.filter(isValidProtocolPermission)
        : [];
      monitorState.basketAccess = Array.isArray(data.basketAccess)
        ? data.basketAccess.filter(isValidBasketAccess)
        : [];
      monitorState.certificateAccess = Array.isArray(data.certificateAccess)
        ? data.certificateAccess.filter(isValidCertificateAccess)
        : [];
      monitorState.pactGroups = Array.isArray(data.pactGroups)
        ? data.pactGroups.filter(isValidPactGroup)
        : [];
      monitorState.summary = data.summary || monitorState.summary;
      monitorState.updatedAt = data.updatedAt || null;
      monitorState.online = true;
      render();
    } catch (_err) {
      monitorState.online = false;
      render();
    }
  }

  async function collectPermission(type, permission) {
    try {
      await postJson(ENDPOINTS.collect, { type, permission });
      await refreshState();
    } catch (_err) {
      monitorState.online = false;
      render();
    }
  }

  async function removePermission(type, key) {
    try {
      await postJson(ENDPOINTS.remove, { type, key });
      await refreshState();
    } catch (_err) {
      monitorState.online = false;
      render();
    }
  }

  async function togglePact(key, enabled) {
    try {
      await postJson(ENDPOINTS.togglePact, { key, enabled });
      await refreshState();
    } catch (_err) {
      monitorState.online = false;
      render();
    }
  }

  async function clearPermissions() {
    try {
      await postJson(ENDPOINTS.clear, {});
      localSeen.protocol.clear();
      localSeen.basket.clear();
      localSeen.cert.clear();
      await refreshState();
    } catch (_err) {
      monitorState.online = false;
      render();
    }
  }

  window.fetch = async function (input, init) {
    const url = getRequestUrl(input);

    if (isWalletRequest(url)) {
      let method = 'unknown';
      let args = {};

      try {
        const pathname = new URL(url).pathname;
        method = pathname.startsWith('/') ? pathname.slice(1) : pathname;
        method = method || 'unknown';
      } catch (_err) {
        method = 'unknown';
      }

      args = parseBodyAsJson(init && init.body);

      if (protocolMethods.includes(method) && Array.isArray(args.protocolID) && args.protocolID.length === 2) {
        const protocolID = [Number(args.protocolID[0]), String(args.protocolID[1])];
        const hasCounterparty = Object.prototype.hasOwnProperty.call(args, 'counterparty');
        const counterparty = hasCounterparty ? String(args.counterparty ?? '') : 'self';

        const protocolPermission = {
          protocolID,
          counterparty,
          description: getDescription(protocolID[1], method)
        };

        const key = protocolPermissionKey(protocolPermission);
        if (!localSeen.protocol.has(key)) {
          localSeen.protocol.add(key);
          void collectPermission('protocol', protocolPermission);
          console.log('%c✓ Protocol: [' + protocolID[0] + ', "' + protocolID[1] + '"] → ' + counterparty, 'color: #22c55e');
        }
      }

      if (basketMethods.includes(method) && typeof args.basket === 'string' && args.basket.length > 0) {
        const basketPermission = {
          basket: args.basket,
          description: 'Access to "' + args.basket + '" basket'
        };
        if (!localSeen.basket.has(basketPermission.basket)) {
          localSeen.basket.add(basketPermission.basket);
          void collectPermission('basket', basketPermission);
          console.log('%c✓ Basket: "' + basketPermission.basket + '"', 'color: #22c55e');
        }
      }

      if (certMethods.includes(method)) {
        const certType = typeof args.type === 'string'
          ? args.type
          : (Array.isArray(args.types) && typeof args.types[0] === 'string' ? args.types[0] : '');

        if (certType) {
          const certPermission = {
            type: certType,
            certifier: typeof args.certifier === 'string' ? args.certifier : undefined,
            description: method + ' for certificate type "' + certType + '"'
          };

          const certPermissionKey = certificateKey(certPermission);
          if (!localSeen.cert.has(certPermissionKey)) {
            localSeen.cert.add(certPermissionKey);
            void collectPermission('certificate', certPermission);
            console.log('%c✓ Certificate: "' + certType + '"', 'color: #22c55e');
          }
        }
      }
    }

    return originalFetch(input, init);
  };

  const style = document.createElement('style');
  style.id = 'lars-permission-monitor-style';
  style.textContent = ${overlayStyles};
  document.head.appendChild(style);

  let root = null;
  let panel = null;
  let toggleButton = null;
  let statusBadge = null;
  let summaryContainer = null;
  let breakdownElement = null;
  let sectionsContainer = null;

  function createElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    if (typeof text === 'string') {
      element.textContent = text;
    }
    return element;
  }

  function mountUi() {
    if (!document.body) {
      window.setTimeout(mountUi, 25);
      return;
    }

    root = createElement('div', null, null);
    root.id = 'lars-permission-monitor-root';

    toggleButton = createElement('button', 'lars-permission-monitor-toggle', null);
    toggleButton.type = 'button';
    toggleButton.innerHTML = '<span>Manifest Monitor</span><span class="lars-permission-monitor-badge" data-role="toggle-badge">0</span>';

    panel = createElement('section', 'lars-permission-monitor-panel', null);

    const header = createElement('div', 'lars-permission-monitor-header', null);
    const headerRow = createElement('div', 'lars-permission-monitor-header-row', null);
    const title = createElement('p', 'lars-permission-monitor-title', 'Permission Monitor');
    statusBadge = createElement('span', 'lars-permission-monitor-status', 'ONLINE');
    headerRow.appendChild(title);
    headerRow.appendChild(statusBadge);

    summaryContainer = createElement('div', 'lars-permission-monitor-summary', null);
    breakdownElement = createElement('p', 'lars-permission-monitor-breakdown', '');

    const actions = createElement('div', 'lars-permission-monitor-actions', null);
    const leftActions = createElement('div', null, null);
    const clearButton = createElement('button', 'lars-permission-monitor-action-button', 'Clear');
    clearButton.type = 'button';
    clearButton.addEventListener('click', function () {
      void clearPermissions();
    });
    leftActions.appendChild(clearButton);

    const rightActions = createElement('div', null, null);
    const refreshButton = createElement('button', 'lars-permission-monitor-action-button', 'Refresh');
    refreshButton.type = 'button';
    refreshButton.addEventListener('click', function () {
      void refreshState();
    });

    const closeButton = createElement('button', 'lars-permission-monitor-action-button', 'Close');
    closeButton.type = 'button';
    closeButton.addEventListener('click', function () {
      panel.classList.remove('open');
    });

    rightActions.appendChild(refreshButton);
    rightActions.appendChild(closeButton);
    actions.appendChild(leftActions);
    actions.appendChild(rightActions);

    header.appendChild(headerRow);
    header.appendChild(summaryContainer);
    header.appendChild(breakdownElement);
    header.appendChild(actions);

    sectionsContainer = createElement('div', 'lars-permission-monitor-content', null);

    panel.appendChild(header);
    panel.appendChild(sectionsContainer);

    toggleButton.addEventListener('click', function () {
      panel.classList.toggle('open');
    });

    root.appendChild(toggleButton);
    root.appendChild(panel);
    document.body.appendChild(root);

    render();
  }

  function createSummaryItem(label, value) {
    const item = createElement('div', 'lars-permission-monitor-summary-item', null);
    const valueElement = createElement('p', 'lars-permission-monitor-summary-value', String(value));
    const labelElement = createElement('p', 'lars-permission-monitor-summary-label', label);
    item.appendChild(valueElement);
    item.appendChild(labelElement);
    return item;
  }

  function createSection(title, count, items) {
    const section = createElement('div', 'lars-permission-monitor-section', null);
    const titleElement = createElement('p', 'lars-permission-monitor-section-title', null);

    const titleLeft = createElement('span', null, title);
    const titleRight = createElement('span', null, String(count));
    titleElement.appendChild(titleLeft);
    titleElement.appendChild(titleRight);

    const list = createElement('div', 'lars-permission-monitor-list', null);

    if (items.length === 0) {
      list.appendChild(createElement('div', 'lars-permission-monitor-empty', 'No permissions intercepted yet.'));
    } else {
      for (const item of items) {
        list.appendChild(item);
      }
    }

    section.appendChild(titleElement);
    section.appendChild(list);
    return section;
  }

  function renderProtocolItems() {
    return monitorState.protocolPermissions.map(function (permission) {
      const row = createElement('div', 'lars-permission-monitor-item', null);
      const main = createElement('div', 'lars-permission-monitor-item-main', null);

      const title = createElement('p', 'lars-permission-monitor-item-title', '[' + permission.protocolID[0] + ', "' + permission.protocolID[1] + '"]');
      const removeButton = createElement('button', 'lars-permission-monitor-remove', 'Remove');
      removeButton.type = 'button';
      removeButton.addEventListener('click', function () {
        void removePermission('protocol', protocolPermissionKey(permission));
      });

      main.appendChild(title);
      main.appendChild(removeButton);

      const meta = createElement('p', 'lars-permission-monitor-item-meta', 'Counterparty: ' + (permission.counterparty || '(PACT)'));
      const desc = createElement('p', 'lars-permission-monitor-item-desc', permission.description || '');

      row.appendChild(main);
      row.appendChild(meta);
      row.appendChild(desc);
      return row;
    });
  }

  function renderPactItems() {
    return monitorState.pactGroups.map(function (group) {
      const row = createElement('div', 'lars-permission-monitor-item', null);
      const main = createElement('div', 'lars-permission-monitor-item-main', null);
      const title = createElement('p', 'lars-permission-monitor-item-title', '[' + group.protocolID[0] + ', "' + group.protocolID[1] + '"] (counterparty: "")');

      const toggle = createElement('input', 'lars-permission-monitor-pact-toggle', null);
      toggle.type = 'checkbox';
      toggle.checked = !!group.enabled;
      toggle.addEventListener('change', function () {
        void togglePact(group.key, !!toggle.checked);
      });

      main.appendChild(title);
      main.appendChild(toggle);

      const meta = createElement('p', 'lars-permission-monitor-item-meta', 'PACT group covers ' + group.counterpartyCount + ' specific counterpart' + (group.counterpartyCount === 1 ? 'y' : 'ies') + '.');
      const desc = createElement('p', 'lars-permission-monitor-item-desc', group.description || '');

      row.appendChild(main);
      row.appendChild(meta);
      row.appendChild(desc);

      if (Array.isArray(group.counterparties) && group.counterparties.length > 0) {
        const chipContainer = createElement('div', 'lars-permission-monitor-counterparties', null);
        for (const counterparty of group.counterparties.slice(0, 6)) {
          chipContainer.appendChild(createElement('span', 'lars-permission-monitor-chip', counterparty));
        }
        if (group.counterparties.length > 6) {
          chipContainer.appendChild(createElement('span', 'lars-permission-monitor-chip', '+' + (group.counterparties.length - 6) + ' more'));
        }
        row.appendChild(chipContainer);
      }

      return row;
    });
  }

  function renderBasketItems() {
    return monitorState.basketAccess.map(function (permission) {
      const row = createElement('div', 'lars-permission-monitor-item', null);
      const main = createElement('div', 'lars-permission-monitor-item-main', null);
      const title = createElement('p', 'lars-permission-monitor-item-title', permission.basket);

      const removeButton = createElement('button', 'lars-permission-monitor-remove', 'Remove');
      removeButton.type = 'button';
      removeButton.addEventListener('click', function () {
        void removePermission('basket', permission.basket);
      });

      main.appendChild(title);
      main.appendChild(removeButton);
      row.appendChild(main);
      row.appendChild(createElement('p', 'lars-permission-monitor-item-desc', permission.description || ''));
      return row;
    });
  }

  function renderCertificateItems() {
    return monitorState.certificateAccess.map(function (permission) {
      const row = createElement('div', 'lars-permission-monitor-item', null);
      const main = createElement('div', 'lars-permission-monitor-item-main', null);
      const title = createElement('p', 'lars-permission-monitor-item-title', permission.type);

      const removeButton = createElement('button', 'lars-permission-monitor-remove', 'Remove');
      removeButton.type = 'button';
      removeButton.addEventListener('click', function () {
        void removePermission('certificate', certificateKey(permission));
      });

      main.appendChild(title);
      main.appendChild(removeButton);

      const meta = permission.certifier
        ? createElement('p', 'lars-permission-monitor-item-meta', 'Certifier: ' + permission.certifier)
        : null;

      row.appendChild(main);
      if (meta) {
        row.appendChild(meta);
      }
      row.appendChild(createElement('p', 'lars-permission-monitor-item-desc', permission.description || ''));
      return row;
    });
  }

  function render() {
    if (!root || !panel || !toggleButton || !statusBadge || !summaryContainer || !breakdownElement || !sectionsContainer) {
      return;
    }

    const directProtocolCount = monitorState.protocolPermissions.length;
    const pactProtocolCount = monitorState.pactGroups.filter(group => !!group.enabled).length;
    const protocolCount = directProtocolCount + pactProtocolCount;
    const basketCount = monitorState.basketAccess.length;
    const certificateCount = monitorState.certificateAccess.length;
    const totalPermissions = protocolCount + basketCount + certificateCount;

    const badge = toggleButton.querySelector('[data-role="toggle-badge"]');
    if (badge) {
      badge.textContent = String(totalPermissions);
    }

    statusBadge.textContent = monitorState.online ? 'ONLINE' : 'OFFLINE';
    statusBadge.className = monitorState.online
      ? 'lars-permission-monitor-status'
      : 'lars-permission-monitor-status offline';

    summaryContainer.innerHTML = '';
    summaryContainer.appendChild(createSummaryItem('Protocols', protocolCount));
    summaryContainer.appendChild(createSummaryItem('PACT', pactProtocolCount));
    summaryContainer.appendChild(createSummaryItem('Baskets', basketCount));
    summaryContainer.appendChild(createSummaryItem('Certificates', certificateCount));
    breakdownElement.textContent = directProtocolCount + ' direct + ' + pactProtocolCount + ' PACT = ' + protocolCount + ' manifest protocols';

    sectionsContainer.innerHTML = '';
    const protocolItems = renderProtocolItems();
    const pactItems = renderPactItems();
    const basketItems = renderBasketItems();
    const certificateItems = renderCertificateItems();

    sectionsContainer.appendChild(createSection('Direct Protocol Permissions', protocolItems.length, protocolItems));
    sectionsContainer.appendChild(createSection('PACT Group Permissions (counterparty "")', pactItems.length, pactItems));
    sectionsContainer.appendChild(createSection('Basket Access', basketItems.length, basketItems));
    sectionsContainer.appendChild(createSection('Certificate Access', certificateItems.length, certificateItems));
  }

  mountUi();
  void refreshState();
  window.setInterval(function () {
    void refreshState();
  }, 2500);

  console.log('%c🔍 LARS Permission Monitor Active', 'color:#0f766e;font-weight:700');
})();
</script>
`
}
