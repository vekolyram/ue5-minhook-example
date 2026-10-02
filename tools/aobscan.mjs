// Static AOB scanner for a PE image on disk.
//
// Runtime scans walk the RVA space; a file scan walks file offsets. Those are
// not the same numbers, so this resolves each hit through the section headers
// and reports the RVA you would actually pass to a hook.
//
//   node aobscan.mjs <binary> "<4C 8B DC ?? ...>"
import { readFileSync } from 'node:fs'

const [, , binPath, patternText] = process.argv
if (!binPath || !patternText) {
  console.error('usage: node aobscan.mjs <binary> "<AOB with ?? wildcards>"')
  process.exit(2)
}

/** Parse "4C 8B ?? DC" into an array of numbers, or null for a wildcard. */
function parsePattern(text) {
  return text
    .trim()
    .split(/\s+/)
    .map((tok) => (tok === '?' || tok === '??' ? null : Number.parseInt(tok, 16)))
    .map((b, i) => {
      if (b !== null && (Number.isNaN(b) || b < 0 || b > 255)) {
        throw new Error(`bad byte at index ${i}: ${text.split(/\s+/)[i]}`)
      }
      return b
    })
}

const pattern = parsePattern(patternText)

// Split the pattern at the first wildcard run so the scan can use indexOf on a
// fixed prefix (fast) and only verify the tail on candidates.
const firstWild = pattern.indexOf(null)
let prefix, tailOffset
if (firstWild === -1) {
  prefix = pattern
  tailOffset = pattern.length
} else {
  prefix = pattern.slice(0, firstWild)
  tailOffset = firstWild
}
const prefixBuf = Buffer.from(prefix)

const img = readFileSync(binPath)

// ---- PE headers -----------------------------------------------------------
if (img.readUInt16LE(0) !== 0x5a4d) throw new Error('not a PE (missing MZ)')
const eLfanew = img.readUInt32LE(0x3c)
if (img.readUInt32LE(eLfanew) !== 0x00004550) throw new Error('not a PE (missing PE\\0\\0)')
const machine = img.readUInt16LE(eLfanew + 4)
const numSections = img.readUInt16LE(eLfanew + 6)
const sizeOfOptional = img.readUInt16LE(eLfanew + 20)
const optBase = eLfanew + 24
const magic = img.readUInt16LE(optBase)
const imageBase = magic === 0x20b ? Number(img.readBigUInt64LE(optBase + 24)) : img.readUInt32LE(optBase + 28)
const secBase = optBase + sizeOfOptional

const sections = []
for (let i = 0; i < numSections; i++) {
  const o = secBase + i * 40
  sections.push({
    name: img.toString('ascii', o, o + 8).replace(/\0+$/, ''),
    virtualSize: img.readUInt32LE(o + 8),
    virtualAddress: img.readUInt32LE(o + 12),
    rawSize: img.readUInt32LE(o + 16),
    rawPointer: img.readUInt32LE(o + 20),
    characteristics: img.readUInt32LE(o + 36),
  })
}

const hex = (n, w = 8) => '0x' + n.toString(16).toUpperCase().padStart(w, '0')
console.log(`binary        ${binPath}`)
console.log(`size          ${img.length} bytes`)
console.log(`machine       ${machine === 0x8664 ? 'x64' : hex(machine, 4)}`)
console.log(`imageBase     ${hex(imageBase, 16)}`)
console.log(`sections      ${sections.map((s) => s.name).join(', ')}`)
console.log(`pattern       ${pattern.length} bytes, ${pattern.filter((b) => b === null).length} wildcards`)

// ---- scan -----------------------------------------------------------------
const hits = []
for (const s of sections) {
  // Only executable sections can hold a function prologue.
  const executable = (s.characteristics & 0x20000000) !== 0
  if (!executable || s.rawPointer === 0 || s.rawSize === 0) continue

  const start = s.rawPointer
  const end = s.rawPointer + s.rawSize
  let at = img.indexOf(prefixBuf, start)
  while (at !== -1 && at + pattern.length <= end && at < end) {
    let ok = true
    for (let i = tailOffset; i < pattern.length; i++) {
      const want = pattern[i]
      if (want !== null && img[at + i] !== want) {
        ok = false
        break
      }
    }
    if (ok) {
      hits.push({ section: s.name, fileOffset: at, rva: at - s.rawPointer + s.virtualAddress })
    }
    at = img.indexOf(prefixBuf, at + 1)
  }
}

console.log(`\nhits          ${hits.length}`)
for (const h of hits) {
  const ctxBefore = img.subarray(h.fileOffset - 8, h.fileOffset).toString('hex').match(/../g).join(' ').toUpperCase()
  const ctxMatch = img.subarray(h.fileOffset, h.fileOffset + 16).toString('hex').match(/../g).join(' ').toUpperCase()
  console.log(`  ${h.section}  fileOffset=${hex(h.fileOffset)}  RVA=${hex(h.rva)}  VA=${hex(imageBase + h.rva, 16)}`)
  console.log(`    before: ${ctxBefore}`)
  console.log(`    match : ${ctxMatch} ...`)
}
if (hits.length === 0) {
  console.log('\nNO MATCH — the signature does not describe this binary.')
  process.exit(1)
}
if (hits.length > 1) {
  console.log('\nWARNING: signature is NOT unique — a runtime scanner would need a tie-breaker.')
}
