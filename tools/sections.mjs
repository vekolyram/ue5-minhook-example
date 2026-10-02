// Print PE section sizes, so a slow scan can be sized before blaming the code.
import { readFileSync } from 'node:fs'

const img = readFileSync(process.argv[2])
const e = img.readUInt32LE(0x3c)
const numSections = img.readUInt16LE(e + 6)
const sizeOfOptional = img.readUInt16LE(e + 20)
const secBase = e + 24 + sizeOfOptional

console.log('name      vsize        rawsize      characteristics')
for (let i = 0; i < numSections; i++) {
  const o = secBase + i * 40
  const name = img.toString('ascii', o, o + 8).replace(/\0+$/, '')
  const vsize = img.readUInt32LE(o + 8)
  const rawSize = img.readUInt32LE(o + 16)
  const ch = img.readUInt32LE(o + 36)
  const flags = [
    ch & 0x20000000 ? 'X' : '-',
    ch & 0x40000000 ? 'R' : '-',
    ch & 0x80000000 ? 'W' : '-',
  ].join('')
  console.log(
    `${name.padEnd(9)} 0x${vsize.toString(16).padStart(8, '0')} 0x${rawSize
      .toString(16)
      .padStart(8, '0')}  ${flags}  (${(vsize / 1048576).toFixed(1)} MB)`,
  )
}
