export type StrengthResult = {
  score: 0 | 1 | 2 | 3 | 4
  label: 'Very weak' | 'Weak' | 'Fair' | 'Strong' | 'Excellent'
  entropy: number
  timeToCrack: string
  suggestions: string[]
}

const COMMON_PATTERNS = [
  'password', 'qwerty', 'letmein', 'welcome', 'admin', 'monkey', 'dragon',
  'football', 'iloveyou', 'abc123', '123456', '111111', '000000',
]

export function randomInt(max: number): number {
  if (!Number.isSafeInteger(max) || max <= 0) throw new Error('max must be a positive integer')
  const limit = Math.floor(0x1_0000_0000 / max) * max
  const value = new Uint32Array(1)
  do crypto.getRandomValues(value)
  while (value[0] >= limit)
  return value[0] % max
}

function secureShuffle<T>(items: T[]): T[] {
  const result = [...items]
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1)
    ;[result[i], result[j]] = [result[j], result[i]]
  }
  return result
}

export type PasswordOptions = {
  length: number
  uppercase: boolean
  lowercase: boolean
  numbers: boolean
  symbols: boolean
  avoidAmbiguous: boolean
}

export function generatePassword(options: PasswordOptions): string {
  const ambiguous = 'Il1O0o'
  const groups = [
    options.uppercase ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '',
    options.lowercase ? 'abcdefghijklmnopqrstuvwxyz' : '',
    options.numbers ? '0123456789' : '',
    options.symbols ? '!@#$%^&*()-_=+[]{};:,.?' : '',
  ].filter(Boolean).map((group) => options.avoidAmbiguous
    ? [...group].filter((char) => !ambiguous.includes(char)).join('')
    : group)

  if (!groups.length) throw new Error('Select at least one character set')
  const length = Math.max(groups.length, Math.min(128, Math.round(options.length)))
  const all = groups.join('')
  const required = groups.map((group) => group[randomInt(group.length)])
  const rest = Array.from({ length: length - required.length }, () => all[randomInt(all.length)])
  return secureShuffle([...required, ...rest]).join('')
}

const WORDS = [
  'amber', 'anchor', 'apricot', 'aurora', 'badger', 'bamboo', 'basil', 'beacon',
  'birch', 'breeze', 'cactus', 'canyon', 'cedar', 'cinder', 'cobalt', 'comet',
  'coral', 'cosmos', 'cricket', 'dahlia', 'delta', 'ember', 'falcon', 'fern',
  'fjord', 'flint', 'forest', 'galaxy', 'garden', 'glacier', 'harbor', 'hazel',
  'heron', 'island', 'ivory', 'jasmine', 'juniper', 'lagoon', 'lantern', 'laurel',
  'lilac', 'lotus', 'lunar', 'maple', 'marble', 'meadow', 'meteor', 'mint',
  'nebula', 'oasis', 'ocean', 'olive', 'onyx', 'orchid', 'otter', 'pebble',
  'pine', 'planet', 'plum', 'poppy', 'quartz', 'raven', 'reef', 'river',
  'robin', 'saffron', 'sage', 'shadow', 'shore', 'silver', 'sparrow', 'spruce',
  'stone', 'summit', 'thistle', 'tiger', 'topaz', 'tulip', 'valley', 'violet',
  'willow', 'winter', 'zephyr', 'zinnia',
]

export function generatePassphrase(words = 5, separator = '-'): string {
  const count = Math.max(3, Math.min(10, words))
  return Array.from({ length: count }, () => WORDS[randomInt(WORDS.length)]).join(separator)
}

export function ratePassword(password: string): StrengthResult {
  if (!password) return { score: 0, label: 'Very weak', entropy: 0, timeToCrack: 'Instant', suggestions: ['Use at least 14 characters'] }
  let pool = 0
  if (/[a-z]/.test(password)) pool += 26
  if (/[A-Z]/.test(password)) pool += 26
  if (/\d/.test(password)) pool += 10
  if (/[^a-zA-Z0-9]/.test(password)) pool += 32
  let entropy = password.length * Math.log2(Math.max(pool, 1))
  const lower = password.toLowerCase()
  const suggestions: string[] = []

  if (COMMON_PATTERNS.some((pattern) => lower.includes(pattern))) {
    entropy = Math.min(entropy, 18)
    suggestions.push('Avoid common words and keyboard patterns')
  }
  if (/(.)\1{2,}/.test(password)) {
    entropy -= 12
    suggestions.push('Avoid repeated characters')
  }
  if (/^(?:[a-zA-Z]+\d+|\d+[a-zA-Z]+)$/.test(password)) entropy -= 8
  if (password.length < 14) suggestions.push('Use 14 or more characters')
  if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push('Add symbols or use a longer passphrase')
  entropy = Math.max(0, Math.round(entropy))

  const score = (entropy < 28 ? 0 : entropy < 45 ? 1 : entropy < 65 ? 2 : entropy < 90 ? 3 : 4) as StrengthResult['score']
  const labels: StrengthResult['label'][] = ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent']
  const guessesPerSecond = 10_000_000_000
  const seconds = 2 ** Math.min(entropy, 200) / guessesPerSecond
  const timeToCrack = seconds < 1 ? 'Instant' : seconds < 60 ? `${Math.round(seconds)} seconds` : seconds < 3600 ? `${Math.round(seconds / 60)} minutes` : seconds < 31_536_000 ? `${Math.round(seconds / 86_400)} days` : seconds < 31_536_000_000 ? `${Math.round(seconds / 31_536_000)} years` : 'Centuries+'

  return { score, label: labels[score], entropy, timeToCrack, suggestions: suggestions.slice(0, 2) }
}

