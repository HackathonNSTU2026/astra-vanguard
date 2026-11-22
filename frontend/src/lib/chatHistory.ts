import type { Decision } from './api'

interface CheckedTurn {
  prompt: string
  result: { decision: Decision }
  resolution?: 'confirm' | 'cancel'
}

function isApproved(turn: CheckedTurn): boolean {
  return turn.result.decision === 'allow' ||
    (turn.result.decision === 'confirm' && turn.resolution === 'confirm')
}

export function messageHistory(turns: CheckedTurn[]) {
  return turns.filter(isApproved).map((turn) => ({ role: 'user', content: turn.prompt }))
}

const implicitFollowUp = /^(?:сделай\s+(?:это|(?:всё\s+)?то\s*же(?:\s+самое)?)|(?:повтори|выполни|отправь|продолжи)(?:\s+(?:это|(?:то\s*же(?:\s+самое)?)|предыдущий\s+запрос|ещ[её]\s+раз))?|то\s*же\s+самое|давай\s+ещ[её]\s+раз|(?:do|send|run)\s+(?:it|that|the\s+same(?:\s+thing)?)(?:\s+again)?|(?:repeat|try)\s+(?:(?:it|that)\s+)?again|repeat(?:\s+(?:it|that|the previous request))?|continue)$/iu

export function needsRestatement(prompt: string, turns: CheckedTurn[]): boolean {
  const lastTurn = turns.at(-1)
  if (!lastTurn || isApproved(lastTurn)) return false

  const text = prompt.trim()
    .replace(/^(?:пожалуйста|please)[,\s]+/iu, '')
    .replace(/[,\s]+(?:пожалуйста|please)[.!?…]*$/iu, '')
    .replace(/[.!?…]+$/u, '')
    .trim()
  return implicitFollowUp.test(text)
}
