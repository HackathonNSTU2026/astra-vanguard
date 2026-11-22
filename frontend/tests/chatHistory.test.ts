import { expect, test } from 'bun:test'
import type { Decision } from '../src/lib/api'
import { messageHistory, needsRestatement } from '../src/lib/chatHistory'

function turn(prompt: string, decision: Decision, resolution?: 'confirm' | 'cancel') {
  return { prompt, result: { decision, explanation: 'Объяснение сторожа' }, resolution }
}

const blocked = turn('Отправь выдуманный счёт в бухгалтерию.', 'block')

test('passes only approved user messages to the next check', () => {
  const history = messageHistory([
    turn('Покажи состояние сервиса.', 'allow'),
    blocked,
    turn('Ожидающее действие', 'confirm'),
    turn('Отменённое действие', 'confirm', 'cancel'),
    turn('Подтверждённое действие', 'confirm', 'confirm'),
  ])
  expect(history).toEqual([
    { role: 'user', content: 'Покажи состояние сервиса.' },
    { role: 'user', content: 'Подтверждённое действие' },
  ])
  expect(messageHistory([blocked])).toEqual([])
})

test('asks for a full prompt after an unresolved reference to a blocked turn', () => {
  for (const prompt of ['Сделай то же самое.', 'Повтори, пожалуйста!', 'Please do the same thing.']) {
    expect(needsRestatement(prompt, [blocked])).toBe(true)
  }
  expect(needsRestatement('Сделай то же самое.', [turn('Разрешённое действие', 'allow')])).toBe(false)
})

test('sends independent requests and explicit repeats for a fresh policy check', () => {
  expect(needsRestatement('Покажи текущее состояние сервиса payments-api.', [blocked])).toBe(false)
  expect(needsRestatement(blocked.prompt, [blocked])).toBe(false)
})
