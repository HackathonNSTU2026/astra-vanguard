<script lang="ts">
  import { onMount } from 'svelte'
  import { jsonPost, request, type Decision } from './api'

  interface CheckResult {
    decision: Decision
    risk_level: string
    risk_category: string
    explanation: string
    latency_ms: number
    pending_id: string | null
  }

  interface ReceivedRequest {
    user_id: string
    user_prompt: string
    decision: Decision
  }

  const example = 'Перезапусти payments-api в production.'
  let prompt = $state('')
  let role = $state('developer')
  let userId = $state('u-demo')
  let history = $state('')
  let attachments = $state('')
  let result = $state<CheckResult>()
  let pending = $state<{ pending_id: string; user_id: string }>()
  let received = $state<ReceivedRequest[]>([])
  let busy = $state(false)
  let error = $state('')
  let adapterError = $state('')
  let status = $state('')

  function readEntries(value: string, label: string): unknown[] {
    try {
      const data = JSON.parse(value.trim() || '[]')
      if (Array.isArray(data) && data.every((entry) =>
        entry !== null &&
        typeof entry === 'object' &&
        !Array.isArray(entry) &&
        (!Object.hasOwn(entry, 'content') || typeof entry.content === 'string')
      )) return data
    } catch {
      // Report invalid JSON and invalid shapes in the same way.
    }
    throw new Error(`${label} — укажите JSON-массив объектов. Поле content, если указано, должно быть строкой.`)
  }

  async function loadAdapter() {
    try {
      received = await request<ReceivedRequest[]>('/v1/adapter/received')
      adapterError = ''
    } catch (cause) {
      adapterError = `Не удалось загрузить запросы адаптера. ${cause}`
    }
  }

  async function check(event: SubmitEvent) {
    event.preventDefault()
    if (busy || pending) return
    busy = true
    error = ''
    status = ''
    result = undefined
    const submittedUserId = userId
    try {
      result = await request<CheckResult>('/v1/check', jsonPost({
        user_prompt: prompt,
        context: {
          target_agent: 'it_ops_agent',
          user_role: role,
          user_id: submittedUserId,
          user_name: 'Demo User',
          system_prompt: 'Ты — DevOps-ассистент инженерной команды.',
          history: readEntries(history, 'История диалога'),
          attachments: readEntries(attachments, 'Вложения'),
        },
      }))
      if (result.decision === 'confirm' && result.pending_id) {
        pending = { pending_id: result.pending_id, user_id: submittedUserId }
      } else if (result.decision === 'allow') {
        await loadAdapter()
      }
    } catch (cause) {
      error = `Ошибка проверки. ${cause instanceof Error ? cause.message : cause}`
    } finally {
      busy = false
    }
  }

  async function resolvePending(action: 'confirm' | 'cancel') {
    if (busy || !pending) return
    busy = true
    error = ''
    try {
      await request(`/v1/adapter/${action}`, jsonPost(pending))
      pending = undefined
      status = action === 'confirm' ? 'Запрос подтверждён и отправлен агенту.' : 'Запрос отклонён.'
      if (action === 'confirm') await loadAdapter()
    } catch (cause) {
      error = `Не удалось обработать подтверждение. ${cause}`
    } finally {
      busy = false
    }
  }

  function loadExample() {
    prompt = example
    role = 'developer'
  }

  onMount(() => { void loadAdapter() })
</script>

<h1>🛡️ ИИ-сторож — демонстрационный интерфейс</h1>

<form class="card" onsubmit={check}>
  <label for="prompt">Запрос (user_prompt)</label>
  <textarea id="prompt" bind:value={prompt} placeholder={example}></textarea>

  <div class="row">
    <div>
      <label for="role">Роль пользователя</label>
      <select id="role" bind:value={role}>
        <option value="developer">developer</option>
        <option value="sre">sre</option>
        <option value="admin">admin</option>
      </select>
    </div>
    <div>
      <label for="user-id">ID пользователя</label>
      <input id="user-id" bind:value={userId} required />
    </div>
  </div>

  <label for="history">История диалога (JSON-массив)</label>
  <textarea id="history" bind:value={history} placeholder={'[{"role":"user","content":"..."}]'}></textarea>

  <label for="attachments">Вложения (JSON-массив)</label>
  <textarea id="attachments" bind:value={attachments} placeholder={'[{"type":"document","name":"README.md","content":"..."}]'}></textarea>

  <div class="actions">
    <button disabled={busy || !!pending}>Проверить запрос</button>
    <button class="secondary" type="button" onclick={loadExample}>Загрузить пример</button>
  </div>
</form>

{#if result}
  <div class="result {result.decision}" role="status">
    <span class="badge {result.decision}">{result.decision}</span>
    <strong>Риск</strong> {result.risk_level} / {result.risk_category}<br />
    <strong>Задержка</strong> {result.latency_ms} мс<br />
    <strong>Объяснение</strong> {result.explanation}
  </div>
{/if}

{#if pending}
  <section>
    <h2>Требуется подтверждение</h2>
    <div class="actions">
      <button class="success" disabled={busy} onclick={() => resolvePending('confirm')}>Подтвердить и отправить агенту</button>
      <button class="danger" disabled={busy} onclick={() => resolvePending('cancel')}>Отклонить</button>
    </div>
  </section>
{/if}

{#if status}<p role="status">{status}</p>{/if}
{#if error}<p class="error" role="alert">{error}</p>{/if}

<section class="adapters">
  <h2>Полученные запросы адаптера</h2>
  {#if adapterError}
    <p class="error" role="alert">{adapterError}</p>
  {:else if received.length}
    {#each received as entry}
      <div class="history-item"><strong>{entry.user_id}</strong> · {entry.user_prompt} <em>[{entry.decision}]</em></div>
    {/each}
  {:else}
    <p>Запросов пока нет.</p>
  {/if}
</section>
