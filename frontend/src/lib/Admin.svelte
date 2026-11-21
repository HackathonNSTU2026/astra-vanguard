<script lang="ts">
  import { onMount } from 'svelte'
  import { request, type Decision } from './api'

  interface JournalEntry {
    timestamp: string
    user_role: string
    decision: Decision
    risk_category: string
    risk_level: string
    latency_ms: number
    user_prompt_masked: string
  }

  let policy = $state('')
  let journal = $state<JournalEntry[]>([])
  let policyError = $state('')
  let journalError = $state('')
  let status = $state('')
  let busy = $state(false)
  let journalLoading = false

  async function loadPolicy(reload = false) {
    if (busy) return
    busy = true
    policyError = ''
    status = ''
    try {
      if (reload) {
        await request('/admin/policy/reload', { method: 'POST' })
        status = 'Политика перезагружена.'
      }
      policy = await request<string>('/admin/policy')
    } catch (cause) {
      policyError = `Ошибка при работе с политикой. ${cause}`
    } finally {
      busy = false
    }
  }

  async function loadJournal() {
    if (journalLoading) return
    journalLoading = true
    try {
      journal = await request<JournalEntry[]>('/admin/journal?limit=50')
      journalError = ''
    } catch (cause) {
      journalError = `Не удалось загрузить журнал. ${cause}`
    } finally {
      journalLoading = false
    }
  }

  onMount(() => {
    void loadPolicy()
    void loadJournal()
    const timer = window.setInterval(loadJournal, 5000)
    return () => window.clearInterval(timer)
  })
</script>

<h1>⚙️ ИИ-сторож — административный интерфейс</h1>

<section class="card">
  <h2>Текущая политика (security_policy.yaml)</h2>
  <pre>{policy}</pre>
  <div class="actions">
    <button disabled={busy} onclick={() => loadPolicy(true)}>Перезагрузить политику</button>
    <button class="secondary" disabled={busy} onclick={() => loadPolicy()}>Обновить вид</button>
  </div>
  {#if status}<p role="status">{status}</p>{/if}
  {#if policyError}<p class="error" role="alert">{policyError}</p>{/if}
</section>

<section class="card">
  <h2>Журнал решений</h2>
  {#if journalError}<p class="error" role="alert">{journalError}</p>{/if}
  <div class="table-scroll">
    <table>
      <thead>
        <tr><th>Время</th><th>Роль</th><th>Решение</th><th>Категория</th><th>Риск</th><th>Задержка</th><th>Запрос (маска)</th></tr>
      </thead>
      <tbody>
        {#each journal as entry}
          <tr>
            <td>{entry.timestamp}</td>
            <td>{entry.user_role}</td>
            <td><span class="badge {entry.decision}">{entry.decision}</span></td>
            <td>{entry.risk_category}</td>
            <td>{entry.risk_level}</td>
            <td>{entry.latency_ms} мс</td>
            <td>{entry.user_prompt_masked}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
