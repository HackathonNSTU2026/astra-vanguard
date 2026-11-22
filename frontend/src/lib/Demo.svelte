<script lang="ts">
  import { onMount, tick } from 'svelte'
  import { SvelteMap, SvelteSet } from 'svelte/reactivity'
  import { jsonPost, request, type Decision } from './api'
  import { messageHistory, needsRestatement } from './chatHistory'

  interface CheckResult {
    decision: Decision
    risk_level: string
    risk_category: string
    explanation: string
    latency_ms: number
    pending_id: string | null
  }

  interface ReceivedRequest {
    id: string
    user_id: string
    user_prompt: string
    decision: Decision
  }

  interface Turn {
    prompt: string
    userId: string
    result: CheckResult
    resolution?: 'confirm' | 'cancel'
  }

  interface Chat {
    id: string
    name?: string
    pinned?: boolean
    draft: string
    role: string
    userId: string
    attachments: string
    turns: Turn[]
  }

  interface Workspace {
    chats: Chat[]
    activeId: string | null
  }

  const storageKey = 'astra-vanguard.chats.v1'
  const example = 'Покажи текущее состояние сервиса payments-api.'
  const decisions: Record<Decision, string> = {
    allow: 'Разрешено',
    confirm: 'Требуется подтверждение',
    block: 'Заблокировано',
  }

  function newChat(previous?: Chat): Chat {
    return {
      id: Array.from(crypto.getRandomValues(new Uint32Array(4))).join('-'),
      draft: '',
      role: previous?.role ?? 'developer',
      userId: previous?.userId ?? 'u-demo',
      attachments: '',
      turns: [],
    }
  }

  function defaultWorkspace(): Workspace {
    const chat = newChat()
    return { chats: [chat], activeId: chat.id }
  }

  function loadWorkspace(): Workspace {
    try {
      const saved = localStorage.getItem(storageKey)
      if (saved) {
        const data: Workspace = JSON.parse(saved)
        if (Array.isArray(data.chats)) {
          const activeId = data.chats.some((chat) => chat.id === data.activeId)
            ? data.activeId
            : data.chats[0]?.id ?? null
          return { chats: data.chats, activeId }
        }
      }
    } catch {
      // Start with an empty conversation if storage can't be read.
    }
    return defaultWorkspace()
  }

  let workspace = $state(loadWorkspace())
  let orderedChats = $derived(workspace.chats.toSorted((a, b) => Number(!!b.pinned) - Number(!!a.pinned)))
  let active = $derived(workspace.chats.find((chat) => chat.id === workspace.activeId))
  let pending = $derived(active && pendingTurn(active))
  let storageError = $state(false)
  let received = $state<ReceivedRequest[]>([])
  let adapterError = $state('')
  let adapterVersion = 0
  let chatDialog = $state<HTMLDialogElement>()
  let renamingChat = $state<Chat>()
  let newName = $state('')
  let deleteError = $state('')
  let chatList = $state<HTMLUListElement>()
  let newChatButton = $state<HTMLButtonElement>()
  let transcript = $state<HTMLElement>()
  let composer = $state<HTMLTextAreaElement>()
  const busy = new SvelteSet<string>()
  const errors = new SvelteMap<string, string>()

  $effect(() => {
    const data = JSON.stringify(workspace)
    try {
      localStorage.setItem(storageKey, data)
      storageError = false
    } catch {
      storageError = true
    }
  })

  function title(chat: Chat): string {
    if (chat.name) return chat.name
    const first = chat.turns[0]?.prompt.replace(/\s+/g, ' ')
    if (!first) return 'Новый чат'
    return first.length <= 56 ? first : `${first.slice(0, 55)}…`
  }

  function pendingTurn(chat: Chat): Turn | undefined {
    const last = chat.turns.at(-1)
    return last?.result.pending_id && !last.resolution ? last : undefined
  }

  async function scrollToLatest(chatId: string) {
    await tick()
    if (workspace.activeId === chatId && transcript) {
      transcript.scrollTop = transcript.scrollHeight
    }
  }

  function selectChat(chat: Chat) {
    workspace.activeId = chat.id
    void scrollToLatest(chat.id)
  }

  function closeChatMenu(event: MouseEvent) {
    (event.currentTarget as HTMLElement).closest<HTMLElement>('.chat-menu')?.hidePopover()
  }

  function togglePinned(event: MouseEvent, chat: Chat) {
    closeChatMenu(event)
    chat.pinned = !chat.pinned
  }

  async function openRenameDialog(event: MouseEvent, chat: Chat) {
    closeChatMenu(event)
    renamingChat = chat
    newName = title(chat)
    await tick()
    chatDialog?.showModal()
    chatDialog?.querySelector('input')?.select()
  }

  function renameChat(event: SubmitEvent, chat: Chat) {
    event.preventDefault()
    const name = newName.trim()
    if (!name) return
    chat.name = name
    chatDialog?.close()
  }

  async function createChat() {
    const chat = newChat(active)
    workspace.chats.unshift(chat)
    selectChat(chat)
    await tick()
    composer?.focus()
  }

  function readAttachments(value: string): unknown[] {
    try {
      const data = JSON.parse(value.trim() || '[]')
      if (Array.isArray(data) && data.every((entry) =>
        entry !== null &&
        typeof entry === 'object' &&
        !Array.isArray(entry) &&
        (!Object.hasOwn(entry, 'content') || typeof entry.content === 'string')
      )) return data
    } catch {
      // Report invalid attachments and invalid JSON together.
    }
    throw new Error('Вложения должны быть JSON-массивом объектов со строковым полем content, если оно указано.')
  }

  async function loadAdapter() {
    const version = ++adapterVersion
    try {
      const entries = await request<ReceivedRequest[]>('/v1/adapter/received')
      if (version === adapterVersion) {
        received = entries
        adapterError = ''
      }
    } catch (cause) {
      if (version === adapterVersion) adapterError = `Не удалось загрузить запросы адаптера. ${cause}`
    }
  }

  async function check(event: SubmitEvent, chat: Chat) {
    event.preventDefault()
    const prompt = chat.draft.trim()
    const userId = chat.userId.trim()
    if (!prompt || busy.has(chat.id) || pendingTurn(chat)) return

    errors.delete(chat.id)
    if (!userId) {
      errors.set(chat.id, 'Укажите ID пользователя в настройках запроса.')
      return
    }

    if (needsRestatement(prompt, chat.turns)) {
      errors.set(chat.id, 'Сформулируйте запрос полностью: предыдущее действие не было разрешено.')
      return
    }

    busy.add(chat.id)
    try {
      const result = await request<CheckResult>('/v1/check', jsonPost({
        user_prompt: prompt,
        context: {
          target_agent: 'it_ops_agent',
          user_role: chat.role,
          user_id: userId,
          user_name: 'Demo User',
          system_prompt: 'Ты — DevOps-ассистент инженерной команды.',
          history: messageHistory(chat.turns),
          attachments: readAttachments(chat.attachments),
        },
      }))
      chat.turns.push({ prompt, userId, result })
      chat.draft = ''
      void scrollToLatest(chat.id)
      if (result.decision === 'allow') void loadAdapter()
    } catch (cause) {
      errors.set(chat.id, `Не удалось проверить запрос. ${cause instanceof Error ? cause.message : cause}`)
    } finally {
      busy.delete(chat.id)
    }
  }

  function updatePending(turn: Turn, action: 'confirm' | 'cancel') {
    return request(`/v1/adapter/${action}`, jsonPost({
      pending_id: turn.result.pending_id,
      user_id: turn.userId,
    }))
  }

  async function resolvePending(chat: Chat, action: 'confirm' | 'cancel') {
    const turn = pendingTurn(chat)
    if (!turn || busy.has(chat.id)) return
    busy.add(chat.id)
    errors.delete(chat.id)
    try {
      await updatePending(turn, action)
      turn.resolution = action
      void scrollToLatest(chat.id)
      if (action === 'confirm') void loadAdapter()
    } catch (cause) {
      errors.set(chat.id, `Не удалось обработать подтверждение. ${cause}`)
    } finally {
      busy.delete(chat.id)
    }
  }

  async function deleteChat(event: MouseEvent, chat: Chat) {
    closeChatMenu(event)
    if (busy.has(chat.id)) return
    busy.add(chat.id)
    deleteError = ''
    try {
      const turn = pendingTurn(chat)
      if (turn) {
        try {
          await updatePending(turn, 'cancel')
        } catch (cause) {
          // The adapter may already have removed the pending request.
          if (!(cause instanceof Error) || cause.message !== 'cancel_failed') throw cause
        }
      }
      const position = orderedChats.findIndex((entry) => entry.id === chat.id)
      const next = orderedChats[position + 1] ?? orderedChats[position - 1]
      const index = workspace.chats.findIndex((entry) => entry.id === chat.id)
      workspace.chats.splice(index, 1)
      errors.delete(chat.id)
      if (workspace.activeId === chat.id) {
        workspace.activeId = next?.id ?? null
        if (next) void scrollToLatest(next.id)
      }
      await tick()
      if (document.activeElement === document.body) {
        const focusTarget = chatList?.querySelector<HTMLButtonElement>('.chat-link[aria-current]') ?? newChatButton
        focusTarget?.focus()
      }
    } catch (cause) {
      deleteError = `Не удалось удалить чат «${title(chat)}». ${cause}`
    } finally {
      busy.delete(chat.id)
    }
  }

  async function loadExample(chat: Chat) {
    chat.draft = example
    await tick()
    composer?.focus()
  }

  onMount(() => {
    void loadAdapter()
    if (active) void scrollToLatest(active.id)
  })
</script>

<div class="workspace">
  <aside class="sidebar" aria-labelledby="chat-list-title">
    <div class="sidebar-header">
      <h2 id="chat-list-title">Чаты</h2>
      <button bind:this={newChatButton} class="new-chat" type="button" onclick={createChat}><span aria-hidden="true">+</span> Новый чат</button>
    </div>

    {#if workspace.chats.length}
      <ul class="chat-list" bind:this={chatList}>
        {#each orderedChats as chat (chat.id)}
          <li class="chat-row">
            <button class="chat-link" class:selected={chat.id === workspace.activeId}
              aria-current={chat.id === workspace.activeId ? 'true' : undefined}
              type="button" onclick={() => selectChat(chat)}>
              <span class="chat-title">
                {#if chat.pinned}<span class="pin-mark" role="img" aria-label="Закреплён">📌</span>{/if}
                <span>{title(chat)}</span>
              </span>
              {#if pendingTurn(chat)}<small>Ожидает подтверждения</small>{/if}
            </button>
            <button class="chat-menu-toggle" type="button" popovertarget={`chat-menu-${chat.id}`}
              aria-label={`Действия с чатом «${title(chat)}»`}>
              <span aria-hidden="true">⋯</span>
            </button>
            <div class="chat-menu" id={`chat-menu-${chat.id}`} popover="auto">
              <button type="button" onclick={(event) => togglePinned(event, chat)}>
                {chat.pinned ? 'Открепить' : 'Закрепить'}
              </button>
              <button type="button" onclick={(event) => openRenameDialog(event, chat)}>Переименовать</button>
              <button class="text-danger" type="button" disabled={busy.has(chat.id)}
                onclick={(event) => deleteChat(event, chat)}>Удалить чат</button>
            </div>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="sidebar-empty">Пока нет чатов</p>
    {/if}
    {#if deleteError}<p class="error composer-status" role="alert">{deleteError}</p>{/if}

    <details class="adapter-panel">
      <summary>Запросы адаптера</summary>
      {#if adapterError}
        <p class="error" role="alert">{adapterError}</p>
      {:else if received.length}
        <ul class="adapter-list">
          {#each received as entry (entry.id)}
            <li><strong>{entry.user_id}</strong><span class="badge {entry.decision}">{decisions[entry.decision]}</span><p>{entry.user_prompt}</p></li>
          {/each}
        </ul>
      {:else}
        <p>Запросов пока нет.</p>
      {/if}
    </details>
  </aside>

  <section class="conversation" aria-labelledby="conversation-title">
    {#if active}
      {@const chat = active}
      {@const isBusy = busy.has(chat.id)}
      <header class="conversation-header">
        <div>
          <h1 id="conversation-title">{title(chat)}</h1>
          <p>Проверка запросов к DevOps-агенту</p>
        </div>
      </header>

      <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard users need to scroll the transcript.) -->
      <div class="transcript" bind:this={transcript} role="log" aria-label="История чата" tabindex="0">
        <div class="messages">
          {#if chat.turns.length}
            {#each chat.turns as turn}
              <article class="message user-message" aria-label="Ваше сообщение">
                <span class="message-author">Вы</span>
                <p>{turn.prompt}</p>
              </article>
              <article class="message guard-message" aria-label="Результат проверки">
                <div class="message-heading">
                  <span class="message-author">Астра Авангард</span>
                  <span class="badge {turn.result.decision}">{decisions[turn.result.decision]}</span>
                </div>
                <p>{turn.result.explanation}</p>
                <div class="message-meta">Риск {turn.result.risk_level} / {turn.result.risk_category} · {turn.result.latency_ms} мс</div>
                {#if turn.resolution === 'confirm'}
                  <p class="message-resolution" role="status">Запрос подтверждён и отправлен агенту.</p>
                {:else if turn.resolution === 'cancel'}
                  <p class="message-resolution" role="status">Запрос отклонён.</p>
                {:else if turn === pending}
                  <div class="actions">
                    <button disabled={isBusy} type="button" onclick={() => resolvePending(chat, 'confirm')}>Подтвердить и отправить</button>
                    <button class="secondary" disabled={isBusy} type="button" onclick={() => resolvePending(chat, 'cancel')}>Отклонить</button>
                  </div>
                {/if}
              </article>
            {/each}
          {:else}
            <div class="empty-chat">
              <span class="brand-mark" aria-hidden="true">ИИ</span>
              <h2>Отправьте запрос на проверку</h2>
              <p>Астра Авангард оценит риск и объяснит своё решение.</p>
              <button class="secondary" type="button" disabled={isBusy} onclick={() => loadExample(chat)}>Вставить пример</button>
            </div>
          {/if}
        </div>
      </div>

      <div class="composer-area">
        <form class="composer" onsubmit={(event) => check(event, chat)}>
          <label class="sr-only" for="prompt">Сообщение</label>
          <textarea id="prompt" bind:this={composer} bind:value={chat.draft} placeholder="Напишите сообщение…" rows="2" disabled={isBusy}
            onkeydown={(event) => {
              if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return
              event.preventDefault()
              if (!event.repeat && !isBusy && !pending && chat.draft.trim()) {
                event.currentTarget.form?.requestSubmit()
              }
            }}></textarea>
          <div class="composer-footer">
            <details class="request-settings">
              <summary>Настройки запроса</summary>
              <div class="settings-fields">
                <div class="row">
                  <div>
                    <label for="role">Роль пользователя</label>
                    <select id="role" bind:value={chat.role} disabled={isBusy}>
                      <option value="developer">developer</option>
                      <option value="sre">sre</option>
                      <option value="admin">admin</option>
                    </select>
                  </div>
                  <div>
                    <label for="user-id">ID пользователя</label>
                    <input id="user-id" bind:value={chat.userId} disabled={isBusy} />
                  </div>
                </div>
                <label for="attachments">Вложения (JSON-массив)</label>
                <textarea id="attachments" bind:value={chat.attachments} rows="3" disabled={isBusy}
                  placeholder={'[{"type":"document","name":"README.md","content":"..."}]'}></textarea>
              </div>
            </details>
            <button type="submit" disabled={isBusy || !!pending || !chat.draft.trim()}>Отправить <span aria-hidden="true">↑</span></button>
          </div>
        </form>
        {#if isBusy}
          <p class="composer-status" role="status">Запрос обрабатывается…</p>
        {:else if pending}
          <p class="composer-status">Подтвердите или отклоните предыдущий запрос, чтобы отправить следующий.</p>
        {/if}
        {#if errors.has(chat.id)}<p class="error composer-status" role="alert">{errors.get(chat.id)}</p>{/if}
        {#if storageError}<p class="error composer-status" role="alert">Не удалось сохранить чаты в браузере.</p>{/if}
      </div>
    {:else}
      <div class="empty-chat no-chat">
        <span class="brand-mark" aria-hidden="true">ИИ</span>
        <h1 id="conversation-title">У вас пока нет чатов</h1>
        <button type="button" onclick={createChat}>Создать чат</button>
        {#if storageError}<p class="error" role="alert">Не удалось сохранить чаты в браузере.</p>{/if}
      </div>
    {/if}
  </section>
</div>

<dialog class="chat-dialog" bind:this={chatDialog} aria-labelledby="chat-dialog-title"
  onclose={() => (renamingChat = undefined)}>
  {#if renamingChat}
    {@const chat = renamingChat}
    <h2 id="chat-dialog-title">Переименовать чат</h2>
    <form onsubmit={(event) => renameChat(event, chat)}>
      <label for="chat-name">Название чата</label>
      <input id="chat-name" bind:value={newName} maxlength="120" required />
      <div class="actions">
        <button class="secondary" type="button" onclick={() => chatDialog?.close()}>Отмена</button>
        <button type="submit" disabled={!newName.trim()}>Сохранить</button>
      </div>
    </form>
  {/if}
</dialog>
