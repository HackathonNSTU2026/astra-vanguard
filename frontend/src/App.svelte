<script lang="ts">
  import astraLogo from './assets/astra-logo.svg'
  import Admin from './lib/Admin.svelte'
  import Demo from './lib/Demo.svelte'

  type Theme = 'light' | 'dark'
  const isAdmin = /^\/admin\/?$/.test(window.location.pathname)
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)')

  function initialTheme(): Theme {
    try {
      const saved = localStorage.getItem('astra-vanguard.theme')
      if (saved === 'dark' || saved === 'light') return saved
    } catch {
      // The switch still works when browser storage is unavailable.
    }
    return prefersDark.matches ? 'dark' : 'light'
  }

  let theme = $state(initialTheme())
  $effect(() => {
    document.documentElement.dataset.theme = theme
  })

  function toggleTheme() {
    theme = theme === 'light' ? 'dark' : 'light'
    try {
      localStorage.setItem('astra-vanguard.theme', theme)
    } catch {
      // The current document already has the selected theme.
    }
  }
</script>

<svelte:head>
  <title>Астра Авангард — {isAdmin ? 'администрирование' : 'чаты'}</title>
</svelte:head>

<header class="site-header">
  <div class="site-header-inner">
    <a class="brand" href="/">
      <span class="brand-mark" aria-hidden="true">ИИ</span>
      Астра Авангард
    </a>

    <nav aria-label="Разделы">
      <a href="/" aria-current={isAdmin ? undefined : 'page'}>Чаты</a>
      <a href="/admin" aria-current={isAdmin ? 'page' : undefined}>Администрирование</a>
    </nav>

    <div class="header-actions">
      <a class="organizer-logo" href="https://astralinux.ru/" target="_blank" rel="noopener">
        <img src={astraLogo} alt="Astra Linux — организатор хакатона" width="914" height="249" />
      </a>
      <button class="secondary theme-toggle" type="button" onclick={toggleTheme} aria-pressed={theme === 'dark'}>
        <span aria-hidden="true">{theme === 'dark' ? '☾' : '☀'}</span>
        <span class="theme-toggle-label">Тёмная тема</span>
      </button>
    </div>
  </div>
</header>

{#if isAdmin}
  <main class="admin-content"><Admin /></main>
{:else}
  <main class="chat-content"><Demo /></main>
{/if}
