<script lang="ts">
  import Admin from './lib/Admin.svelte'
  import Demo from './lib/Demo.svelte'

  const isAdmin = /^\/admin\/?$/.test(window.location.pathname)
</script>

<svelte:head>
  <title>ИИ-сторож — {isAdmin ? 'администрирование' : 'демо'}</title>
</svelte:head>

<main class:admin={isAdmin}>
  <nav aria-label="Разделы">
    <a href="/" aria-current={isAdmin ? undefined : 'page'}>Демо</a>
    <a href="/admin" aria-current={isAdmin ? 'page' : undefined}>Администрирование</a>
  </nav>
  {#if isAdmin}
    <Admin />
  {:else}
    <Demo />
  {/if}
</main>
