<script>
  import Page from "./+page.svelte";

</script>


<div class="main">
    <slot></slot>
</div>



<svelte:head>
    <style>
        body{
            margin:0;
        }
    </style>
</svelte:head>



<style>
    .main{
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }
</style>