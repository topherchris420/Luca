<template>
    <main class="luca-home">
        <header class="luca-header">
            <a class="luca-wordmark" href="/" aria-label="Luca home" @click.prevent="$router.push({ name: 'loader' })">
                <span class="luca-mark" aria-hidden="true"><i></i><i></i><i></i></span>
                <span>Luca</span>
            </a>
            <span v-if="current_version" class="luca-version">{{ current_version }}</span>
        </header>

        <section class="luca-content">
            <div class="luca-copy">
                <p class="luca-kicker">{{ $t("home.kicker") }}</p>
                <h1>{{ $t("home.welcome_msg") }}</h1>
                <p class="luca-description">{{ $t("home.help_msg") }}</p>
                <button class="luca-start" type="button" @click="next()">
                    <span>{{ $t("home.start_btn") }}</span>
                    <span class="luca-arrow" aria-hidden="true">&#8594;</span>
                </button>
            </div>

            <div class="luca-visual" aria-hidden="true">
                <span class="luca-connection luca-connection-top"></span>
                <span class="luca-connection luca-connection-bottom"></span>
                <span class="luca-signal luca-signal-top"></span>
                <span class="luca-signal luca-signal-bottom"></span>
                <div class="luca-device"><span></span><i></i></div>
                <div class="luca-check"><span></span></div>
            </div>
        </section>
    </main>
</template>

<style scoped>
.luca-home {
    --luca-ink: #182b2a;
    --luca-muted: #637370;
    --luca-green: #187a62;
    --luca-mint: #dcefe7;
    box-sizing: border-box;
    width: min(100%, 1080px);
    min-height: 100%;
    margin: 0 auto;
    padding: 30px 48px 42px;
    display: flex;
    flex-direction: column;
    color: var(--luca-ink);
    text-align: left;
}

.luca-header {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 42px;
}

.luca-wordmark {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    color: var(--luca-ink);
    font-family: "Roboto-Bold", sans-serif;
    font-size: 21px;
    text-decoration: none;
}

.luca-mark {
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 3px;
    border-radius: 10px;
    background: var(--luca-green);
}

.luca-mark i {
    width: 3px;
    border-radius: 3px;
    background: #fff;
}

.luca-mark i:nth-child(1) { height: 9px; }
.luca-mark i:nth-child(2) { height: 16px; }
.luca-mark i:nth-child(3) { height: 12px; }

.luca-version {
    padding: 4px 8px;
    border: 1px solid #dce5e1;
    border-radius: 4px;
    color: var(--luca-muted);
    font-size: 11px;
}

.luca-content {
    flex: 1;
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(250px, 0.9fr);
    align-items: center;
    gap: 42px;
    padding: 22px 0 8px;
}

.luca-copy { max-width: 490px; }

.luca-kicker {
    margin: 0 0 18px;
    color: var(--luca-green);
    font-family: "Roboto-Bold", sans-serif;
    font-size: 11px;
    letter-spacing: 1.4px;
}

.luca-copy h1 {
    margin: 0;
    font-family: "Roboto-Bold", sans-serif;
    font-size: 42px;
    line-height: 1.12;
}

.luca-description {
    max-width: 390px;
    margin: 18px 0 30px;
    color: var(--luca-muted);
    font-size: 17px;
    line-height: 1.55;
}

.luca-start {
    min-width: 220px;
    min-height: 58px;
    padding: 0 18px 0 22px;
    display: inline-flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    border: 0;
    border-radius: 5px;
    background: var(--luca-green);
    color: #fff;
    cursor: pointer;
    font-family: "Roboto-Bold", sans-serif;
    font-size: 17px;
    transition: background-color 160ms ease, transform 160ms ease;
}

.luca-start:hover { background: #11644f; transform: translateY(-1px); }
.luca-start:focus-visible { outline: 3px solid #95cbb8; outline-offset: 3px; }
.luca-arrow { font-size: 22px; line-height: 1; }

.luca-visual {
    position: relative;
    width: min(100%, 360px);
    aspect-ratio: 1.18;
    justify-self: center;
    overflow: hidden;
    border-radius: 4px;
    background: #eaf4ef;
}

.luca-device {
    position: absolute;
    z-index: 1;
    top: 50%;
    left: 50%;
    width: 74px;
    height: 122px;
    border: 5px solid var(--luca-ink);
    border-radius: 15px;
    background: #fff;
    box-shadow: 0 12px 30px rgba(24, 43, 42, .14);
    transform: translate(-50%, -50%);
}

.luca-device span {
    position: absolute;
    top: 10px;
    left: 50%;
    width: 20px;
    height: 3px;
    border-radius: 3px;
    background: #b7c7c1;
    transform: translateX(-50%);
}

.luca-device i {
    position: absolute;
    right: 12px;
    bottom: 13px;
    left: 12px;
    height: 45px;
    border-radius: 5px;
    background: linear-gradient(180deg, #cce8dc 0 24%, #e8f3ee 24% 48%, #cce8dc 48% 72%, #e8f3ee 72%);
}

.luca-check {
    position: absolute;
    z-index: 2;
    top: 25%;
    right: 21%;
    width: 48px;
    height: 48px;
    border: 4px solid #fff;
    border-radius: 50%;
    background: #e9a24b;
    box-shadow: 0 4px 15px rgba(24, 43, 42, .16);
}

.luca-check span {
    position: absolute;
    top: 13px;
    left: 12px;
    width: 17px;
    height: 9px;
    border-bottom: 3px solid #fff;
    border-left: 3px solid #fff;
    transform: rotate(-45deg);
}

.luca-connection {
    position: absolute;
    z-index: 1;
    left: 25%;
    width: 50%;
    height: 1px;
    background: rgba(24, 122, 98, .28);
    transform: rotate(-28deg);
}

.luca-connection-top { top: 32%; }
.luca-connection-bottom { bottom: 30%; transform: rotate(24deg); }

.luca-signal {
    position: absolute;
    z-index: 1;
    width: 12px;
    height: 12px;
    border: 3px solid #fff;
    border-radius: 50%;
    background: var(--luca-green);
    box-shadow: 0 0 0 4px rgba(24, 122, 98, .13);
}

.luca-signal-top { top: 29%; left: 25%; }
.luca-signal-bottom { right: 25%; bottom: 27%; background: #e9a24b; }

@media (max-width: 700px) {
    .luca-home { padding: 22px 24px 30px; }
    .luca-content { grid-template-columns: minmax(0, 1fr) 220px; gap: 18px; }
    .luca-copy h1 { font-size: 34px; }
    .luca-description { font-size: 15px; }
    .luca-visual { width: 220px; }
}

@media (max-width: 500px) {
    .luca-home { min-height: 100vh; padding: 18px 22px 26px; }
    .luca-content { grid-template-columns: 1fr; gap: 14px; padding-top: 28px; }
    .luca-copy h1 { font-size: 32px; }
    .luca-description { margin: 12px 0 20px; }
    .luca-start { width: 100%; min-height: 54px; }
    .luca-visual { width: 150px; margin: 0 auto; }
    .luca-device { width: 46px; height: 78px; border-width: 3px; border-radius: 10px; }
    .luca-device span { top: 6px; width: 13px; }
    .luca-device i { right: 7px; bottom: 8px; left: 7px; height: 29px; }
    .luca-check { width: 36px; height: 36px; border-width: 3px; }
    .luca-check span { top: 10px; left: 9px; width: 13px; height: 7px; border-width: 2px; }
}

@media (prefers-reduced-motion: reduce) {
    .luca-start { transition: none; }
}
</style>

<script>
import router from '../router'

export default {
    name: 'home',
    props: { saved_ssid: String, list_ssids: Array, internet: Boolean },
     data() {
        return {
            current_version: ""
        }
    },
    methods: {
        next: function() {
            var saved_ssid = this.saved_ssid
            var list_ssids = this.list_ssids
            var internet = this.internet
            if (window.config.iface_out.charAt(0) == 'e'){
                router.push({ name: 'generate-ap' });
            } else if (!window.config.choose_net && this.internet){
                router.push({ name: 'generate-ap' });
            } else {
                router.push({ name: 'wifi-select', 
                              params: { saved_ssid: saved_ssid, 
                                        list_ssids: list_ssids, 
                                        internet: internet } });
            }
        }
    },
    created: function() {
        if ('current_version' in window)
            this.current_version = window.current_version
    }
}
</script>
