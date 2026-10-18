<template>
    <div class="luca-splash">
        <div class="luca-splash-brand">
            <span class="luca-splash-mark" aria-hidden="true"><i></i><i></i><i></i></span>
            <span>Luca</span>
        </div>
        <div class="loading loading-lg loadingsplash" aria-label="Loading"></div>
    </div>
</template>

<script>
    import router from '../router'
    import axios from 'axios'

    export default {
        name: 'splash-screen',
        components: {},
        data() {
            return {
                list_ssids: [],
                internet: false
            }
        },
        methods: {
            internet_check: function() {
                axios.get('/api/network/status', { timeout: 30000 })
                    .then(response => {
                        if (response.data.internet) this.internet = true
                        if (window.config.iface_out.charAt(0) == 'e') {
                            setTimeout(function () { this.goto_home(); }.bind(this), 1000);
                        } else {
                            this.get_wifi_networks();
                        }
                    })
                    .catch(err => (console.log(err)))
            },
            get_wifi_networks: function() {
                axios.get('/api/network/wifi/list', { timeout: 30000 })
                    .then(response => { 
                        this.list_ssids = response.data.networks
                        this.goto_home();
                     })
                    .catch(err => (console.log(err)))
            },
            delete_captures: function() {
                axios.get('/api/misc/delete-captures', { timeout: 30000 })
                    .catch(err => (console.log(err)))
            }, 
            goto_home: function() {
                var list_ssids = this.list_ssids
                var internet   = this.internet
                router.replace({ name: 'home', params: { list_ssids: list_ssids, internet: internet } });
            }
        },
        created: function() {
            this.delete_captures();
            setTimeout(function () { this.internet_check(); }.bind(this), 5000);
        }
    }
</script>

<style scoped>
.luca-splash {
    position: absolute;
    top: 50%;
    left: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 28px;
    color: #182b2a;
    transform: translate(-50%, -50%);
}

.luca-splash-brand {
    display: flex;
    align-items: center;
    gap: 14px;
    font-family: "Roboto-Bold", sans-serif;
    font-size: 48px;
}

.luca-splash-mark {
    width: 52px;
    height: 52px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 4px;
    border-radius: 14px;
    background: #187a62;
}

.luca-splash-mark i { width: 4px; border-radius: 4px; background: #fff; }
.luca-splash-mark i:nth-child(1) { height: 14px; }
.luca-splash-mark i:nth-child(2) { height: 25px; }
.luca-splash-mark i:nth-child(3) { height: 19px; }

@media (max-width: 500px) {
    .luca-splash-brand { font-size: 38px; }
}
</style>
