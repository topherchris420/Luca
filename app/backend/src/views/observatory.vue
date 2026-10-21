<template>
    <div class="backend-content" id="content">
        <div class="column col-10 col-xs-12">
            <h3 class="s-title">Kernel Observatory</h3>
            <p class="obs-intro">
                Kernel-level observations of the access point interface, correlated with the capture.
                Every statement is labelled
                <span class="prov prov-observed">observed</span>
                <span class="prov prov-correlated">correlated</span>
                <span class="prov prov-inferred">inferred</span>
                <span class="prov prov-unavailable">unavailable</span>.
            </p>

            <h5 class="s-subtitle">Status and compatibility</h5>
            <div v-if="status_error" class="toast toast-error">{{ status_error }}</div>
            <table class="table table-striped" v-if="status">
                <tbody>
                    <tr>
                        <td>Configuration</td>
                        <td>
                            <span v-if="status.status == 'not_installed'">observatory/ is not installed</span>
                            <span v-else-if="status.enabled">enabled (observatory.enabled: true)</span>
                            <span v-else>disabled &mdash; set observatory.enabled to true and install the
                                luca-observatory service to collect kernel telemetry</span>
                            <ul v-if="status.config_problems && status.config_problems.length" class="obs-list">
                                <li v-for="p in status.config_problems" :key="p">{{ p }}</li>
                            </ul>
                        </td>
                    </tr>
                    <tr v-if="status.status != 'not_installed'">
                        <td>Collector service</td>
                        <td>
                            <span v-if="status.status == 'available'">running (version {{ status.service.version }})</span>
                            <span v-else-if="status.status == 'disabled'">not used</span>
                            <span v-else>unavailable: {{ status.error }}
                                <br /><small>The service reads its settings when it starts: after changing them, run
                                sudo systemctl restart luca-observatory.</small></span>
                        </td>
                    </tr>
                    <tr v-if="status.status != 'not_installed'">
                        <td>Interface</td>
                        <td>
                            {{ status.configured_interface || '--' }}
                            <span v-if="status.interface_problem"> &mdash; {{ status.interface_problem }}</span>
                        </td>
                    </tr>
                    <tr v-if="caps">
                        <td>Host</td>
                        <td>Linux {{ caps.kernel }} ({{ caps.machine }}),
                            kernel BTF {{ caps.btf ? 'present' : 'absent' }}<span v-if="caps.lockdown">,
                            lockdown {{ caps.lockdown }}</span>
                            <span v-if="caps.reason"> &mdash; {{ caps.reason }}</span>
                            <ul v-if="caps.problems && caps.problems.length" class="obs-list">
                                <li v-for="p in caps.problems" :key="p">{{ p }}</li>
                            </ul>
                        </td>
                    </tr>
                    <tr v-if="caps && caps.features">
                        <td>Expected features</td>
                        <td>
                            <span v-for="(v, k) in caps.features" :key="k" class="obs-feature">
                                {{ k.replace('_', ' ') }}: <strong>{{ v }}</strong>
                            </span>
                            <br /><small>Predicted from the kernel version and configuration. Only a
                            session's attach result proves that a feature works.</small>
                        </td>
                    </tr>
                </tbody>
            </table>

            <h5 class="s-subtitle">Session</h5>
            <div class="form-group obs-row">
                <select class="form-select obs-select" v-model="selected" @change="load_session()">
                    <option value="">Select a capture session</option>
                    <option v-for="s in sessions" :key="s.token" :value="s.token">
                        {{ s.token }} &mdash; {{ format_time(s.mtime) }} &mdash; {{ s.status }}{{ s.analysed ? '' : ' (not analysed yet)' }}
                    </option>
                </select>
                <button class="btn" v-on:click="load_example()">Show offline example</button>
            </div>
            <div v-if="!sessions.length && !summary" class="empty obs-empty">
                <p class="empty-title h5">No session with kernel telemetry.</p>
                <p class="empty-subtitle">Sessions appear here after a capture made with the observatory enabled.
                    The offline example shows the layout with synthetic data.</p>
            </div>
            <div v-if="session_message" class="toast">{{ session_message }}</div>

            <div v-if="summary">
                <div v-if="example" class="toast toast-warning obs-banner">
                    <strong>OFFLINE EXAMPLE &mdash; synthetic data, not a measurement.</strong>
                    It was computed from the fixtures in observatory/tests and only illustrates this view.
                </div>

                <table class="table table-striped">
                    <tbody>
                        <tr><td>Telemetry source</td>
                            <td>eBPF classifiers on {{ col.interface || '--' }} ({{ col.attach_mode || 'not attached' }}),
                                kernel drop events {{ col.drop_tracepoint || '--' }}; capture on {{ col.capture_interface || '--' }}</td></tr>
                        <tr><td>Collection status</td>
                            <td>{{ col.status }}<span v-if="col.error"> &mdash; {{ col.error }}</span></td></tr>
                        <tr><td>Kernel</td>
                            <td>Linux {{ col.kernel || '--' }} ({{ col.machine || '--' }}),
                                collector {{ col.generator ? col.generator.version + ' @ ' + col.generator.commit : '--' }}</td></tr>
                        <tr v-if="col.window"><td>Window</td>
                            <td>{{ format_time(col.window.start) }} &rarr; {{ format_time(col.window.end) }}
                                <span v-if="col.clock && col.clock.uncertainty_s != null">
                                    (wall-clock drift {{ col.clock.uncertainty_s.toFixed(6) }} s)</span></td></tr>
                        <tr v-if="summary.coverage"><td>Capture completeness</td>
                            <td><strong>{{ summary.coverage.assessment }}</strong> &mdash; {{ summary.coverage.explanation }}
                                <span v-for="(d, k) in summary.coverage.directions" :key="k" class="obs-feature">
                                    {{ k }}: captured {{ d.captured }}, kernel {{ d.kernel_lower }}&ndash;{{ d.kernel_upper == null ? '?' : d.kernel_upper }}
                                </span></td></tr>
                    </tbody>
                </table>

                <h5 class="s-subtitle">Flow statistics</h5>
                <div v-if="stats">
                    <table class="table table-striped">
                        <thead><tr><th></th><th>Socket buffers</th><th>Segments</th><th>Bytes</th><th>IPv4</th><th>IPv6</th><th>Matching capture filter</th></tr></thead>
                        <tbody>
                            <tr v-for="d in ['tx', 'rx']" :key="d">
                                <td>{{ d == 'tx' ? 'device → network' : 'network → device' }}</td>
                                <td>{{ stats.totals[d].skbs }}</td><td>{{ stats.totals[d].segments }}</td>
                                <td>{{ stats.totals[d].bytes }}</td><td>{{ stats.totals[d].ipv4 }}</td>
                                <td>{{ stats.totals[d].ipv6 }}</td><td>{{ stats.totals[d].pcap_filter_skbs }}</td>
                            </tr>
                        </tbody>
                    </table>
                    <p class="obs-intro">{{ stats.flows }} flow(s); TCP: {{ stats.tcp.handshakes_completed }} handshake(s) completed,
                        {{ stats.tcp.syn_without_synack }} SYN without SYN-ACK, {{ stats.tcp.rst_seen }} with RST,
                        {{ stats.tcp.retrans_or_reorder }} retransmitted-or-reordered segment(s)<span v-if="stats.tcp.synack_after_ms_median != null">,
                        median SYN&rarr;SYN-ACK {{ stats.tcp.synack_after_ms_median }} ms</span>; {{ stats.drops }} kernel drop(s).</p>
                    <table class="table table-striped">
                        <thead><tr><th>Protocol</th><th>Packets out</th><th>Packets in</th><th>Bytes</th></tr></thead>
                        <tbody>
                            <tr v-for="p in stats.protocols" :key="p.proto">
                                <td>{{ p.name }}</td><td>{{ p.tx_packets }}</td><td>{{ p.rx_packets }}</td><td>{{ p.bytes }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <p v-else>No kernel flow statistics: telemetry unavailable.</p>

                <h5 class="s-subtitle">Correlated observations</h5>
                <div class="obs-row">
                    <button v-for="f in filters" :key="f" class="btn btn-sm" :class="{ 'btn-primary': filter == f }"
                            v-on:click="filter = f">{{ f }} ({{ f == 'ALL' ? observations.length : (summary.labels[f] || 0) }})</button>
                </div>
                <p class="obs-intro">
                    {{ summary.counts.corroborated }} corroborated, {{ summary.counts.single_source }} single-source,
                    {{ summary.counts.uncertain }} uncertain, {{ summary.counts.inferred }} inferred,
                    {{ summary.counts.missing }} missing-telemetry statement(s).
                    <span v-if="summary.observations_truncated">Only the first {{ observations.length }} are included.</span>
                </p>
                <table class="table table-hover">
                    <thead><tr><th>Provenance</th><th>Category</th><th>Statement</th><th>Evidence</th></tr></thead>
                    <tbody>
                        <template v-for="o in shown">
                            <tr :key="o.id">
                                <td><span class="prov" :class="'prov-' + o.label.toLowerCase()">{{ o.label }}</span></td>
                                <td class="obs-category">{{ o.category.replace('_', ' ') }}</td>
                                <td>{{ o.statement }}
                                    <ul v-if="o.reasons.length" class="obs-list"><li v-for="r in o.reasons" :key="r">{{ r }}</li></ul></td>
                                <td><button class="btn btn-sm" v-on:click="toggle(o.id)">{{ open[o.id] ? 'hide' : o.evidence.length }}</button></td>
                            </tr>
                            <tr v-if="open[o.id]" :key="o.id + '-ev'">
                                <td colspan="4"><pre class="obs-evidence">{{ JSON.stringify(o.evidence, null, 2) }}</pre></td>
                            </tr>
                        </template>
                    </tbody>
                </table>
                <button v-if="shown.length < filtered.length" class="btn btn-sm" v-on:click="limit += 50">Show more</button>

                <h5 class="s-subtitle">Overhead and lost events</h5>
                <table class="table table-striped" v-if="col.health || col.loss">
                    <tbody>
                        <tr v-if="col.health"><td>Collector process</td>
                            <td>{{ col.health.collector_cpu_seconds }} s CPU, {{ col.health.collector_max_rss_kb }} kB max RSS,
                                {{ col.health.map_memlock_bytes }} B of BPF maps</td></tr>
                        <tr v-if="col.health"><td>BPF run time</td>
                            <td><span v-if="col.health.prog_stats && col.health.prog_stats.enabled">
                                <span v-for="p in col.health.prog_stats.programs" :key="p.name" class="obs-feature">
                                    {{ p.name }}: {{ p.run_cnt ? (p.run_time_ns / p.run_cnt).toFixed(0) : 0 }} ns/run over {{ p.run_cnt }} runs</span></span>
                                <span v-else>not measured ({{ (col.health.prog_stats && col.health.prog_stats.note) || 'needs --prog-stats' }})</span></td></tr>
                        <tr v-if="col.health"><td>Tables</td>
                            <td>flows {{ col.health.flow_entries }} / {{ col.health.flow_capacity }},
                                drop keys {{ col.health.drop_entries }} / {{ col.health.drop_capacity }}</td></tr>
                        <tr v-if="col.loss"><td>Lost or truncated telemetry</td>
                            <td>{{ col.loss.flows_not_recorded }} packet(s) not attributed to flows,
                                {{ col.loss.drops_not_keyed }} drop event(s) not keyed, {{ col.loss.parse_errors }} parse error(s),
                                timeline {{ col.loss.timeline_truncated ? 'truncated' : 'complete' }},
                                {{ col.loss.snapshot_failures }} failed snapshot write(s)</td></tr>
                    </tbody>
                </table>
                <p v-else>No collector health data.</p>

                <h5 class="s-subtitle">Confidence and limitations</h5>
                <ul class="obs-list">
                    <li v-for="l in summary.limitations" :key="l">{{ l }}</li>
                </ul>
                <p class="obs-intro"><strong>Conclusions this evidence does not support</strong></p>
                <ul class="obs-list">
                    <li v-for="u in summary.unsupported" :key="u.conclusion"><strong>{{ u.conclusion }}</strong>: {{ u.reason }}</li>
                </ul>

                <h5 class="s-subtitle">Export</h5>
                <p v-if="example">The offline example cannot be exported as evidence.</p>
                <p v-else><a class="btn btn-primary" :href="export_url">Download evidence bundle</a>
                    snapshot, session record, summary and a manifest with SHA-256 digests (the pcap is referenced, not included).</p>
            </div>

            <h5 class="s-subtitle">Experiment results</h5>
            <div v-if="results.length">
                <table class="table table-striped">
                    <thead><tr><th>Run</th><th>Environment</th><th>Experiments</th></tr></thead>
                    <tbody>
                        <tr v-for="r in results" :key="r.file">
                            <td>{{ r.file }}</td>
                            <td>{{ r.environment ? r.environment.description : '--' }}</td>
                            <td><span v-for="(e, k) in r.experiments" :key="k" class="obs-feature">{{ k }}: <strong>{{ e.verdict }}</strong></span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <p v-else class="obs-intro">No experiment results on this host. Run observatory/experiments/run_experiments.py
                as root on Linux to produce them; none are shipped with Luca.</p>
        </div>
    </div>
</template>

<script>
import axios from 'axios'

export default {
    name: 'observatory',
    data() {
        return {
            jwt: "",
            status: null,
            status_error: "",
            sessions: [],
            selected: "",
            summary: null,
            example: false,
            session_message: "",
            filters: ["ALL", "OBSERVED", "CORRELATED", "INFERRED", "UNAVAILABLE"],
            filter: "ALL",
            limit: 50,
            open: {},
            results: []
        }
    },
    computed: {
        caps: function() { return this.status ? this.status.capabilities : null },
        col: function() { return (this.summary && this.summary.collection) || {} },
        stats: function() { return this.summary ? this.summary.statistics : null },
        observations: function() { return (this.summary && this.summary.observations) || [] },
        filtered: function() {
            return this.filter == "ALL" ? this.observations : this.observations.filter(o => o.label == this.filter)
        },
        shown: function() { return this.filtered.slice(0, this.limit) },
        export_url: function() { return `/api/observatory/export/${this.selected}?token=${this.jwt}` }
    },
    methods: {
        headers: function() { return { headers: { "X-Token": this.jwt }, timeout: 30000 } },
        format_time: function(t) { return t ? new Date(t * 1000).toLocaleString() : "--" },
        toggle: function(id) { this.$set(this.open, id, !this.open[id]) },
        reset: function(summary, example) {
            this.summary = summary
            this.example = example
            this.filter = "ALL"
            this.limit = 50
            this.open = {}
        },
        load_status: function() {
            axios.get(`/api/observatory/status`, this.headers())
                .then(response => { this.status = response.data })
                .catch(err => { this.status_error = "Status unavailable: " + err })
        },
        load_sessions: function() {
            axios.get(`/api/observatory/sessions`, this.headers())
                .then(response => { this.sessions = response.data.sessions || [] })
                .catch(err => (console.log(err)))
        },
        load_results: function() {
            axios.get(`/api/observatory/experiments`, this.headers())
                .then(response => { this.results = response.data.results || [] })
                .catch(err => (console.log(err)))
        },
        load_session: function() {
            this.session_message = ""
            if (!this.selected) { this.reset(null, false); return }
            axios.get(`/api/observatory/session/${this.selected}`, this.headers())
                .then(response => {
                    if (response.data.status) { this.reset(response.data.summary, false) }
                    else { this.reset(null, false); this.session_message = response.data.message }
                })
                .catch(err => { this.session_message = "Session unavailable: " + err })
        },
        load_example: function() {
            this.selected = ""
            this.session_message = ""
            axios.get(`/api/observatory/example`, this.headers())
                .then(response => {
                    if (response.data.status && response.data.synthetic) { this.reset(response.data.summary, true) }
                    else { this.session_message = response.data.message }
                })
                .catch(err => { this.session_message = "Example unavailable: " + err })
        },
        async get_jwt() {
            await axios.get(`/api/get-token`, { timeout: 10000 })
                .then(response => {
                    if (response.data.token) {
                        this.jwt = response.data.token
                    }
                })
                .catch(err => (console.log(err)))
        }
    },
    created: function() {
        this.get_jwt().then(() => {
            this.load_status()
            this.load_sessions()
            this.load_results()
        });
    }
}
</script>

<style scoped>
    .obs-intro { font-size: .8rem; color: #555; }
    .s-subtitle { margin-top: 1.6rem; }
    .obs-row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; margin-bottom: .6rem; }
    .obs-select { max-width: 32rem; }
    .obs-empty { margin-top: .5rem; }
    .obs-banner { margin-bottom: .8rem; }
    .obs-list { margin: .2rem 0 .2rem 1rem; font-size: .75rem; }
    .obs-feature { display: inline-block; margin-right: 1rem; }
    .obs-category { text-transform: capitalize; white-space: nowrap; }
    .obs-evidence { max-height: 20rem; overflow: auto; font-size: .65rem; background: #fafafa; padding: .5rem; }
    .prov {
        font-size: .6rem;
        padding: .05rem .3rem;
        line-height: 1.2rem;
        text-transform: uppercase;
        font-weight: bold;
        vertical-align: middle;
        border-radius: .1rem;
        border: 2px solid transparent;
        white-space: nowrap;
    }
    .prov-observed { background-color: #2f6fdb; border-color: #2a62c2; color: #FFF; }
    .prov-correlated { background-color: #199a09cf; border-color: #0f8600cf; color: #FFF; }
    .prov-inferred { background-color: #ffc000cf; border-color: #ffc000cf; color: #3b2c00; }
    .prov-unavailable { background-color: #FFF; border-color: #cfcfcf; color: #666; }
</style>
