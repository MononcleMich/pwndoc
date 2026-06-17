<template>
    <q-btn
    v-if="showButton"
    id="x10-generate-severity-chart"
    color="positive"
    no-caps
    class="q-mr-sm"
    :loading="loading"
    :disable="loading"
    @click="generateSeverityChart"
    >
        <span v-if="$q.screen.gt.sm">Generate Severity Chart</span>
        <q-icon v-else name="donut_large" />
        <q-tooltip anchor="bottom middle" self="center left" :delay="500" class="text-bold">
            Generate Severity Chart
        </q-tooltip>
    </q-btn>

    <q-dialog v-model="panelOpen">
        <q-card class="x10-severity-dialog">
            <q-card-section class="row items-center q-pb-sm">
                <div class="text-h6">Severity Chart Generated</div>
                <q-space />
                <q-btn v-close-popup flat round dense icon="close" />
            </q-card-section>

            <q-card-section class="q-pt-none">
                <div class="text-caption text-grey-8 q-mb-sm">
                    <div><strong>Audit:</strong> {{ chart.auditName || 'Current audit' }}</div>
                    <div><strong>Total findings:</strong> {{ chart.findingsCount }}</div>
                </div>

                <div class="row q-col-gutter-xs q-mb-md">
                    <div v-for="severity of severityOrder" :key="severity" class="col-auto">
                        <q-chip square dense>
                            <span
                            class="x10-severity-swatch"
                            :style="{ backgroundColor: severityColors[severity] }"
                            />
                            {{ severity }}: <strong>{{ chart.counts[severity] || 0 }}</strong>
                        </q-chip>
                    </div>
                </div>

                <img
                v-if="chart.chartUrl"
                class="x10-severity-preview"
                :src="chart.chartUrl"
                alt="Finding Severity Distribution"
                >
            </q-card-section>

            <q-card-actions align="right" class="q-gutter-sm">
                <q-btn color="primary" no-caps label="Insert into focused editor" @click="insertCurrentChart" />
                <q-btn color="secondary" outline no-caps label="Copy HTML" @click="copyCurrentHtml" />
                <q-btn color="secondary" outline no-caps label="Copy URL" @click="copyCurrentUrl" />
                <q-btn
                v-if="chart.chartUrl"
                color="secondary"
                outline
                no-caps
                label="Open chart"
                :href="chart.chartUrl"
                target="_blank"
                rel="noopener noreferrer"
                />
            </q-card-actions>
        </q-card>
    </q-dialog>
</template>

<script>
import { Notify } from 'quasar'
import AuditService from '@/services/audit'
import { Cvss4P0, Cvss3P1 } from 'ae-cvss-calculator'

const SEVERITY_ORDER = ['Informational', 'Low', 'Moderate', 'High', 'Critical']

const SEVERITY_COLORS = {
    Informational: '#36A2EB',
    Low: '#22C55E',
    Moderate: '#F1C40F',
    High: '#F77825',
    Critical: '#C0392B'
}

const PRIORITY_TO_SEVERITY = {
    0: 'Informational',
    1: 'Low',
    2: 'Moderate',
    3: 'High',
    4: 'Critical'
}

function createEmptyCounts() {
    return SEVERITY_ORDER.reduce((counts, severity) => {
        counts[severity] = 0
        return counts
    }, {})
}

export default {
    name: 'AuditSeverityChartButton',

    inject: {
        auditParent: {
            default: null
        }
    },

    data: function() {
        return {
            loading: false,
            panelOpen: false,
            lastEditor: null,
            severityOrder: SEVERITY_ORDER,
            severityColors: SEVERITY_COLORS,
            chart: {
                chartUrl: '',
                html: '',
                counts: createEmptyCounts(),
                findingsCount: 0,
                auditName: ''
            }
        }
    },

    computed: {
        auditId: function() {
            return this.$route?.params?.auditId || this.auditParent?._id || null
        },

        showButton: function() {
            return !!this.auditId
        }
    },

    mounted: function() {
        document.addEventListener('focusin', this.trackFocusedEditor, true)
    },

    beforeUnmount: function() {
        document.removeEventListener('focusin', this.trackFocusedEditor, true)
    },

    methods: {
        trackFocusedEditor: function(event) {
            if (!event.target?.closest)
                return

            const editor = event.target.closest('.ProseMirror[contenteditable="true"], [contenteditable="true"]')
            if (editor)
                this.lastEditor = editor
        },

        generateSeverityChart: async function() {
            this.loading = true

            try {
                const audit = await this.getAuditForChart()
                const findings = Array.isArray(audit.findings) ? audit.findings : []
                const counts = this.countSeverities(findings)
                const chartUrl = this.buildQuickChartUrl(counts, audit.name)

                this.chart = {
                    chartUrl,
                    html: this.makeEmbedHtml(chartUrl),
                    counts,
                    findingsCount: findings.length,
                    auditName: audit.name || ''
                }
                this.panelOpen = true
            }
            catch (err) {
                Notify.create({
                    message: `Could not generate severity chart: ${err.message}`,
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
            }
            finally {
                this.loading = false
            }
        },

        getAuditForChart: async function() {
            if (this.auditParent && Array.isArray(this.auditParent.findings))
                return this.auditParent

            const response = await AuditService.getAudit(this.auditId)
            return response.data.datas
        },

        emptyCounts: function() {
            return createEmptyCounts()
        },

        countSeverities: function(findings) {
            const counts = this.emptyCounts()

            for (const finding of findings || []) {
                const severity = this.normalizeSeverity(finding)
                counts[severity] += 1
            }

            return counts
        },

        normalizeSeverity: function(finding) {
            const cvssSeverity = this.normalizeCvssSeverity(finding)
            if (cvssSeverity)
                return cvssSeverity

            if (finding.priority !== undefined && finding.priority !== null) {
                const priority = Number(finding.priority)
                if (PRIORITY_TO_SEVERITY[priority])
                    return PRIORITY_TO_SEVERITY[priority]
            }

            const raw = finding.severity || finding.risk || finding.cvssSeverity || finding.priorityLabel || ''
            return this.normalizeSeverityLabel(raw) || 'Informational'
        },

        normalizeCvssSeverity: function(finding) {
            const scoringMethods = this.$settings?.report?.public?.scoringMethods || {}
            const shouldUseCvss4 = scoringMethods.CVSS4 !== false
            const shouldUseCvss3 = scoringMethods.CVSS3 !== false

            try {
                if (shouldUseCvss4 && finding.cvssv4)
                    return this.normalizeSeverityLabel(new Cvss4P0(finding.cvssv4).createJsonSchema().baseSeverity)

                if (shouldUseCvss3 && finding.cvssv3)
                    return this.normalizeSeverityLabel(new Cvss3P1(finding.cvssv3).createJsonSchema().baseSeverity)
            }
            catch (err) {
                return null
            }

            return null
        },

        normalizeSeverityLabel: function(value) {
            const severity = String(value || '').toLowerCase()

            if (severity.includes('critical') || severity.includes('urgent'))
                return 'Critical'
            if (severity.includes('high'))
                return 'High'
            if (severity.includes('medium') || severity.includes('moderate'))
                return 'Moderate'
            if (severity.includes('low'))
                return 'Low'
            if (severity.includes('none') || severity.includes('info'))
                return 'Informational'

            return null
        },

        buildQuickChartUrl: function(counts, auditName) {
            const labels = SEVERITY_ORDER
            const data = labels.map(label => counts[label] || 0)
            const colors = labels.map(label => SEVERITY_COLORS[label])

            const chartConfig = {
                type: 'doughnut',
                data: {
                    labels,
                    datasets: [{
                        data,
                        backgroundColor: colors,
                        borderColor: '#ffffff',
                        borderWidth: 3
                    }]
                },
                options: {
                    cutoutPercentage: 58,
                    legend: {
                        display: true,
                        position: 'bottom',
                        labels: {
                            fontColor: '#111827',
                            fontSize: 16,
                            padding: 18
                        }
                    },
                    title: {
                        display: true,
                        text: auditName
                            ? `${auditName} - Finding Severity Distribution`
                            : 'Finding Severity Distribution',
                        fontColor: '#111827',
                        fontSize: 24,
                        fontStyle: 'bold',
                        padding: 20
                    },
                    plugins: {
                        datalabels: {
                            color: '#111827',
                            font: {
                                weight: 'bold',
                                size: 18
                            },
                            formatter: 'function(value) { return value > 0 ? value : ""; }'
                        }
                    }
                }
            }

            return `https://quickchart.io/chart?width=900&height=620&backgroundColor=white&c=${encodeURIComponent(JSON.stringify(chartConfig))}`
        },

        makeEmbedHtml: function(chartUrl) {
            return `
<p style="text-align:center;">
  <img src="${chartUrl}" alt="Finding Severity Distribution" style="width:468px;max-width:100%;height:auto;">
</p>`.trim()
        },

        insertCurrentChart: function() {
            if (!this.lastEditor) {
                Notify.create({
                    message: 'Click inside the PwnDoc Severity Chart editor field first, then click Insert.',
                    color: 'warning',
                    textColor: 'white',
                    position: 'top-right'
                })
                return
            }

            this.lastEditor.focus()
            const inserted = document.execCommand('insertHTML', false, this.chart.html)

            try {
                this.lastEditor.dispatchEvent(new InputEvent('input', {
                    bubbles: true,
                    inputType: 'insertHTML',
                    data: this.chart.html
                }))
            }
            catch (err) {
                this.lastEditor.dispatchEvent(new Event('input', { bubbles: true }))
            }

            this.lastEditor.dispatchEvent(new Event('change', { bubbles: true }))

            Notify.create({
                message: inserted ? 'Inserted severity chart.' : 'Browser refused direct insert. Copy HTML and paste it into the editor source view.',
                color: inserted ? 'positive' : 'warning',
                textColor: 'white',
                position: 'top-right'
            })
        },

        copyCurrentHtml: function() {
            this.copyText(this.chart.html, 'Copied chart HTML.')
        },

        copyCurrentUrl: function() {
            this.copyText(this.chart.chartUrl, 'Copied chart URL.')
        },

        copyText: async function(text, message) {
            try {
                if (navigator.clipboard?.writeText) {
                    await navigator.clipboard.writeText(text)
                }
                else {
                    const textarea = document.createElement('textarea')
                    textarea.value = text
                    textarea.setAttribute('readonly', '')
                    textarea.style.position = 'fixed'
                    textarea.style.left = '-9999px'
                    document.body.appendChild(textarea)
                    textarea.select()
                    document.execCommand('copy')
                    textarea.remove()
                }

                Notify.create({
                    message,
                    color: 'positive',
                    textColor: 'white',
                    position: 'top-right'
                })
            }
            catch (err) {
                Notify.create({
                    message: `Could not copy: ${err.message}`,
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
            }
        }
    }
}
</script>

<style scoped>
.x10-severity-dialog {
    width: 560px;
    max-width: calc(100vw - 32px);
}

.x10-severity-swatch {
    display: inline-block;
    width: 10px;
    height: 10px;
    margin-right: 6px;
}

.x10-severity-preview {
    width: 100%;
    max-width: 468px;
    display: block;
    margin: 0 auto;
    border: 1px solid #e5e7eb;
    background: #ffffff;
}
</style>
