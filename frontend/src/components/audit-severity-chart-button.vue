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
                <div class="text-h6">PwnDoc Charts Generated</div>
                <q-space />
                <q-btn v-close-popup flat round dense icon="close" />
            </q-card-section>

            <q-card-section class="q-pt-none">
                <div class="text-caption text-grey-8 q-mb-sm">
                    <div><strong>Audit:</strong> {{ chart.auditName || 'Current audit' }}</div>
                    <div><strong>Total findings:</strong> {{ chart.findingsCount }}</div>
                    <div><strong>Default difficulty used:</strong> {{ chart.defaultEffortCount }}</div>
                </div>

                <q-btn-toggle
                v-model="chartMode"
                dense
                no-caps
                spread
                class="q-mb-md full-width"
                toggle-color="primary"
                color="white"
                text-color="primary"
                :options="chartModeOptions"
                />

                <div v-if="chartMode === 'severity'" class="row q-col-gutter-xs q-mb-md">
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
                v-if="currentChart.chartUrl"
                class="x10-severity-preview"
                :class="{ 'x10-matrix-preview': chartMode === 'matrix' }"
                :src="currentChart.chartUrl"
                :alt="currentChart.alt"
                >
            </q-card-section>

            <q-card-actions align="right" class="q-gutter-sm">
                <q-btn color="primary" no-caps label="Insert into focused editor" @click="insertCurrentChart" />
                <q-btn color="secondary" outline no-caps label="Copy HTML" @click="copyCurrentHtml" />
                <q-btn color="secondary" outline no-caps label="Copy URL" @click="copyCurrentUrl" />
                <q-btn
                v-if="currentChart.chartUrl"
                color="secondary"
                outline
                no-caps
                label="Open chart"
                :href="currentChart.chartUrl"
                target="_blank"
                rel="noopener noreferrer"
                />
            </q-card-actions>
        </q-card>
    </q-dialog>
</template>

<script>
import { Notify } from 'quasar'
import { Cvss4P0, Cvss3P1 } from 'ae-cvss-calculator'

const SEVERITY_ORDER = ['Informational', 'Low', 'Moderate', 'High', 'Critical']

const SEVERITY_COLORS = {
    Informational: '#36A2EB',
    Low: '#22C55E',
    Moderate: '#F1C40F',
    High: '#F77825',
    Critical: '#C0392B'
}

const MATRIX_QUADS = [
    { name: 'Quick-wins', color: 'rgba(34, 197, 94, 0.30)' },
    { name: 'High Priority', color: 'rgba(239, 68, 68, 0.28)' },
    { name: 'Medium Priority', color: 'rgba(249, 115, 22, 0.24)' },
    { name: 'Low Priority', color: 'rgba(100, 116, 139, 0.18)' }
]

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
            chartMode: 'severity',
            chartModeOptions: [
                { label: 'Severity Chart', value: 'severity' },
                { label: 'Priority Matrix', value: 'matrix' }
            ],
            lastEditor: null,
            lastEditorComponent: null,
            severityOrder: SEVERITY_ORDER,
            severityColors: SEVERITY_COLORS,
            chart: {
                charts: {
                    severity: {
                        chartUrl: '',
                        html: '',
                        alt: 'Finding Severity Distribution'
                    },
                    matrix: {
                        chartUrl: '',
                        html: '',
                        alt: 'Action Priority Matrix'
                    }
                },
                counts: createEmptyCounts(),
                findingsCount: 0,
                auditName: '',
                defaultEffortCount: 0
            }
        }
    },

    computed: {
        auditId: function() {
            return this.$route?.params?.auditId || this.auditParent?._id || null
        },

        showButton: function() {
            return !!this.auditId
        },

        currentChart: function() {
            return this.chart.charts?.[this.chartMode] || this.chart.charts.severity
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
            if (editor) {
                this.lastEditor = editor
                this.lastEditorComponent = this.findBasicEditorComponent(editor)
            }
        },

        findBasicEditorComponent: function(element) {
            let node = element
            while (node) {
                let component = node.__vueParentComponent
                while (component) {
                    const proxy = component.proxy
                    if (proxy?.editor?.commands && typeof proxy.updateHTML === 'function')
                        return proxy

                    component = component.parent
                }

                node = node.parentElement
            }

            return null
        },

        generateSeverityChart: async function() {
            this.loading = true

            try {
                const audit = await this.getAuditForChart()
                const findings = Array.isArray(audit.findings) ? audit.findings : []
                if (!findings.length)
                    throw new Error('No findings found in this audit.')

                const counts = this.countSeverities(findings)
                const companyName = this.getCompanyName(audit)
                const severityUrl = this.buildSeverityPieDataUrl(companyName || audit.name || 'Current audit', 'Findings Severity Chart', counts)
                const matrix = this.getMatrixFindings(findings)
                const matrixUrl = this.buildPriorityMatrixDataUrl('Action Priority Matrix', matrix.findings)

                this.chart = {
                    charts: {
                        severity: {
                            chartUrl: severityUrl,
                            html: this.makeEmbedHtml(severityUrl, 'Finding Severity Distribution', '468px'),
                            alt: 'Finding Severity Distribution'
                        },
                        matrix: {
                            chartUrl: matrixUrl,
                            html: this.makeEmbedHtml(matrixUrl, 'Action Priority Matrix', '700px'),
                            alt: 'Action Priority Matrix'
                        }
                    },
                    counts,
                    findingsCount: findings.length,
                    auditName: audit.name || '',
                    defaultEffortCount: matrix.defaultEffortCount
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

            const { default: AuditService } = await import('@/services/audit')
            const response = await AuditService.getAudit(this.auditId)
            return response.data.datas
        },

        getCompanyName: function(audit) {
            const auditCompany = String(audit?.company?.name || '').trim()
            if (auditCompany)
                return auditCompany

            const companyInput = document.querySelector('input[aria-label="Company"]')
            const companyField = companyInput?.closest('.q-field__native')
            const visibleCompany = String(companyField?.querySelector('span')?.textContent || '').trim()
            if (visibleCompany)
                return visibleCompany

            return ''
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
            const cvss = this.getFindingCvssData(finding)
            return this.normalizeSeverityLabel(cvss.baseSeverity) || 'Informational'
        },

        normalizeSeverityLabel: function(value) {
            const severity = String(value || '').toLowerCase()

            if (severity.includes('critical'))
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

        getFindingCvssData: function(finding) {
            const scoringMethods = this.$settings?.report?.public?.scoringMethods || {}
            const shouldUseCvss4 = scoringMethods.CVSS4 !== false
            const shouldUseCvss3 = scoringMethods.CVSS3 !== false

            try {
                if (shouldUseCvss4 && finding.cvssv4) {
                    const cvss = new Cvss4P0(finding.cvssv4).createJsonSchema()
                    return {
                        baseScore: Number.isFinite(Number(cvss.baseScore)) ? Number(cvss.baseScore) : null,
                        baseSeverity: cvss.baseSeverity || ''
                    }
                }

                if (shouldUseCvss3 && finding.cvssv3) {
                    const cvss = new Cvss3P1(finding.cvssv3).createJsonSchema()
                    return {
                        baseScore: Number.isFinite(Number(cvss.baseScore)) ? Number(cvss.baseScore) : null,
                        baseSeverity: cvss.baseSeverity || ''
                    }
                }
            }
            catch (err) {
                return { baseScore: null, baseSeverity: '' }
            }

            return { baseScore: null, baseSeverity: '' }
        },

        buildSeverityPieDataUrl: function(title, subtitle, counts) {
            const canvas = document.createElement('canvas')
            canvas.width = 900
            canvas.height = 620

            const ctx = canvas.getContext('2d')
            if (!ctx)
                throw new Error('Canvas rendering is not available in this browser.')

            const values = SEVERITY_ORDER.map(severity => counts[severity] || 0)
            const total = values.reduce((sum, value) => sum + value, 0)
            const centerX = canvas.width / 2
            const centerY = 310
            const radius = 175

            ctx.fillStyle = '#ffffff'
            ctx.fillRect(0, 0, canvas.width, canvas.height)

            if (title) {
                ctx.fillStyle = '#111111'
                ctx.font = 'bold 26px Arial'
                ctx.textAlign = 'center'
                ctx.textBaseline = 'middle'
                ctx.fillText(title, canvas.width / 2, 42)
            }

            if (subtitle) {
                ctx.fillStyle = '#444444'
                ctx.font = 'bold 24px Arial'
                ctx.textAlign = 'center'
                ctx.textBaseline = 'middle'
                ctx.fillText(subtitle, canvas.width / 2, 74)
            }

            let start = -Math.PI / 2
            values.forEach((value, index) => {
                if (value <= 0 || total <= 0)
                    return

                const end = start + (value / total) * Math.PI * 2
                ctx.beginPath()
                ctx.moveTo(centerX, centerY)
                ctx.arc(centerX, centerY, radius, start, end)
                ctx.closePath()
                ctx.fillStyle = SEVERITY_COLORS[SEVERITY_ORDER[index]]
                ctx.fill()
                ctx.lineWidth = 2
                ctx.strokeStyle = '#ffffff'
                ctx.stroke()

                const middle = (start + end) / 2
                const labelX = centerX + Math.cos(middle) * (radius * 0.62)
                const labelY = centerY + Math.sin(middle) * (radius * 0.62)
                ctx.fillStyle = '#111111'
                ctx.font = 'bold 20px Arial'
                ctx.textAlign = 'center'
                ctx.textBaseline = 'middle'
                ctx.fillText(String(value), labelX, labelY)

                start = end
            })

            const legendY = 555
            const legendGap = 28
            ctx.font = 'bold 13px Arial'
            ctx.textAlign = 'left'
            ctx.textBaseline = 'middle'
            const legendItems = SEVERITY_ORDER.map(severity => ({
                severity,
                width: 18 + 10 + ctx.measureText(severity).width
            }))
            const totalLegendWidth = legendItems.reduce((sum, item) => sum + item.width, 0) + (legendItems.length - 1) * legendGap
            let legendX = (canvas.width - totalLegendWidth) / 2

            legendItems.forEach(({ severity, width }) => {
                ctx.fillStyle = SEVERITY_COLORS[severity]
                ctx.fillRect(legendX, legendY - 9, 18, 18)
                ctx.fillStyle = '#111111'
                ctx.fillText(severity, legendX + 28, legendY)
                legendX += width + legendGap
            })

            return canvas.toDataURL('image/png')
        },

        getCvssNumeric: function(finding) {
            const cvss = this.getFindingCvssData(finding)
            if (cvss.baseScore === null)
                return null

            return Math.max(1, Math.min(10, cvss.baseScore))
        },

        normalizeRangeToTen: function(value, min, max) {
            if (!Number.isFinite(value))
                return null

            const normalized = 1 + ((value - min) * 9 / (max - min))
            return Math.max(1, Math.min(10, normalized))
        },

        priorityToEffortPoint: function(value) {
            const label = String(value || '').toLowerCase()
            if (label.includes('low'))
                return 4
            if (label.includes('medium') || label.includes('moderate'))
                return 3
            if (label.includes('high'))
                return 2
            if (label.includes('urgent') || label.includes('critical'))
                return 1

            const numericValue = Number(value)
            if (numericValue === 4)
                return 1
            if (numericValue === 3)
                return 2
            if (numericValue === 2)
                return 3
            if (numericValue === 1)
                return 4

            return null
        },

        getEffortPriorityScore: function(finding, remediationEffort) {
            const priorityPoint = this.priorityToEffortPoint(finding.priority) || 2.5
            const rawEffortScore = remediationEffort + priorityPoint

            return Number(this.normalizeRangeToTen(rawEffortScore, 2, 7).toFixed(1))
        },

        remediationDifficultyToEffort: function(value) {
            const label = String(value || '').toLowerCase()
            if (label.includes('easy') || label.includes('low'))
                return 1
            if (label.includes('medium') || label.includes('moderate'))
                return 2
            if (label.includes('complex') || label.includes('difficult') || label.includes('hard') || label.includes('high'))
                return 3

            const numericValue = Number(value)
            if (!Number.isFinite(numericValue))
                return null

            if (numericValue >= 1 && numericValue <= 3)
                return numericValue

            return null
        },

        getRemediationDifficulty: function(finding) {
            const directValue = this.remediationDifficultyToEffort(finding.remediationComplexity)
            if (directValue !== null)
                return { effort: directValue, defaulted: false }

            const customFields = Array.isArray(finding.customFields) ? finding.customFields : []
            for (const item of customFields) {
                const label = String(item?.customField?.label || '').toLowerCase()
                if (!label.includes('remediation'))
                    continue

                if (label.includes('difficulty') || label.includes('effort') || label.includes('complex')) {
                    const fieldValue = this.remediationDifficultyToEffort(item?.text)
                    if (fieldValue !== null)
                        return { effort: fieldValue, defaulted: false }
                }
            }

            return { effort: 2, defaulted: true }
        },

        getShortLabel: function(finding, index) {
            const title = String(finding.title || '').trim()
            const prefixMatch = title.match(/\b([A-Z]{2,5}-\d+)\b/i)
            if (prefixMatch)
                return prefixMatch[1].toUpperCase()

            const category = String(finding.category || '').toLowerCase()
            let prefix = 'FIND'
            if (category.startsWith('int'))
                prefix = 'INT'
            else if (category.startsWith('ext'))
                prefix = 'EXT'
            else if (category.startsWith('sum'))
                prefix = 'SUM'

            const identifier = Number.isFinite(Number(finding.identifier)) ? Number(finding.identifier) : (index + 1)
            return `${prefix}-${identifier}`
        },

        getMatrixFindings: function(findings) {
            let defaultEffortCount = 0
            const matrixFindings = findings.map((finding, index) => {
                const difficulty = this.getRemediationDifficulty(finding)
                if (difficulty.defaulted)
                    defaultEffortCount += 1

                return {
                    name: this.getShortLabel(finding, index),
                    cvss: this.getCvssNumeric(finding) || 1.0,
                    effort: this.getEffortPriorityScore(finding, difficulty.effort)
                }
            })

            return {
                findings: matrixFindings,
                defaultEffortCount
            }
        },

        wrapText: function(text, maxChars) {
            const words = String(text || '').split(/\s+/).filter(Boolean)
            const lines = []
            let line = ''

            for (const word of words) {
                const test = line ? `${line} ${word}` : word
                if (test.length > maxChars) {
                    if (line)
                        lines.push(line)
                    line = word
                }
                else {
                    line = test
                }
            }

            if (line)
                lines.push(line)

            return lines
        },

        valueToX: function(value, plot) {
            return plot.x + ((value - 1) / 9) * plot.w
        },

        valueToY: function(value, plot) {
            return plot.y + plot.h - ((value - 1) / 9) * plot.h
        },

        applyMatrixOffsets: function(points) {
            const byCell = new Map()
            points.forEach(point => {
                const key = `${Math.round(point.finding.effort)}:${Math.round(point.finding.cvss)}`
                if (!byCell.has(key))
                    byCell.set(key, [])
                byCell.get(key).push(point)
            })

            for (const group of byCell.values()) {
                if (group.length <= 1)
                    continue

                const offsets = [[0, 0], [22, -16], [-22, 16], [22, 16], [-22, -16], [0, -28], [0, 28]]
                group.forEach((point, index) => {
                    const offset = offsets[index % offsets.length]
                    point.x += offset[0]
                    point.y += offset[1]
                })
            }
        },

        drawLegendSquare: function(ctx, x, y, color, label) {
            ctx.save()
            ctx.fillStyle = color
            ctx.strokeStyle = 'rgba(15,23,42,0.16)'
            ctx.lineWidth = 2
            ctx.fillRect(x, y - 15, 38, 26)
            ctx.strokeRect(x, y - 15, 38, 26)
            ctx.fillStyle = '#475467'
            ctx.font = '20px Arial'
            ctx.textAlign = 'left'
            ctx.textBaseline = 'middle'
            ctx.fillText(label, x + 50, y - 2)
            ctx.restore()
        },

        buildPriorityMatrixDataUrl: function(title, findings) {
            const canvas = document.createElement('canvas')
            canvas.width = 1200
            canvas.height = 1000

            const ctx = canvas.getContext('2d')
            if (!ctx)
                throw new Error('Canvas rendering is not available in this browser.')

            ctx.clearRect(0, 0, canvas.width, canvas.height)
            ctx.fillStyle = '#ffffff'
            ctx.fillRect(0, 0, canvas.width, canvas.height)

            const plot = { x: 220, y: 145, w: 760, h: 500 }
            const midX = this.valueToX(5.5, plot)
            const midY = this.valueToY(5.5, plot)
            const axisLeft = plot.x - 70
            const axisBottom = plot.y + plot.h + 45

            ctx.save()
            ctx.fillStyle = '#1f2937'
            ctx.font = 'bold 48px Arial'
            ctx.textAlign = 'center'
            ctx.textBaseline = 'middle'
            ctx.fillText(title || 'Action Priority Matrix', canvas.width / 2, 70)
            ctx.restore()

            ctx.save()
            ctx.strokeStyle = '#1f2937'
            ctx.fillStyle = '#1f2937'
            ctx.lineWidth = 5
            ctx.lineCap = 'round'
            ctx.beginPath()
            ctx.moveTo(axisLeft, axisBottom)
            ctx.lineTo(axisLeft, plot.y - 35)
            ctx.stroke()
            ctx.beginPath()
            ctx.moveTo(axisLeft, plot.y - 50)
            ctx.lineTo(axisLeft - 14, plot.y - 20)
            ctx.lineTo(axisLeft + 14, plot.y - 20)
            ctx.closePath()
            ctx.fill()
            ctx.beginPath()
            ctx.moveTo(axisLeft, axisBottom)
            ctx.lineTo(plot.x + plot.w + 55, axisBottom)
            ctx.stroke()
            ctx.beginPath()
            ctx.moveTo(plot.x + plot.w + 75, axisBottom)
            ctx.lineTo(plot.x + plot.w + 42, axisBottom - 15)
            ctx.lineTo(plot.x + plot.w + 42, axisBottom + 15)
            ctx.closePath()
            ctx.fill()
            ctx.restore()

            ctx.save()
            ctx.fillStyle = '#111827'
            ctx.font = '30px Arial'
            ctx.textAlign = 'center'
            ctx.textBaseline = 'middle'
            ctx.fillText('REMEDIATION EFFORT', plot.x + plot.w / 2, axisBottom + 52)
            ctx.translate(axisLeft - 54, plot.y + plot.h / 2)
            ctx.rotate(-Math.PI / 2)
            ctx.fillText('SEVERITY', 0, 0)
            ctx.restore()

            ctx.save()
            ctx.shadowColor = 'rgba(15,23,42,0.10)'
            ctx.shadowBlur = 16
            ctx.shadowOffsetY = 6
            ctx.fillStyle = MATRIX_QUADS[0].color
            ctx.fillRect(plot.x, plot.y, midX - plot.x, midY - plot.y)
            ctx.fillStyle = MATRIX_QUADS[1].color
            ctx.fillRect(midX, plot.y, plot.x + plot.w - midX, midY - plot.y)
            ctx.fillStyle = MATRIX_QUADS[2].color
            ctx.fillRect(plot.x, midY, midX - plot.x, plot.y + plot.h - midY)
            ctx.fillStyle = MATRIX_QUADS[3].color
            ctx.fillRect(midX, midY, plot.x + plot.w - midX, plot.y + plot.h - midY)
            ctx.restore()

            ctx.save()
            ctx.lineWidth = 1
            ctx.font = '13px Arial'
            ctx.textAlign = 'center'
            ctx.textBaseline = 'middle'
            for (let i = 1; i <= 10; i++) {
                const x = this.valueToX(i, plot)
                const y = this.valueToY(i, plot)
                ctx.strokeStyle = i === 5 || i === 6 ? 'rgba(15,23,42,0.18)' : 'rgba(15,23,42,0.10)'
                ctx.beginPath()
                ctx.moveTo(x, plot.y)
                ctx.lineTo(x, plot.y + plot.h)
                ctx.stroke()
                ctx.beginPath()
                ctx.moveTo(plot.x, y)
                ctx.lineTo(plot.x + plot.w, y)
                ctx.stroke()
                ctx.fillStyle = 'rgba(15,23,42,0.58)'
                ctx.fillText(String(i), x, plot.y + plot.h + 18)
                ctx.textAlign = 'right'
                ctx.fillText(String(i), plot.x - 12, y)
                ctx.textAlign = 'center'
            }
            ctx.restore()

            ctx.save()
            ctx.strokeStyle = '#ffffff'
            ctx.lineWidth = 10
            ctx.beginPath()
            ctx.moveTo(midX, plot.y)
            ctx.lineTo(midX, plot.y + plot.h)
            ctx.stroke()
            ctx.beginPath()
            ctx.moveTo(plot.x, midY)
            ctx.lineTo(plot.x + plot.w, midY)
            ctx.stroke()
            ctx.lineWidth = 7
            ctx.strokeRect(plot.x, plot.y, plot.w, plot.h)
            ctx.restore()

            const points = findings.map(finding => ({
                finding,
                x: this.valueToX(finding.effort, plot),
                y: this.valueToY(Math.max(1, Math.min(10, finding.cvss)), plot)
            }))
            this.applyMatrixOffsets(points)

            points.forEach(point => {
                ctx.save()
                ctx.beginPath()
                ctx.arc(point.x, point.y, 6, 0, Math.PI * 2)
                ctx.fillStyle = '#111827'
                ctx.fill()
                ctx.restore()
            })

            points.forEach(point => {
                const lines = this.wrapText(point.finding.name, 10)
                let labelX = point.x
                let labelY = point.y + 22
                let align = 'center'
                if (point.x < plot.x + 80) {
                    labelX = point.x + 18
                    align = 'left'
                }
                else if (point.x > plot.x + plot.w - 80) {
                    labelX = point.x - 18
                    align = 'right'
                }
                if (point.y > plot.y + plot.h - 60)
                    labelY = point.y - 22

                ctx.save()
                ctx.fillStyle = 'rgba(17,24,39,0.78)'
                ctx.font = 'bold 13px Arial'
                ctx.textAlign = align
                ctx.textBaseline = 'middle'
                const lineHeight = 15
                const totalHeight = (lines.length - 1) * lineHeight
                lines.forEach((line, index) => ctx.fillText(line, labelX, labelY - totalHeight / 2 + index * lineHeight))
                ctx.restore()
            })

            ctx.save()
            ctx.fillStyle = '#344054'
            ctx.font = 'bold 19px Arial'
            ctx.textAlign = 'left'
            ctx.textBaseline = 'middle'
            ctx.fillText('Priority Zones', 120, 850)
            ctx.restore()

            const legendX = 300
            const spacing = 205
            MATRIX_QUADS.forEach((quad, index) => this.drawLegendSquare(ctx, legendX + index * spacing, 850, quad.color, quad.name))

            return canvas.toDataURL('image/png')
        },

        makeEmbedHtml: function(chartUrl, alt, width) {
            return `
<p style="text-align:center;">
  <img src="${chartUrl}" alt="${alt}" style="width:${width};max-width:100%;height:auto;">
</p>`.trim()
        },

        uploadChartImage: async function(chart) {
            const { default: ImageService } = await import('@/services/image')
            const response = await ImageService.createImage({
                value: chart.chartUrl,
                name: `${(chart.alt || 'PwnDoc chart').replace(/\s+/g, '-').toLowerCase()}.png`,
                auditId: this.auditId
            })

            return response.data.datas._id
        },

        insertCurrentChart: async function() {
            const editorComponent = this.lastEditorComponent || this.findBasicEditorComponent(this.lastEditor)
            if (!editorComponent?.editor?.commands) {
                Notify.create({
                    message: 'Click inside the PwnDoc editor field first, then click Insert.',
                    color: 'warning',
                    textColor: 'white',
                    position: 'top-right'
                })
                return
            }

            if (!this.currentChart.chartUrl) {
                Notify.create({
                    message: 'Generate a chart before inserting it.',
                    color: 'warning',
                    textColor: 'white',
                    position: 'top-right'
                })
                return
            }

            if (editorComponent.editor.isEditable === false) {
                Notify.create({
                    message: 'The focused PwnDoc editor is read-only.',
                    color: 'warning',
                    textColor: 'white',
                    position: 'top-right'
                })
                return
            }

            let imageSource = this.currentChart.chartUrl
            let storedInPwndoc = false

            try {
                imageSource = await this.uploadChartImage(this.currentChart)
                storedInPwndoc = true
            }
            catch (err) {
                console.warn('Could not upload generated chart; inserting data URL instead.', err)
            }

            const inserted = editorComponent.editor.chain()
            .focus()
            .setImage({
                src: imageSource,
                alt: this.currentChart.alt || 'PwnDoc chart'
            })
            .run()

            if (inserted) {
                editorComponent.updateHTML()
                editorComponent.$el?.dispatchEvent(new CustomEvent('basic-editor-change', { bubbles: true }))
            }

            Notify.create({
                message: inserted
                    ? (storedInPwndoc ? 'Inserted chart.' : 'Inserted chart with embedded image data.')
                    : 'Could not insert into the focused editor. Copy HTML and paste it into the editor source view.',
                color: inserted ? 'positive' : 'warning',
                textColor: 'white',
                position: 'top-right'
            })
        },

        copyCurrentHtml: function() {
            this.copyText(this.currentChart.html, 'Copied chart HTML.')
        },

        copyCurrentUrl: function() {
            this.copyText(this.currentChart.chartUrl, 'Copied chart URL.')
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
    width: 760px;
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

.x10-matrix-preview {
    max-width: 700px;
}
</style>
