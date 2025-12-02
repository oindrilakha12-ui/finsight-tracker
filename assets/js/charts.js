/**
 * Charts Module
 * Handles Chart.js setup and rendering for various chart types
 */

let chartInstances = {};

/**
 * Destroy existing chart instance if it exists
 */
function destroyChart(chartId) {
    if (chartInstances[chartId]) {
        chartInstances[chartId].destroy();
        delete chartInstances[chartId];
    }
}

/**
 * Create a pie chart
 * @param {string} canvasId - Canvas element ID
 * @param {Object} data - { labels: [], values: [], colors?: [] }
 * @param {string} title - Chart title
 */
export function createPieChart(canvasId, data, title) {
    destroyChart(canvasId);
    
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Use custom colors if provided, otherwise generate them
    const colors = data.colors || generateColors(data.labels.length);
    
    chartInstances[canvasId] = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: colors,
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: { size: 12 }
                    }
                },
                title: {
                    display: !!title,
                    text: title,
                    font: { size: 16, weight: 'bold' },
                    padding: { bottom: 20 }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value.toFixed(2)} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create a bar chart
 * @param {string} canvasId - Canvas element ID
 * @param {Object} data - { labels: [], datasets: [{ label, data, backgroundColor }] }
 */
export function createBarChart(canvasId, data) {
    destroyChart(canvasId);
    
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    chartInstances[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.dataset.label}: ${context.parsed.y.toFixed(2)}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return value.toFixed(0);
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create a line chart
 * @param {string} canvasId - Canvas element ID
 * @param {Object} data - { labels: [], datasets: [{ label, data, borderColor, backgroundColor }] }
 */
export function createLineChart(canvasId, data) {
    destroyChart(canvasId);
    
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    chartInstances[canvasId] = new Chart(ctx, {
        type: 'line',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Balance: ${context.parsed.y.toFixed(2)}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: false
                }
            },
            elements: {
                line: {
                    tension: 0.4
                },
                point: {
                    radius: 3
                }
            }
        }
    });
}

/**
 * Generate an array of colors
 */
function generateColors(count) {
    const baseColors = [
        '#4f46e5', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
        '#ec4899', '#14b8a6', '#f97316', '#06b6d4', '#84cc16'
    ];
    
    const colors = [];
    for (let i = 0; i < count; i++) {
        colors.push(baseColors[i % baseColors.length]);
    }
    return colors;
}

/**
 * Update chart data
 * @param {string} chartId - Chart instance ID
 * @param {Object} newData - New data object
 */
export function updateChartData(chartId, newData) {
    const chart = chartInstances[chartId];
    if (!chart) return;
    
    chart.data = newData;
    chart.update();
}

/**
 * Destroy all chart instances
 */
export function destroyAllCharts() {
    Object.keys(chartInstances).forEach(chartId => {
        destroyChart(chartId);
    });
}
