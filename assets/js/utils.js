/**
 * Utility Functions Module
 * Provides debounce, formatters, and currency conversion helpers
 */

/**
 * Debounce function - delays execution until after wait time has elapsed
 * since the last call. Useful for search inputs to avoid excessive calls.
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds (default 300ms)
 * @returns {Function} - Debounced function
 */
export function debounce(func, wait = 300) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Currency symbols mapping
 */
const CURRENCY_SYMBOLS = {
    INR: '₹',
    USD: '$',
    EUR: '€',
    JPY: '¥',
    GBP: '£'
};

/**
 * Format number as currency
 * @param {number} amount - Amount to format
 * @param {string} currency - Currency code (INR, USD, EUR, JPY, GBP)
 * @returns {string} - Formatted currency string
 */
export function formatCurrency(amount, currency = 'INR') {
    const symbol = CURRENCY_SYMBOLS[currency] || currency;
    const formatted = Math.abs(amount).toFixed(2);
    return `${symbol}${formatted}`;
}

/**
 * Format date to readable string
 * @param {string|Date} date - Date to format
 * @returns {string} - Formatted date string
 */
export function formatDate(date) {
    const d = new Date(date);
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return d.toLocaleDateString('en-US', options);
}

/**
 * Format date and time
 * @param {string|Date} date - Date to format
 * @param {string} time - Time string (HH:MM)
 * @returns {string} - Formatted date and time string
 */
export function formatDateTime(date, time) {
    const dateStr = formatDate(date);
    if (time) {
        return `${dateStr} at ${time}`;
    }
    return dateStr;
}

/**
 * Get current date in YYYY-MM-DD format
 */
export function getCurrentDate() {
    const today = new Date();
    return today.toISOString().split('T')[0];
}

/**
 * Get current time in HH:MM format
 */
export function getCurrentTime() {
    const now = new Date();
    return now.toTimeString().slice(0, 5);
}

/**
 * Calculate percentage
 * @param {number} value - Current value
 * @param {number} total - Total value
 * @returns {number} - Percentage (0-100)
 */
export function calculatePercentage(value, total) {
    if (total === 0) return 0;
    return Math.min((value / total) * 100, 100);
}

/**
 * Group array of objects by a key
 * @param {Array} array - Array to group
 * @param {string} key - Key to group by
 * @returns {Object} - Grouped object
 */
export function groupBy(array, key) {
    return array.reduce((result, item) => {
        const group = item[key];
        if (!result[group]) {
            result[group] = [];
        }
        result[group].push(item);
        return result;
    }, {});
}

/**
 * Get date range for period
 * @param {string} period - 'week', 'month', or 'year'
 * @returns {Object} - { start: Date, end: Date }
 */
export function getDateRange(period) {
    const end = new Date();
    const start = new Date();
    
    switch (period) {
        case 'week':
            start.setDate(end.getDate() - 7);
            break;
        case 'month':
            start.setMonth(end.getMonth() - 1);
            break;
        case 'year':
            start.setFullYear(end.getFullYear() - 1);
            break;
    }
    
    return { start, end };
}

/**
 * Filter transactions by date range
 */
export function filterByDateRange(transactions, start, end) {
    return transactions.filter(tx => {
        const txDate = new Date(tx.date);
        return txDate >= start && txDate <= end;
    });
}
