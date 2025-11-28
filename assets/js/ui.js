/**
 * UI Helper Module
 * Provides functions for rendering lists and accessible UI components
 */

import { formatCurrency, formatDateTime } from './utils.js';

/**
 * Render transaction list
 * @param {Array} transactions - Transactions to render
 * @param {HTMLElement} container - Container element
 * @param {Object} options - { onEdit, onDelete, currency }
 */
export function renderTransactionList(transactions, container, options = {}) {
    if (!container) return;
    
    if (transactions.length === 0) {
        container.innerHTML = '<p class="empty-state">No transactions found</p>';
        return;
    }
    
    const { onEdit, onDelete, currency = 'INR' } = options;
    
    container.innerHTML = transactions.map(tx => `
        <div class="transaction-item" data-id="${tx.id}">
            <div class="transaction-info">
                <div class="transaction-category">${tx.category}</div>
                ${tx.note ? `<div class="transaction-note">${escapeHtml(tx.note)}</div>` : ''}
                <div class="transaction-date">${formatDateTime(tx.date, tx.time)}</div>
            </div>
            <div class="transaction-amount ${tx.type}">
                ${tx.type === 'income' ? '+' : '-'}${formatCurrency(tx.amount, currency)}
            </div>
            <div class="transaction-actions">
                <button class="btn btn-small btn-secondary edit-btn" data-id="${tx.id}" aria-label="Edit transaction">
                    ✏️ Edit
                </button>
                <button class="btn btn-small btn-danger delete-btn" data-id="${tx.id}" aria-label="Delete transaction">
                    🗑️ Delete
                </button>
            </div>
        </div>
    `).join('');
    
    // Attach event listeners
    if (onEdit) {
        container.querySelectorAll('.edit-btn').forEach(btn => {
            btn.addEventListener('click', () => onEdit(parseInt(btn.dataset.id)));
        });
    }
    
    if (onDelete) {
        container.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', () => onDelete(parseInt(btn.dataset.id)));
        });
    }
}

/**
 * Render pagination controls
 * @param {Object} paginationData - { currentPage, totalPages, total }
 * @param {HTMLElement} container - Container element
 * @param {Function} onPageChange - Callback when page changes
 */
export function renderPagination(paginationData, container, onPageChange) {
    if (!container || paginationData.totalPages <= 1) {
        container.innerHTML = '';
        return;
    }
    
    const { currentPage, totalPages } = paginationData;
    let html = '';
    
    // Previous button
    html += `<button class="prev-btn" ${currentPage === 1 ? 'disabled' : ''} 
             aria-label="Previous page">← Previous</button>`;
    
    // Page numbers
    for (let i = 1; i <= totalPages; i++) {
        if (i === 1 || i === totalPages || (i >= currentPage - 1 && i <= currentPage + 1)) {
            html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" 
                     data-page="${i}" aria-label="Page ${i}" 
                     ${i === currentPage ? 'aria-current="page"' : ''}>${i}</button>`;
        } else if (i === currentPage - 2 || i === currentPage + 2) {
            html += '<span>...</span>';
        }
    }
    
    // Next button
    html += `<button class="next-btn" ${currentPage === totalPages ? 'disabled' : ''} 
             aria-label="Next page">Next →</button>`;
    
    container.innerHTML = html;
    
    // Attach event listeners
    container.querySelector('.prev-btn')?.addEventListener('click', () => {
        if (currentPage > 1) onPageChange(currentPage - 1);
    });
    
    container.querySelector('.next-btn')?.addEventListener('click', () => {
        if (currentPage < totalPages) onPageChange(currentPage + 1);
    });
    
    container.querySelectorAll('.page-btn').forEach(btn => {
        btn.addEventListener('click', () => onPageChange(parseInt(btn.dataset.page)));
    });
}

/**
 * Render budget overview
 * @param {Array} budgets - Budget data with spending
 * @param {HTMLElement} container - Container element
 * @param {string} currency - Currency code
 */
export function renderBudgetOverview(budgets, container, currency = 'INR') {
    if (!container) return;
    
    if (budgets.length === 0) {
        container.innerHTML = '<p class="empty-state">No budgets set</p>';
        return;
    }
    
    container.innerHTML = budgets.map(budget => {
        const percentage = (budget.spent / budget.amount) * 100;
        const progressClass = percentage >= 100 ? 'danger' : percentage >= 80 ? 'warning' : '';
        
        return `
            <div class="budget-item">
                <div class="budget-header">
                    <span class="budget-category">${budget.category}</span>
                    <span class="budget-amounts">
                        ${formatCurrency(budget.spent, currency)} / ${formatCurrency(budget.amount, currency)}
                    </span>
                </div>
                <div class="budget-bar">
                    <div class="budget-progress ${progressClass}" 
                         style="width: ${Math.min(percentage, 100)}%"
                         role="progressbar" 
                         aria-valuenow="${percentage.toFixed(0)}" 
                         aria-valuemin="0" 
                         aria-valuemax="100">
                    </div>
                </div>
                <small>${percentage.toFixed(1)}% used</small>
            </div>
        `;
    }).join('');
}

/**
 * Render category tags with delete option
 * @param {Array} categories - Category names
 * @param {HTMLElement} container - Container element
 * @param {Function} onDelete - Callback when category is deleted
 * @param {Array} protectedCategories - Categories that cannot be deleted
 */
export function renderCategoryTags(categories, container, onDelete, protectedCategories = []) {
    if (!container) return;
    
    container.innerHTML = categories.map(cat => {
        const isProtected = protectedCategories.includes(cat);
        return `
            <div class="category-tag">
                <span>${cat}</span>
                ${!isProtected ? `<button data-category="${cat}" aria-label="Delete ${cat}">×</button>` : ''}
            </div>
        `;
    }).join('');
    
    // Attach delete listeners
    if (onDelete) {
        container.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', () => onDelete(btn.dataset.category));
        });
    }
}

/**
 * Show a toast notification
 * @param {string} message - Message to display
 * @param {string} type - 'success', 'error', 'info'
 */
export function showToast(message, type = 'info') {
    // Remove existing toast
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'polite');
    
    document.body.appendChild(toast);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

/**
 * Show confirmation dialog
 * @param {string} message - Confirmation message
 * @returns {boolean} - User's choice
 */
export function confirm(message) {
    return window.confirm(message);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Toggle mobile menu
 */
export function setupMobileMenu() {
    const toggle = document.querySelector('.mobile-menu-toggle');
    const sidebar = document.querySelector('.sidebar');
    
    if (toggle && sidebar) {
        toggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
        
        // Close on navigation
        sidebar.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                sidebar.classList.remove('open');
            });
        });
    }
}
