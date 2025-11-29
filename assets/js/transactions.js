/**
 * Transactions Module
 * Handles transaction CRUD operations, search, sort, pagination, and undo stack
 */

import { getRecordsByIndex, putRecord, deleteRecord } from './db.js';
import { getCurrentUser } from './auth.js';

// In-memory cache for performance
let transactionsCache = [];
let undoStack = [];
const MAX_UNDO_STACK = 10;

/**
 * Load all transactions for current user
 * Uses in-memory cache to avoid repeated DB reads
 */
export async function loadTransactions(forceRefresh = false) {
    if (transactionsCache.length > 0 && !forceRefresh) {
        return transactionsCache;
    }
    
    const username = getCurrentUser();
    transactionsCache = await getRecordsByIndex('transactions', 'username', username);
    return transactionsCache;
}

/**
 * Add a new transaction
 * @param {Object} transaction - Transaction data
 * @returns {Promise<number>} - Transaction ID
 */
export async function addTransaction(transaction) {
    const username = getCurrentUser();
    transaction.username = username;
    transaction.createdAt = new Date().toISOString();
    
    const id = await putRecord('transactions', transaction);
    transaction.id = id;
    
    // Update cache
    transactionsCache.push(transaction);
    
    // Add to undo stack
    pushUndo({
        type: 'add',
        transaction: { ...transaction }
    });
    
    return id;
}

/**
 * Update an existing transaction
 * @param {Object} transaction - Updated transaction data (must include id)
 */
export async function updateTransaction(transaction) {
    const username = getCurrentUser();
    transaction.username = username;
    transaction.updatedAt = new Date().toISOString();
    
    // Store old version for undo
    const oldTransaction = transactionsCache.find(t => t.id === transaction.id);
    
    await putRecord('transactions', transaction);
    
    // Update cache
    const index = transactionsCache.findIndex(t => t.id === transaction.id);
    if (index !== -1) {
        transactionsCache[index] = transaction;
    }
    
    // Add to undo stack
    pushUndo({
        type: 'edit',
        oldTransaction: { ...oldTransaction },
        newTransaction: { ...transaction }
    });
}

/**
 * Delete a transaction
 * @param {number} id - Transaction ID
 */
export async function deleteTransaction(id) {
    // Store for undo
    const transaction = transactionsCache.find(t => t.id === id);
    
    await deleteRecord('transactions', id);
    
    // Update cache
    transactionsCache = transactionsCache.filter(t => t.id !== id);
    
    // Add to undo stack
    pushUndo({
        type: 'delete',
        transaction: { ...transaction }
    });
}

/**
 * Get transaction by ID
 */
export function getTransactionById(id) {
    return transactionsCache.find(t => t.id === id);
}

/**
 * Search transactions
 * Searches in category, amount, and notes
 * @param {string} query - Search query
 * @returns {Array} - Filtered transactions
 */
export function searchTransactions(query) {
    if (!query) return transactionsCache;
    
    const lowerQuery = query.toLowerCase();
    return transactionsCache.filter(tx => {
        return (
            tx.category.toLowerCase().includes(lowerQuery) ||
            tx.amount.toString().includes(lowerQuery) ||
            (tx.note && tx.note.toLowerCase().includes(lowerQuery))
        );
    });
}

/**
 * Sort transactions
 * @param {Array} transactions - Transactions to sort
 * @param {string} sortBy - Sort criteria
 * @returns {Array} - Sorted transactions
 */
export function sortTransactions(transactions, sortBy) {
    const sorted = [...transactions];
    
    switch (sortBy) {
        case 'date-desc':
            return sorted.sort((a, b) => new Date(b.date) - new Date(a.date));
        case 'date-asc':
            return sorted.sort((a, b) => new Date(a.date) - new Date(b.date));
        case 'amount-desc':
            return sorted.sort((a, b) => b.amount - a.amount);
        case 'amount-asc':
            return sorted.sort((a, b) => a.amount - b.amount);
        case 'category-asc':
            return sorted.sort((a, b) => a.category.localeCompare(b.category));
        default:
            return sorted;
    }
}

/**
 * Paginate transactions
 * @param {Array} transactions - Transactions to paginate
 * @param {number} page - Current page (1-indexed)
 * @param {number} perPage - Items per page
 * @returns {Object} - { items, totalPages, currentPage }
 */
export function paginateTransactions(transactions, page = 1, perPage = 10) {
    const totalPages = Math.ceil(transactions.length / perPage);
    const start = (page - 1) * perPage;
    const end = start + perPage;
    const items = transactions.slice(start, end);
    
    return {
        items,
        totalPages,
        currentPage: page,
        total: transactions.length
    };
}

/**
 * Calculate summary statistics
 * @param {Array} transactions - Transactions to analyze
 * @returns {Object} - { totalIncome, totalExpenses, balance }
 */
export function calculateSummary(transactions) {
    const summary = {
        totalIncome: 0,
        totalExpenses: 0,
        balance: 0
    };
    
    transactions.forEach(tx => {
        if (tx.type === 'income') {
            summary.totalIncome += tx.amount;
        } else {
            summary.totalExpenses += tx.amount;
        }
    });
    
    summary.balance = summary.totalIncome - summary.totalExpenses;
    return summary;
}

/**
 * Group transactions by category
 * @param {Array} transactions - Transactions to group
 * @param {string} type - 'income' or 'expense'
 * @returns {Object} - { category: total }
 */
export function groupByCategory(transactions, type) {
    const filtered = transactions.filter(tx => tx.type === type);
    const grouped = {};
    
    filtered.forEach(tx => {
        if (!grouped[tx.category]) {
            grouped[tx.category] = 0;
        }
        grouped[tx.category] += tx.amount;
    });
    
    return grouped;
}

/**
 * Get monthly aggregated data
 * @param {Array} transactions - Transactions to aggregate
 * @returns {Array} - Array of { month, income, expenses, savings }
 */
export function getMonthlyData(transactions) {
    const monthlyMap = {};
    
    transactions.forEach(tx => {
        const date = new Date(tx.date);
        const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
        
        if (!monthlyMap[monthKey]) {
            monthlyMap[monthKey] = { month: monthKey, income: 0, expenses: 0 };
        }
        
        if (tx.type === 'income') {
            monthlyMap[monthKey].income += tx.amount;
        } else {
            monthlyMap[monthKey].expenses += tx.amount;
        }
    });
    
    // Convert to array and calculate savings
    const monthlyData = Object.values(monthlyMap).map(m => ({
        ...m,
        savings: m.income - m.expenses
    }));
    
    // Sort by month
    monthlyData.sort((a, b) => a.month.localeCompare(b.month));
    
    return monthlyData;
}

/**
 * Undo Stack Management
 */
function pushUndo(action) {
    undoStack.push(action);
    if (undoStack.length > MAX_UNDO_STACK) {
        undoStack.shift(); // Remove oldest
    }
}

/**
 * Undo the last action
 * @returns {Promise<boolean>} - Success status
 */
export async function undoLastAction() {
    if (undoStack.length === 0) return false;
    
    const action = undoStack.pop();
    
    switch (action.type) {
        case 'add':
            // Undo add by deleting
            await deleteRecord('transactions', action.transaction.id);
            transactionsCache = transactionsCache.filter(t => t.id !== action.transaction.id);
            break;
            
        case 'edit':
            // Undo edit by restoring old version
            await putRecord('transactions', action.oldTransaction);
            const index = transactionsCache.findIndex(t => t.id === action.oldTransaction.id);
            if (index !== -1) {
                transactionsCache[index] = action.oldTransaction;
            }
            break;
            
        case 'delete':
            // Undo delete by re-adding
            await putRecord('transactions', action.transaction);
            transactionsCache.push(action.transaction);
            break;
    }
    
    return true;
}

/**
 * Check if undo is available
 */
export function canUndo() {
    return undoStack.length > 0;
}

/**
 * Clear undo stack
 */
export function clearUndoStack() {
    undoStack = [];
}
