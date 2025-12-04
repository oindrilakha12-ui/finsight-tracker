/**
 * Main Application Module
 * Router and app bootstrap - loads appropriate page logic
 */

import { requireAuth, logout, getCurrentUser } from './auth.js';
import { initDB, getRecord, putRecord, getRecordsByIndex, exportData, importData, clearAllData } from './db.js';
import { 
    loadTransactions, 
    addTransaction, 
    updateTransaction, 
    deleteTransaction,
    getTransactionById,
    searchTransactions,
    sortTransactions,
    paginateTransactions,
    calculateSummary,
    groupByCategory,
    getMonthlyData,
    undoLastAction,
    canUndo
} from './transactions.js';
import { createPieChart, createBarChart, createLineChart } from './charts.js';
import { renderTransactionList, renderPagination, renderBudgetOverview, renderCategoryTags, showToast, confirm, setupMobileMenu } from './ui.js';
import { debounce, formatCurrency, getCurrentDate, getCurrentTime, getDateRange, filterByDateRange } from './utils.js';

// Global state
let currentSettings = null;

/**
 * Initialize app on page load
 */
document.addEventListener('DOMContentLoaded', async () => {
    // Check authentication (skip for index.html)
    if (!window.location.pathname.endsWith('index.html') && window.location.pathname !== '/') {
        const username = requireAuth();
        if (!username) return;
        
        await initDB();
        await loadSettings();
        setupCommonUI();
        
        // Route to appropriate page handler
        const page = getPageName();
        switch (page) {
            case 'dashboard':
                await initDashboard();
                break;
            case 'transactions':
                await initTransactions();
                break;
            case 'add-transaction':
                await initAddTransaction();
                break;
            case 'edit-transaction':
                await initEditTransaction();
                break;
            case 'budgets':
                await initBudgets();
                break;
            case 'settings':
                await initSettings();
                break;
        }
    }
});

/**
 * Get current page name from URL
 */
function getPageName() {
    const path = window.location.pathname;
    const page = path.split('/').pop().replace('.html', '');
    return page || 'dashboard';
}

/**
 * Load user settings and apply theme
 */
async function loadSettings() {
    const username = getCurrentUser();
    currentSettings = await getRecord('settings', username);
    
    if (!currentSettings) {
        currentSettings = { username, theme: 'light', currency: 'INR' };
        await putRecord('settings', currentSettings);
    }
    
    // Apply theme
    if (currentSettings.theme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
}

/**
 * Setup common UI elements (sidebar, logout, mobile menu)
 */
function setupCommonUI() {
    const username = getCurrentUser();
    const userInfo = document.getElementById('currentUser');
    if (userInfo) {
        userInfo.textContent = `👤 ${username}`;
    }
    
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
    
    setupMobileMenu();
}

/**
 * Get user categories
 */
async function getCategories() {
    const username = getCurrentUser();
    let categories = await getRecord('categories', username);
    
    if (!categories) {
        categories = {
            username,
            expense: ['food', 'transport', 'medical', 'rent', 'entertainment', 'shopping', 'bills', 'other'],
            income: ['salary', 'freelance', 'investment', 'gift', 'other']
        };
        await putRecord('categories', categories);
    }
    
    return categories;
}

/**
 * Dashboard Page
 */
async function initDashboard() {
    const transactions = await loadTransactions();
    const summary = calculateSummary(transactions);
    const currency = currentSettings.currency;
    
    // Update summary cards
    document.getElementById('totalBalance').textContent = formatCurrency(summary.balance, currency);
    document.getElementById('totalIncome').textContent = formatCurrency(summary.totalIncome, currency);
    document.getElementById('totalExpenses').textContent = formatCurrency(summary.totalExpenses, currency);
    
    // Expense breakdown pie chart
    const expensesByCategory = groupByCategory(transactions, 'expense');
    if (Object.keys(expensesByCategory).length > 0) {
        createPieChart('expensePieChart', {
            labels: Object.keys(expensesByCategory),
            values: Object.values(expensesByCategory)
        }, 'Expense Breakdown');
    }
    
    // Income sources pie chart
    const incomeByCategory = groupByCategory(transactions, 'income');
    if (Object.keys(incomeByCategory).length > 0) {
        createPieChart('incomePieChart', {
            labels: Object.keys(incomeByCategory),
            values: Object.values(incomeByCategory)
        }, 'Income Sources');
    }
    
    // Monthly bar chart
    const monthlyData = getMonthlyData(transactions);
    if (monthlyData.length > 0) {
        createBarChart('monthlyBarChart', {
            labels: monthlyData.map(m => m.month),
            datasets: [
                {
                    label: 'Income',
                    data: monthlyData.map(m => m.income),
                    backgroundColor: '#10b981'
                },
                {
                    label: 'Expenses',
                    data: monthlyData.map(m => m.expenses),
                    backgroundColor: '#ef4444'
                },
                {
                    label: 'Savings',
                    data: monthlyData.map(m => m.savings),
                    backgroundColor: '#4f46e5'
                }
            ]
        });
    }
    
    // Balance trend line chart
    if (monthlyData.length > 0) {
        const balances = [];
        let runningBalance = 0;
        monthlyData.forEach(m => {
            runningBalance += m.savings;
            balances.push(runningBalance);
        });
        
        createLineChart('balanceTrendChart', {
            labels: monthlyData.map(m => m.month),
            datasets: [{
                label: 'Balance',
                data: balances,
                borderColor: '#4f46e5',
                backgroundColor: 'rgba(79, 70, 229, 0.1)',
                fill: true
            }]
        });
    }
    
    // Balance insight message
    const balanceInsightEl = document.getElementById('balanceInsight');
    if (summary.balance >= 0) {
        balanceInsightEl.textContent = `Great! You have a positive balance of ${formatCurrency(summary.balance, currency)}`;
        balanceInsightEl.classList.remove('negative');
    } else {
        balanceInsightEl.textContent = `Alert! You have a negative balance of ${formatCurrency(Math.abs(summary.balance), currency)}`;
        balanceInsightEl.classList.add('negative');
    }
    
    // Top spending category
    const topCategory = Object.entries(expensesByCategory)
        .sort((a, b) => b[1] - a[1])[0];
    
    if (topCategory) {
        document.getElementById('topSpendingCategory').textContent = 
            `${topCategory[0]}: ${formatCurrency(topCategory[1], currency)}`;
    } else {
        document.getElementById('topSpendingCategory').textContent = 'No expenses yet';
    }
    
    // Recent transactions
    const recentTransactions = [...transactions]
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .slice(0, 3);
    
    renderTransactionList(recentTransactions, document.getElementById('recentTransactionsList'), {
        currency,
        onEdit: (id) => window.location.href = `edit-transaction.html?id=${id}`,
        onDelete: async (id) => {
            if (confirm('Delete this transaction?')) {
                await deleteTransaction(id);
                window.location.reload();
            }
        }
    });
}

/**
 * Transactions Page
 */
async function initTransactions() {
    let allTransactions = await loadTransactions();
    let filteredTransactions = allTransactions;
    let currentPage = 1;
    let currentSort = 'date-desc';
    let currentPeriod = 'month';
    const currency = currentSettings.currency;
    
    // Search functionality (debounced)
    const searchInput = document.getElementById('searchInput');
    const debouncedSearch = debounce((query) => {
        filteredTransactions = searchTransactions(query);
        currentPage = 1;
        renderTransactionsPage();
    }, 300);
    
    searchInput?.addEventListener('input', (e) => {
        debouncedSearch(e.target.value);
    });
    
    // Sort functionality
    const sortSelect = document.getElementById('sortSelect');
    sortSelect?.addEventListener('change', (e) => {
        currentSort = e.target.value;
        renderTransactionsPage();
    });
    
    // Undo functionality
    const undoBtn = document.getElementById('undoBtn');
    undoBtn?.addEventListener('click', async () => {
        const success = await undoLastAction();
        if (success) {
            showToast('Action undone', 'success');
            allTransactions = await loadTransactions(true);
            filteredTransactions = allTransactions;
            renderTransactionsPage();
        }
    });
    
    // Update undo button state
    function updateUndoButton() {
        if (undoBtn) {
            undoBtn.disabled = !canUndo();
        }
    }
    
    // Spending analysis chart
    const chartButtons = document.querySelectorAll('.chart-controls button');
    chartButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            chartButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentPeriod = btn.dataset.period;
            renderSpendingChart();
        });
    });
    
    function renderSpendingChart() {
        const range = getDateRange(currentPeriod);
        const periodTransactions = filterByDateRange(allTransactions, range.start, range.end);
        const dailyData = {};
        
        periodTransactions.forEach(tx => {
            const date = tx.date;
            if (!dailyData[date]) {
                dailyData[date] = { income: 0, expenses: 0 };
            }
            if (tx.type === 'income') {
                dailyData[date].income += tx.amount;
            } else {
                dailyData[date].expenses += tx.amount;
            }
        });
        
        const dates = Object.keys(dailyData).sort();
        createBarChart('spendingAnalysisChart', {
            labels: dates,
            datasets: [
                {
                    label: 'Income',
                    data: dates.map(d => dailyData[d].income),
                    backgroundColor: '#10b981'
                },
                {
                    label: 'Expenses',
                    data: dates.map(d => dailyData[d].expenses),
                    backgroundColor: '#ef4444'
                }
            ]
        });
    }
    
    function renderTransactionsPage() {
        const sorted = sortTransactions(filteredTransactions, currentSort);
        const paginated = paginateTransactions(sorted, currentPage, 10);
        
        document.getElementById('transactionCount').textContent = paginated.total;
        
        renderTransactionList(paginated.items, document.getElementById('transactionsList'), {
            currency,
            onEdit: (id) => window.location.href = `edit-transaction.html?id=${id}`,
            onDelete: async (id) => {
                if (confirm('Delete this transaction?')) {
                    await deleteTransaction(id);
                    allTransactions = await loadTransactions(true);
                    filteredTransactions = allTransactions;
                    renderTransactionsPage();
                    updateUndoButton();
                }
            }
        });
        
        renderPagination(paginated, document.getElementById('pagination'), (page) => {
            currentPage = page;
            renderTransactionsPage();
        });
        
        updateUndoButton();
    }
    
    renderSpendingChart();
    renderTransactionsPage();
}

/**
 * Add Transaction Page
 */
async function initAddTransaction() {
    const form = document.getElementById('transactionForm');
    const typeInputs = form.querySelectorAll('input[name="type"]');
    const categorySelect = document.getElementById('category');
    const dateInput = document.getElementById('date');
    const timeInput = document.getElementById('time');
    
    // Set default date and time
    dateInput.value = getCurrentDate();
    timeInput.value = getCurrentTime();
    
    // Load categories
    const categories = await getCategories();
    
    function updateCategoryOptions() {
        const selectedType = form.querySelector('input[name="type"]:checked').value;
        const categoryList = categories[selectedType] || [];
        
        categorySelect.innerHTML = '<option value="">Select category</option>' +
            categoryList.map(cat => `<option value="${cat}">${cat}</option>`).join('');
    }
    
    typeInputs.forEach(input => {
        input.addEventListener('change', updateCategoryOptions);
    });
    
    updateCategoryOptions();
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(form);
        const transaction = {
            type: formData.get('type'),
            category: formData.get('category'),
            amount: parseFloat(formData.get('amount')),
            date: formData.get('date'),
            time: formData.get('time') || null,
            note: formData.get('note') || null
        };
        
        try {
            await addTransaction(transaction);
            showToast('Transaction added successfully', 'success');
            setTimeout(() => {
                window.location.href = 'transactions.html';
            }, 1000);
        } catch (error) {
            showToast('Error adding transaction: ' + error.message, 'error');
        }
    });
}

/**
 * Edit Transaction Page
 */
async function initEditTransaction() {
    const urlParams = new URLSearchParams(window.location.search);
    const transactionId = parseInt(urlParams.get('id'));
    
    if (!transactionId) {
        window.location.href = 'transactions.html';
        return;
    }
    
    await loadTransactions();
    const transaction = getTransactionById(transactionId);
    
    if (!transaction) {
        showToast('Transaction not found', 'error');
        setTimeout(() => window.location.href = 'transactions.html', 1000);
        return;
    }
    
    const form = document.getElementById('editTransactionForm');
    const typeInputs = form.querySelectorAll('input[name="type"]');
    const categorySelect = document.getElementById('category');
    
    // Load categories
    const categories = await getCategories();
    
    function updateCategoryOptions() {
        const selectedType = form.querySelector('input[name="type"]:checked').value;
        const categoryList = categories[selectedType] || [];
        
        categorySelect.innerHTML = '<option value="">Select category</option>' +
            categoryList.map(cat => `<option value="${cat}">${cat}</option>`).join('');
        
        categorySelect.value = transaction.category;
    }
    
    typeInputs.forEach(input => {
        input.addEventListener('change', updateCategoryOptions);
    });
    
    // Populate form
    document.getElementById('transactionId').value = transaction.id;
    form.querySelector(`input[name="type"][value="${transaction.type}"]`).checked = true;
    updateCategoryOptions();
    document.getElementById('amount').value = transaction.amount;
    document.getElementById('date').value = transaction.date;
    document.getElementById('time').value = transaction.time || '';
    document.getElementById('note').value = transaction.note || '';
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(form);
        const updatedTransaction = {
            id: transaction.id,
            type: formData.get('type'),
            category: formData.get('category'),
            amount: parseFloat(formData.get('amount')),
            date: formData.get('date'),
            time: formData.get('time') || null,
            note: formData.get('note') || null
        };
        
        try {
            await updateTransaction(updatedTransaction);
            showToast('Transaction updated successfully', 'success');
            setTimeout(() => {
                window.location.href = 'transactions.html';
            }, 1000);
        } catch (error) {
            showToast('Error updating transaction: ' + error.message, 'error');
        }
    });
}

/**
 * Budgets Page
 */
async function initBudgets() {
    const username = getCurrentUser();
    const categories = await getCategories();
    const transactions = await loadTransactions();
    const currency = currentSettings.currency;
    
    // Get all expense categories
    const expenseCategories = categories.expense || [];
    
    // Load existing budgets
    const existingBudgets = await getRecordsByIndex('budgets', 'username', username);
    const budgetMap = {};
    existingBudgets.forEach(b => {
        budgetMap[b.category] = b.amount;
    });
    
    // Render budget input form
    const budgetInputs = document.getElementById('budgetInputs');
    budgetInputs.innerHTML = expenseCategories.map(cat => `
        <div class="form-group">
            <label for="budget-${cat}">${cat}</label>
            <input type="number" id="budget-${cat}" name="${cat}" 
                   value="${budgetMap[cat] || 0}" min="0" step="0.01">
        </div>
    `).join('');
    
    // Handle budget form submission
    const budgetForm = document.getElementById('budgetForm');
    budgetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(budgetForm);
        
        // Update budgetMap with new values
        for (const cat of expenseCategories) {
            const amount = parseFloat(formData.get(cat)) || 0;
            budgetMap[cat] = amount; // Update local budgetMap
            
            if (amount > 0) {
                await putRecord('budgets', {
                    username,
                    category: cat,
                    amount
                });
            }
        }
        
        showToast('Budgets saved successfully', 'success');
        renderBudgetOverviewSection();
    });
    
    // Simple Budget Summary Pie Chart Function
    function renderBudgetOverviewSection() {
        const expensesByCategory = groupByCategory(transactions, 'expense');
        
        const budgetData = expenseCategories.map(cat => {
            const budgetAmount = budgetMap[cat] || 0;
            const spent = expensesByCategory[cat] || 0;
            
            return {
                category: cat,
                amount: budgetAmount,
                spent: spent
            };
        }).filter(b => b.amount > 0);
        
        renderBudgetOverview(budgetData, document.getElementById('budgetOverview'), currency);
        
        // Calculate totals
        const totalBudget = budgetData.reduce((sum, b) => sum + b.amount, 0);
        const totalSpent = budgetData.reduce((sum, b) => sum + b.spent, 0);
        const totalRest = Math.max(0, totalBudget - totalSpent);
        
        // Debug: Log values to console
        console.log('Budget Debug:', {
            totalBudget,
            totalSpent,
            totalRest,
            budgetData,
            expensesByCategory
        });
        
        if (totalBudget > 0) {
            // Simple pie chart with only 2 sections
            const chartData = {
                labels: ['Total Spent', 'Total Rest'],
                values: [totalSpent, totalRest],
                colors: ['#ef4444', '#10b981'] // Red for spent, Green for rest
            };
            
            createPieChart('budgetSummaryChart', chartData, 'Budget Summary');
            
            // Add simple summary text
            const chartContainer = document.querySelector('.budget-chart-container');
            const summaryHtml = `
                <div class="budget-summary-text">
                    <div class="budget-total">
                        <strong>Total Budget: ${formatCurrency(totalBudget, currency)}</strong>
                    </div>
                    <div class="budget-spent">
                        Total Spent: ${formatCurrency(totalSpent, currency)}
                    </div>
                    <div class="budget-remaining">
                        Total Rest: ${formatCurrency(totalRest, currency)}
                    </div>
                </div>
            `;
            
            // Remove existing summary if present
            const existingSummary = chartContainer.querySelector('.budget-summary-text');
            if (existingSummary) {
                existingSummary.remove();
            }
            
            // Add summary text after chart
            chartContainer.insertAdjacentHTML('beforeend', summaryHtml);
        } else {
            // Show message when no budgets are set
            const chartContainer = document.querySelector('.budget-chart-container');
            chartContainer.innerHTML = `
                <div class="no-budget-message">
                    <p>📊 Set your category budgets above to see the summary chart</p>
                </div>
            `;
        }
    }
    
    // Test function - create chart with dummy data
    function createTestChart() {
        console.log('Creating test chart...');
        const testData = {
            labels: ['Total Spent', 'Total Rest'],
            values: [30000, 20000],
            colors: ['#ef4444', '#10b981']
        };
        
        try {
            createPieChart('budgetSummaryChart', testData, 'Test Budget Summary');
            console.log('Test chart created successfully');
        } catch (error) {
            console.error('Error creating test chart:', error);
        }
    }
    
    // Add test button (temporary)
    setTimeout(() => {
        const testBtn = document.createElement('button');
        testBtn.textContent = 'Test Chart';
        testBtn.onclick = createTestChart;
        testBtn.style.margin = '10px';
        testBtn.className = 'btn btn-secondary';
        document.querySelector('.budget-summary-card').appendChild(testBtn);
    }, 1000);
    
    renderBudgetOverviewSection();
}

/**
 * Settings Page
 */
async function initSettings() {
    const username = getCurrentUser();
    const categories = await getCategories();
    
    // Theme toggle
    const themeToggle = document.getElementById('themeToggle');
    themeToggle.value = currentSettings.theme;
    themeToggle.addEventListener('change', async (e) => {
        currentSettings.theme = e.target.value;
        await putRecord('settings', currentSettings);
        
        if (currentSettings.theme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        
        showToast('Theme updated', 'success');
    });
    
    // Currency selector
    const currencySelect = document.getElementById('currencySelect');
    currencySelect.value = currentSettings.currency;
    currencySelect.addEventListener('change', async (e) => {
        currentSettings.currency = e.target.value;
        await putRecord('settings', currentSettings);
        showToast('Currency updated. Refresh page to see changes.', 'success');
    });
    
    // Category management
    function renderCategories() {
        const expenseContainer = document.getElementById('expenseCategoriesList');
        const incomeContainer = document.getElementById('incomeCategoriesList');
        
        const defaultExpense = ['food', 'transport', 'medical', 'rent', 'entertainment', 'shopping', 'bills', 'other'];
        const defaultIncome = ['salary', 'freelance', 'investment', 'gift', 'other'];
        
        renderCategoryTags(categories.expense, expenseContainer, async (cat) => {
            if (confirm(`Delete category "${cat}"?`)) {
                categories.expense = categories.expense.filter(c => c !== cat);
                await putRecord('categories', categories);
                renderCategories();
                showToast('Category deleted', 'success');
            }
        }, defaultExpense);
        
        renderCategoryTags(categories.income, incomeContainer, async (cat) => {
            if (confirm(`Delete category "${cat}"?`)) {
                categories.income = categories.income.filter(c => c !== cat);
                await putRecord('categories', categories);
                renderCategories();
                showToast('Category deleted', 'success');
            }
        }, defaultIncome);
    }
    
    renderCategories();
    
    // Add expense category
    document.getElementById('addExpenseCategoryBtn').addEventListener('click', async () => {
        const input = document.getElementById('newExpenseCategory');
        const newCat = input.value.trim();
        
        if (newCat && !categories.expense.includes(newCat)) {
            categories.expense.push(newCat);
            await putRecord('categories', categories);
            input.value = '';
            renderCategories();
            showToast('Category added', 'success');
        }
    });
    
    // Add income category
    document.getElementById('addIncomeCategoryBtn').addEventListener('click', async () => {
        const input = document.getElementById('newIncomeCategory');
        const newCat = input.value.trim();
        
        if (newCat && !categories.income.includes(newCat)) {
            categories.income.push(newCat);
            await putRecord('categories', categories);
            input.value = '';
            renderCategories();
            showToast('Category added', 'success');
        }
    });
    
    // Export data
    document.getElementById('exportDataBtn').addEventListener('click', async () => {
        const data = await exportData(username);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `finsight-export-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Data exported', 'success');
    });
    
    // Import data
    const importInput = document.getElementById('importDataInput');
    document.getElementById('importDataBtn').addEventListener('click', () => {
        importInput.click();
    });
    
    importInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        try {
            const text = await file.text();
            const data = JSON.parse(text);
            await importData(data, username);
            showToast('Data imported successfully. Refreshing...', 'success');
            setTimeout(() => window.location.reload(), 1500);
        } catch (error) {
            showToast('Error importing data: ' + error.message, 'error');
        }
    });
    
    // Clear all data
    document.getElementById('clearDataBtn').addEventListener('click', async () => {
        if (confirm('Are you sure you want to clear ALL data? This cannot be undone!')) {
            if (confirm('This will delete all transactions, budgets, and settings. Continue?')) {
                await clearAllData();
                showToast('All data cleared. Redirecting to login...', 'success');
                setTimeout(() => {
                    sessionStorage.clear();
                    window.location.href = 'index.html';
                }, 2000);
            }
        }
    });
}
