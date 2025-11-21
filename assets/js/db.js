/**
 * IndexedDB Wrapper Module
 * Provides a promise-based interface for all database operations
 * Stores: users, transactions, budgets, settings, categories
 */

const DB_NAME = 'FinSightDB';
const DB_VERSION = 1;

let db = null;

/**
 * Initialize and open the IndexedDB database
 * Creates object stores if they don't exist
 */
export async function initDB() {
    return new Promise((resolve, reject) => {
        if (db) {
            resolve(db);
            return;
        }

        if (!window.indexedDB) {
            reject(new Error('IndexedDB is not supported in this browser'));
            return;
        }

        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            db = request.result;
            resolve(db);
        };

        // Create object stores on first run or version upgrade
        request.onupgradeneeded = (event) => {
            const database = event.target.result;

            // Users store: username is the key
            if (!database.objectStoreNames.contains('users')) {
                database.createObjectStore('users', { keyPath: 'username' });
            }

            // Transactions store: auto-incrementing id
            if (!database.objectStoreNames.contains('transactions')) {
                const txStore = database.createObjectStore('transactions', { 
                    keyPath: 'id', 
                    autoIncrement: true 
                });
                txStore.createIndex('username', 'username', { unique: false });
                txStore.createIndex('type', 'type', { unique: false });
                txStore.createIndex('category', 'category', { unique: false });
                txStore.createIndex('date', 'date', { unique: false });
            }

            // Budgets store: composite key (username + category)
            if (!database.objectStoreNames.contains('budgets')) {
                const budgetStore = database.createObjectStore('budgets', { 
                    keyPath: ['username', 'category'] 
                });
                budgetStore.createIndex('username', 'username', { unique: false });
            }

            // Settings store: username is the key
            if (!database.objectStoreNames.contains('settings')) {
                database.createObjectStore('settings', { keyPath: 'username' });
            }

            // Categories store: username is the key
            if (!database.objectStoreNames.contains('categories')) {
                database.createObjectStore('categories', { keyPath: 'username' });
            }
        };
    });
}

/**
 * Generic function to add or update a record in a store
 */
export async function putRecord(storeName, record) {
    const database = await initDB();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([storeName], 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.put(record);
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Generic function to get a record by key
 */
export async function getRecord(storeName, key) {
    const database = await initDB();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([storeName], 'readonly');
        const store = transaction.objectStore(storeName);
        const request = store.get(key);
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Generic function to get all records from a store
 */
export async function getAllRecords(storeName) {
    const database = await initDB();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([storeName], 'readonly');
        const store = transaction.objectStore(storeName);
        const request = store.getAll();
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Generic function to delete a record by key
 */
export async function deleteRecord(storeName, key) {
    const database = await initDB();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([storeName], 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.delete(key);
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

/**
 * Get records by index
 */
export async function getRecordsByIndex(storeName, indexName, value) {
    const database = await initDB();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction([storeName], 'readonly');
        const store = transaction.objectStore(storeName);
        const index = store.index(indexName);
        const request = index.getAll(value);
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Clear all data from the database (for reset functionality)
 */
export async function clearAllData() {
    const database = await initDB();
    const storeNames = ['users', 'transactions', 'budgets', 'settings', 'categories'];
    
    return Promise.all(storeNames.map(storeName => {
        return new Promise((resolve, reject) => {
            const transaction = database.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.clear();
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }));
}

/**
 * Export all data as JSON
 */
export async function exportData(username) {
    const transactions = await getRecordsByIndex('transactions', 'username', username);
    const budgets = await getRecordsByIndex('budgets', 'username', username);
    const settings = await getRecord('settings', username);
    const categories = await getRecord('categories', username);
    
    return {
        username,
        transactions,
        budgets,
        settings,
        categories,
        exportDate: new Date().toISOString()
    };
}

/**
 * Import data from JSON
 */
export async function importData(data, username) {
    // Import transactions
    if (data.transactions) {
        for (const tx of data.transactions) {
            tx.username = username; // Override username
            delete tx.id; // Let DB auto-generate new IDs
            await putRecord('transactions', tx);
        }
    }
    
    // Import budgets
    if (data.budgets) {
        for (const budget of data.budgets) {
            budget.username = username;
            await putRecord('budgets', budget);
        }
    }
    
    return true;
}
