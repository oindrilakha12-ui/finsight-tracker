/**
 * Authentication Module
 * Handles user signup, login, and password security using Web Crypto API
 * 
 * SECURITY APPROACH:
 * - Passwords are never stored in plaintext
 * - Uses PBKDF2 with SHA-256 for key derivation (100,000 iterations)
 * - Random salt generated for each user
 * - Constant-time comparison to prevent timing attacks
 */

import { initDB, getRecord, putRecord } from './db.js';

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const KEY_LENGTH = 256;

/**
 * Generate a random salt for password hashing
 */
function generateSalt() {
    return window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/**
 * Convert ArrayBuffer to hex string
 */
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Convert hex string to ArrayBuffer
 */
function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Derive a key from password using PBKDF2
 * @param {string} password - Plain text password
 * @param {Uint8Array} salt - Salt for key derivation
 * @returns {Promise<ArrayBuffer>} - Derived key bits
 */
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // Import password as a key
    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );

    
    // Derive bits using PBKDF2
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        baseKey,
        KEY_LENGTH
    );
    
    return derivedBits;
}

/**
 * Constant-time comparison to prevent timing attacks
 * Compares two hex strings
 */
function constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

/**
 * Sign up a new user
 * @param {string} username
 * @param {string} password
 * @returns {Promise<boolean>}
 */
async function signup(username, password) {
    await initDB();
    
    // Check if user already exists
    const existingUser = await getRecord('users', username);
    if (existingUser) {
        throw new Error('Username already exists');
    }
    
    // Generate salt and derive key
    const salt = generateSalt();
    const derivedKey = await deriveKey(password, salt);
    
    // Store user with salt and derived key (never store plaintext password!)
    const user = {
        username,
        salt: bufferToHex(salt),
        passwordHash: bufferToHex(derivedKey),
        createdAt: new Date().toISOString()
    };
    
    await putRecord('users', user);
    
    // Initialize default settings and categories for new user
    await initializeUserData(username);
    
    return true;
}

/**
 * Login an existing user
 * @param {string} username
 * @param {string} password
 * @returns {Promise<boolean>}
 */
async function login(username, password) {
    await initDB();
    
    // Get user record
    const user = await getRecord('users', username);
    if (!user) {
        throw new Error('Invalid username or password');
    }
    
    // Derive key from provided password using stored salt
    const salt = hexToBuffer(user.salt);
    const derivedKey = await deriveKey(password, salt);
    const derivedKeyHex = bufferToHex(derivedKey);
    
    // Compare derived key with stored hash (constant-time comparison)
    if (!constantTimeCompare(derivedKeyHex, user.passwordHash)) {
        throw new Error('Invalid username or password');
    }
    
    return true;
}

/**
 * Initialize default data for a new user
 */
async function initializeUserData(username) {
    // Default categories
    const categories = {
        username,
        expense: ['food', 'transport', 'medical', 'rent', 'entertainment', 'shopping', 'bills', 'other'],
        income: ['salary', 'freelance', 'investment', 'gift', 'other']
    };
    await putRecord('categories', categories);
    
    // Default settings
    const settings = {
        username,
        theme: 'light',
        currency: 'INR'
    };
    await putRecord('settings', settings);
}

/**
 * Get current logged-in user from sessionStorage
 */
export function getCurrentUser() {
    return sessionStorage.getItem('currentUser');
}

/**
 * Set current user in sessionStorage
 */
export function setCurrentUser(username) {
    sessionStorage.setItem('currentUser', username);
}

/**
 * Logout current user
 */
export function logout() {
    sessionStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

/**
 * Check if user is authenticated, redirect to login if not
 */
export function requireAuth() {
    const user = getCurrentUser();
    if (!user) {
        window.location.href = 'index.html';
        return null;
    }
    return user;
}

// UI Event Handlers for index.html
if (window.location.pathname.endsWith('index.html') || window.location.pathname === '/') {
    document.addEventListener('DOMContentLoaded', async () => {
        await initDB();
        
        const loginForm = document.getElementById('loginForm');
        const signupForm = document.getElementById('signupForm');
        const showSignupLink = document.getElementById('showSignup');
        const showLoginLink = document.getElementById('showLogin');
        const messageDiv = document.getElementById('authMessage');
        
        // Toggle between login and signup forms
        showSignupLink?.addEventListener('click', (e) => {
            e.preventDefault();
            loginForm.classList.add('hidden');
            signupForm.classList.remove('hidden');
            messageDiv.classList.add('hidden');
        });
        
        showLoginLink?.addEventListener('click', (e) => {
            e.preventDefault();
            signupForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
            messageDiv.classList.add('hidden');
        });
        
        // Handle login
        loginForm?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value.trim();
            const password = document.getElementById('loginPassword').value;
            
            try {
                await login(username, password);
                setCurrentUser(username);
                window.location.href = 'dashboard.html';
            } catch (error) {
                showMessage(error.message, 'error');
            }
        });
        
        // Handle signup
        signupForm?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('signupUsername').value.trim();
            const password = document.getElementById('signupPassword').value;
            const passwordConfirm = document.getElementById('signupPasswordConfirm').value;
            
            if (password !== passwordConfirm) {
                showMessage('Passwords do not match', 'error');
                return;
            }
            
            if (password.length < 6) {
                showMessage('Password must be at least 6 characters', 'error');
                return;
            }
            
            try {
                await signup(username, password);
                showMessage('Account created successfully! Logging in...', 'success');
                setTimeout(() => {
                    setCurrentUser(username);
                    window.location.href = 'dashboard.html';
                }, 1000);
            } catch (error) {
                showMessage(error.message, 'error');
            }
        });
        
        function showMessage(message, type) {
            messageDiv.textContent = message;
            messageDiv.className = `message ${type}`;
            messageDiv.classList.remove('hidden');
        }
    });
}
