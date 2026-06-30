import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './app';

// 🛠️ CRITICAL CONFLICT FIX: Clear the legacy vanilla window.onload hook
// This stops the old script at (index):123 from running and crashing the page.
window.onload = null;

// Try finding 'root' first, fallback to 'app' if that's what your index.html uses
const container = document.getElementById('root') || document.getElementById('app') || document.body;

const root = createRoot(container);
root.render(<App />);
