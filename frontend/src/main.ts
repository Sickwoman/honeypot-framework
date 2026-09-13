// Entry point. Everything lives in app.ts; this only wires it to the page so
// that the application itself stays importable (and testable) without side
// effects. See app.test.ts.

import './style.css';
import { createApp } from './app';

const root = document.querySelector<HTMLDivElement>('#app');
if (!root) throw new Error('#app element is missing from index.html');

const app = createApp(root);
app.render();
void app.fetchAll();
app.startPolling();
