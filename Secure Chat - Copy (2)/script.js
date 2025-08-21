// --- Navigation: Home/About/Contact/History button logic ---
document.addEventListener('DOMContentLoaded', function() {
    const navLinks = document.querySelectorAll('.main-navbar .nav-link');
    const homeBtn = document.querySelector('.main-navbar .nav-link[href="#"]');
    const aboutBtn = document.querySelector('.main-navbar .nav-link[href="#about"]');
    const contactBtn = document.querySelector('.main-navbar .nav-link[href="#contact"]');
    const historyBtn = document.querySelector('.main-navbar .nav-link[href="#history"]');
    const about = document.getElementById('about');
    const contact = document.getElementById('contact');
    const wrapper = document.querySelector('.wrapper');
    // Remove all active classes initially
    navLinks.forEach(link => link.classList.remove('active'));
    // Home button click
    if (homeBtn) {
        homeBtn.addEventListener('click', function(e) {
            e.preventDefault();
            navLinks.forEach(link => link.classList.remove('active'));
            homeBtn.classList.add('active');
            window.scrollTo({ top: 0, behavior: 'smooth' });
            if (about) about.style.display = 'none';
            if (contact) contact.style.display = 'none';
            if (wrapper) wrapper.style.display = '';
        });
    }
    // About button click - show modal
    const aboutModal = document.getElementById('aboutModal');
    const closeAboutModal = document.getElementById('closeAboutModal');
    if (aboutBtn) {
        aboutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            navLinks.forEach(link => link.classList.remove('active'));
            aboutBtn.classList.add('active');
            if (aboutModal) aboutModal.style.display = 'block';
            if (about) about.style.display = 'none';
            if (contact) contact.style.display = 'none';
            if (wrapper) wrapper.style.display = '';
        });
    }
    // Close modal on X click or outside click
    if (closeAboutModal && aboutModal) {
        closeAboutModal.addEventListener('click', function() {
            aboutModal.style.display = 'none';
        });
        window.addEventListener('click', function(event) {
            if (event.target === aboutModal) {
                aboutModal.style.display = 'none';
            }
        });
    }
    // Contact button click
    if (contactBtn) {
        contactBtn.addEventListener('click', function(e) {
            e.preventDefault();
            navLinks.forEach(link => link.classList.remove('active'));
            contactBtn.classList.add('active');
            if (about) about.style.display = 'none';
            if (contact) contact.style.display = 'none';
            if (wrapper) wrapper.style.display = '';
            // Scroll to footer
            const footer = document.querySelector('footer');
            if (footer) footer.scrollIntoView({ behavior: 'smooth' });
        });
    }
    // History button click (optional: scroll to history section)
    if (historyBtn) {
        historyBtn.addEventListener('click', function(e) {
            e.preventDefault();
            navLinks.forEach(link => link.classList.remove('active'));
            historyBtn.classList.add('active');
            // Scroll to history section if you have one, or focus on history UI
            // Example: document.getElementById('encryptHistoryBtn').scrollIntoView({ behavior: 'smooth' });
        });
    }
    // Set Home as active by default on load
    if (homeBtn) homeBtn.classList.add('active');
});
// --- Navigation: Scroll to footer on Contact click ---
document.addEventListener('DOMContentLoaded', function() {
    const contactBtn = document.querySelector('.main-navbar .nav-link[href="#contact"]');
    const footer = document.querySelector('footer');
    if (contactBtn && footer) {
        contactBtn.addEventListener('click', function(e) {
            e.preventDefault();
            footer.scrollIntoView({ behavior: 'smooth' });
        });
    }
});
// --- Secure Chat Encryption/Decryption Script ---

// Get UI elements
const inputMessage = document.getElementById('inputMessage');
const secretKey = document.getElementById('secretKey');
const toggleSecretKeyVisibility = document.getElementById('toggleSecretKeyVisibility');
const encryptButton = document.getElementById('encryptButton');
const encryptedOutput = document.getElementById('encryptedOutput');
const copyEncryptedOutput = document.getElementById('copyEncryptedOutput');
const pasteInputMessage = document.getElementById('pasteInputMessage');
const clearInputMessage = document.getElementById('clearInputMessage');
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileStatus'); 
const encryptDropZone = document.getElementById('encryptDropZone');
const downloadEncryptedFile = document.getElementById('downloadEncryptedFile');

const inputEncrypted = document.getElementById('inputEncrypted');
const decryptKey = document.getElementById('decryptKey');
const decryptButton = document.getElementById('decryptButton');
const decryptedOutput = document.getElementById('decryptedOutput');
const copyDecryptedOutput = document.getElementById('copyDecryptedOutput');
const pasteInputEncrypted = document.getElementById('pasteInputEncrypted');
const clearInputEncrypted = document.getElementById('clearInputEncrypted');
const encInput = document.getElementById('encInput');
const encFileName = document.getElementById('encFileName');
const decryptDropZone = document.getElementById('decryptDropZone');
const downloadDecryptedFile = document.getElementById('downloadDecryptedFile');

const encryptStatus = document.getElementById('encryptStatus');
const encryptProgress = document.getElementById('encryptProgress');
const decryptStatus = document.getElementById('decryptStatus');
const decryptProgress = document.getElementById('decryptProgress');
const errorMessage = document.getElementById('errorMessage');

const encryptHistoryBtn = document.getElementById('encryptHistoryBtn');
const encryptHistory = document.getElementById('encryptHistory');
const encryptHistoryList = document.getElementById('encryptHistoryList');

const decryptHistoryBtn = document.getElementById('decryptHistoryBtn');
const decryptHistory = document.getElementById('decryptHistory');
const decryptHistoryList = document.getElementById('decryptHistoryList');

let lastEncryptedFileData = '';
let lastEncryptedFileMeta = null;
let lastDecryptedFileBlob = null;
let lastDecryptedFileMeta = null;

let encryptedHistory = [];
let decryptedHistory = [];

// ------------------ Helpers ------------------ //
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function wrapFileData(base64, meta) {
    return JSON.stringify({ meta, data: base64 });
}

function unwrapFileData(jsonStr) {
    try { return JSON.parse(jsonStr); } catch { return null; }
}

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptMessage(message, password) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(message));
    // Concatenate salt + iv + ciphertext
    const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
    return arrayBufferToBase64(combined.buffer);
}

async function decryptMessage(encryptedStr, password) {
    const dec = new TextDecoder();
    let bytes;
    try {
        bytes = new Uint8Array(base64ToArrayBuffer(encryptedStr));
    } catch { throw new Error('Invalid encrypted data'); }
    if (bytes.length < 16 + 12 + 1) throw new Error('Invalid encrypted data');
    const salt = bytes.slice(0, 16);
    const iv = bytes.slice(16, 28);
    const data = bytes.slice(28);
    try {
        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
        return dec.decode(decrypted);
    } catch { throw new Error('Wrong password or corrupted data'); }
}

function showStatus(element, message, type) {
    if (!element) return;
    element.textContent = message;
    element.className = 'status-message';
    if (type) element.classList.add(type);
}

function displayErrorMessage(msg) { if (errorMessage) errorMessage.textContent = msg; }
function enableDownload(button) { if (button) { button.disabled = false; button.classList.remove('just-enabled'); void button.offsetWidth; button.classList.add('just-enabled'); } }
function disableDownload(button) { if (button) { button.disabled = true; button.classList.remove('just-enabled'); } }

// ------------------ Password Toggle ------------------ //
if (toggleSecretKeyVisibility && secretKey) {
    toggleSecretKeyVisibility.addEventListener('click', () => {
        const isPassword = secretKey.type === 'password';
        secretKey.type = isPassword ? 'text' : 'password';
        toggleSecretKeyVisibility.src = isPassword ? '../Assets/eye.svg' : '../Assets/eye-closed.svg';
        toggleSecretKeyVisibility.alt = isPassword ? 'Hide' : 'Show';
    });
    toggleSecretKeyVisibility.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleSecretKeyVisibility.click(); } });
}

const toggleDecryptKeyVisibility = document.getElementById('toggleDecryptKeyVisibility');
if (toggleDecryptKeyVisibility && decryptKey) {
    toggleDecryptKeyVisibility.addEventListener('click', () => {
        const isPassword = decryptKey.type === 'password';
        decryptKey.type = isPassword ? 'text' : 'password';
        toggleDecryptKeyVisibility.src = isPassword ? '../Assets/eye.svg' : '../Assets/eye-closed.svg';
        toggleDecryptKeyVisibility.alt = isPassword ? 'Hide' : 'Show';
    });
    toggleDecryptKeyVisibility.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleDecryptKeyVisibility.click(); } });
}

// ------------------ File Input Handling ------------------ //
fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files[0]) {
        inputMessage.value = '';
        fileName.textContent = fileInput.files[0].name;
        lastEncryptedFileMeta = { name: fileInput.files[0].name, type: fileInput.files[0].type, size: fileInput.files[0].size };
    } else { fileName.textContent = 'No file chosen'; lastEncryptedFileMeta = null; }
});

encInput.addEventListener('change', () => {
    if (encInput.files && encInput.files[0]) {
        inputEncrypted.value = '';
        decryptedOutput.value = '';
        encFileName.textContent = encInput.files[0].name;
        lastDecryptedFileMeta = { name: encInput.files[0].name.replace(/\.enc$/i, '') };
        lastDecryptedFileBlob = null;
    } else { encFileName.textContent = ''; lastDecryptedFileMeta = null; }
});

// Auto-clear file when typing
inputMessage.addEventListener('input', () => {
    if (fileInput.files && fileInput.files.length > 0) { fileInput.value = ''; fileName.textContent = 'No file chosen'; lastEncryptedFileMeta = null; }
    disableDownload(downloadEncryptedFile);
});

// ------------------ Encrypt Button ------------------ //
encryptButton.addEventListener('click', async () => {
    displayErrorMessage('');
    showStatus(encryptStatus, 'Encrypting...', 'loading');
    if (encryptProgress) encryptProgress.textContent = '';
    encryptButton.disabled = true;
    const password = secretKey.value.trim();
    if (!password) { showStatus(encryptStatus, '', ''); displayErrorMessage('Enter secret key!'); encryptButton.disabled = false; return; }

    const isText = !!inputMessage.value.trim();
    const isFile = fileInput.files && fileInput.files[0];
    if (isText && isFile) { displayErrorMessage('Choose either text or file'); encryptButton.disabled = false; return; }

    try {
        if (isText) {
            const encrypted = await encryptMessage(inputMessage.value, password);
            encryptedOutput.value = encrypted;
            lastEncryptedFileData = encrypted;
            showStatus(encryptStatus, 'Text encrypted!', 'success');
            // Prevent duplicate entry if last is same
            if (!encryptedHistory[0] || encryptedHistory[0].type !== 'Text' || encryptedHistory[0].content !== inputMessage.value) {
                encryptedHistory.unshift({
                    type: 'Text',
                    content: inputMessage.value,
                    fileKind: 'Text',
                    date: new Date().toLocaleString()
                });
                updateEncryptHistory();
            }
            disableDownload(downloadEncryptedFile);
            if (encryptProgress) encryptProgress.textContent = '';
        } else if (isFile) {
            const file = fileInput.files[0];
            const chunkSize = 1024 * 1024; // 1MB
            const totalChunks = Math.ceil(file.size / chunkSize);
            let currentChunk = 0;
            let encryptedChunks = [];
            let meta = { name: file.name, type: file.type, size: file.size };
            let isEncrypting = true;
            const readNextChunk = async () => {
                if (!isEncrypting) return;
                const start = currentChunk * chunkSize;
                const end = Math.min(file.size, start + chunkSize);
                const blob = file.slice(start, end);
                const reader = new FileReader();
                reader.onload = async (e) => {
                    if (!isEncrypting) return;
                    const base64 = arrayBufferToBase64(e.target.result);
                    const wrapped = wrapFileData(base64, meta);
                    const encrypted = await encryptMessage(wrapped, password);
                    encryptedChunks.push(encrypted);
                    currentChunk++;
                    if (encryptProgress) encryptProgress.textContent = Math.floor((currentChunk / totalChunks) * 100) + '%';
                    if (currentChunk < totalChunks) {
                        readNextChunk();
                    } else {
                        isEncrypting = false;
                        lastEncryptedFileData = JSON.stringify({ meta, chunks: encryptedChunks });
                        setTimeout(() => {
                            encryptedOutput.value = '';
                            showStatus(encryptStatus, 'File encrypted!', 'success');
                            encryptedHistory.unshift({
                                type: 'File',
                                name: file.name,
                                fileKind: getFileKind(file),
                                date: new Date().toLocaleString()
                            });
                            updateEncryptHistory();
                            if (encryptProgress) encryptProgress.textContent = 'Done';
                            if (lastEncryptedFileData && downloadEncryptedFile) enableDownload(downloadEncryptedFile);
                            encryptButton.disabled = false;
                        }, 0);
                    }
                };
                reader.onerror = () => {
                    isEncrypting = false;
                    displayErrorMessage('File read error');
                    encryptButton.disabled = false;
                };
                reader.readAsArrayBuffer(blob);
            };
            readNextChunk();
        } else { displayErrorMessage('Type a message or select a file'); disableDownload(downloadEncryptedFile); if (encryptProgress) encryptProgress.textContent = ''; }
    } catch (e) { displayErrorMessage('Encryption failed'); disableDownload(downloadEncryptedFile); if (encryptProgress) encryptProgress.textContent = ''; }
    finally { if (!isFile) encryptButton.disabled = false; }
});

// ------------------ Decrypt Button ------------------ //
decryptButton.addEventListener('click', async () => {
    displayErrorMessage('');
    showStatus(decryptStatus, 'Decrypting...', 'loading');
    if (decryptProgress) decryptProgress.textContent = '';
    decryptButton.disabled = true;
    const password = decryptKey.value.trim();
    if (!password) { displayErrorMessage('Enter secret key!'); decryptButton.disabled = false; return; }

    const isText = !!inputEncrypted.value.trim();
    const isFile = encInput.files && encInput.files[0];
    if (isText && isFile) { displayErrorMessage('Choose either text or file'); decryptButton.disabled = false; return; }

    try {
        if (isText) {
            encInput.value = ''; encFileName.textContent = ''; lastDecryptedFileBlob = null; lastDecryptedFileMeta = null; decryptedOutput.value = '';
            try {
                const decrypted = await decryptMessage(inputEncrypted.value, password);
                decryptedOutput.value = decrypted;
                showStatus(decryptStatus, 'Text decrypted!', 'success');
                disableDownload(downloadDecryptedFile);
                decryptedHistory.unshift({
                    type: 'Text',
                    content: inputEncrypted.value,
                    fileKind: 'Text',
                    date: new Date().toLocaleString()
                });
                updateDecryptHistory();
                if (decryptProgress) decryptProgress.textContent = '';
            } catch { showStatus(decryptStatus, 'Wrong password or corrupted data', 'error'); displayErrorMessage('Wrong password or corrupted data'); disableDownload(downloadDecryptedFile); if (decryptProgress) decryptProgress.textContent = ''; }
        } else if (isFile) {
            decryptedOutput.value = '';
            const file = encInput.files[0];
            if (!file.name.endsWith('.enc')) { showStatus(decryptStatus, 'Only .enc files supported', 'error'); displayErrorMessage('Only .enc files supported'); disableDownload(downloadDecryptedFile); if (decryptProgress) decryptProgress.textContent = ''; return; }
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    // Parse chunked encrypted file
                    let parsed;
                    try {
                        parsed = JSON.parse(e.target.result);
                    } catch { throw new Error('Invalid encrypted file format'); }
                    if (!parsed || !parsed.chunks || !Array.isArray(parsed.chunks)) throw new Error('Invalid encrypted file format');
                    let decryptedParts = [];
                    for (let i = 0; i < parsed.chunks.length; i++) {
                        if (decryptProgress) decryptProgress.textContent = Math.floor((i / parsed.chunks.length) * 100) + '%';
                        const decryptedWrapped = await decryptMessage(parsed.chunks[i], password);
                        const part = unwrapFileData(decryptedWrapped);
                        if (!part || !part.data) throw new Error('Corrupted chunk');
                        decryptedParts.push(base64ToArrayBuffer(part.data));
                    }
                    // Merge all ArrayBuffers
                    let totalLength = decryptedParts.reduce((acc, buf) => acc + buf.byteLength, 0);
                    let merged = new Uint8Array(totalLength);
                    let offset = 0;
                    for (let part of decryptedParts) {
                        merged.set(new Uint8Array(part), offset);
                        offset += part.byteLength;
                    }
                    lastDecryptedFileBlob = new Blob([merged], { type: parsed.meta.type || 'application/octet-stream' });
                    lastDecryptedFileMeta = parsed.meta;
                    showStatus(decryptStatus, `File "${parsed.meta.name}" decrypted!`, 'success');
                    enableDownload(downloadDecryptedFile);
                    decryptedHistory.unshift({
                        type: 'File',
                        name: parsed.meta.name,
                        fileKind: getFileKind(parsed.meta),
                        date: new Date().toLocaleString()
                    });
                    updateDecryptHistory();
                    if (decryptProgress) decryptProgress.textContent = 'Done';
                } catch (err) {
                    showStatus(decryptStatus, 'Wrong password or corrupted file', 'error');
                    displayErrorMessage('Wrong password or corrupted file');
                    disableDownload(downloadDecryptedFile);
                    if (decryptProgress) decryptProgress.textContent = '';
                } finally { decryptButton.disabled = false; }
            };
            reader.readAsText(file);
        } else { showStatus(decryptStatus, 'Paste encrypted text or select .enc file', 'error'); displayErrorMessage('Paste encrypted text or select .enc file'); if (decryptProgress) decryptProgress.textContent = ''; }
    } catch { showStatus(decryptStatus, 'Decryption failed', 'error'); displayErrorMessage('Decryption failed'); if (decryptProgress) decryptProgress.textContent = ''; }
    finally { decryptButton.disabled = false; }
});

// ------------------ Download Buttons ------------------ //
downloadEncryptedFile.addEventListener('click', () => {
    if (!lastEncryptedFileData) return;
    const downloadProgress = document.getElementById('downloadEncryptedProgress');
    if (downloadProgress) downloadProgress.textContent = '0%';
    const blob = new Blob([lastEncryptedFileData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'encrypted.enc';
    document.body.appendChild(a);
    // Simulate progress for UX (since browser download is instant for blobs)
    let percent = 0;
    const fakeProgress = setInterval(() => {
        percent += 20;
        if (downloadProgress) downloadProgress.textContent = (percent >= 100 ? '100%' : percent + '%');
        if (percent >= 100) {
            clearInterval(fakeProgress);
            setTimeout(() => { if (downloadProgress) downloadProgress.textContent = ''; }, 600);
        }
    }, 60);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
        // Disable the button after download
        disableDownload(downloadEncryptedFile);
});

downloadDecryptedFile.addEventListener('click', () => {
    if (!lastDecryptedFileBlob || !lastDecryptedFileMeta) return;
    const downloadProgress = document.getElementById('downloadDecryptedProgress');
    if (downloadProgress) downloadProgress.textContent = '0%';
    const url = URL.createObjectURL(lastDecryptedFileBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = lastDecryptedFileMeta.name || 'decrypted';
    document.body.appendChild(a);
    // Simulate progress for UX (since browser download is instant for blobs)
    let percent = 0;
    const fakeProgress = setInterval(() => {
        percent += 20;
        if (downloadProgress) downloadProgress.textContent = (percent >= 100 ? '100%' : percent + '%');
        if (percent >= 100) {
            clearInterval(fakeProgress);
            setTimeout(() => { if (downloadProgress) downloadProgress.textContent = ''; }, 600);
        }
    }, 60);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
        // Disable the button after download
        disableDownload(downloadDecryptedFile);
});

// ------------------ Copy/Paste ------------------ //
copyEncryptedOutput.addEventListener('click', () => { if (!encryptedOutput.value) return; navigator.clipboard.writeText(encryptedOutput.value); showStatus(encryptStatus, 'Copied!', 'success'); });
copyDecryptedOutput.addEventListener('click', () => { if (!decryptedOutput.value) return; navigator.clipboard.writeText(decryptedOutput.value); showStatus(decryptStatus, 'Copied!', 'success'); });

pasteInputMessage.addEventListener('click', async () => { try { inputMessage.value = await navigator.clipboard.readText(); disableDownload(downloadEncryptedFile); showStatus(encryptStatus, 'Pasted!', 'success'); } catch { showStatus(encryptStatus, 'Failed to paste', 'error'); } });
pasteInputEncrypted.addEventListener('click', async () => { try { inputEncrypted.value = await navigator.clipboard.readText(); encInput.value = ''; encFileName.textContent = ''; lastDecryptedFileBlob = null; lastDecryptedFileMeta = null; decryptedOutput.value = ''; disableDownload(downloadDecryptedFile); showStatus(decryptStatus, 'Pasted!', 'success'); } catch { showStatus(decryptStatus, 'Failed to paste', 'error'); } });

// ------------------ Clear Inputs ------------------ //
clearInputMessage.addEventListener('click', () => { inputMessage.value = ''; disableDownload(downloadEncryptedFile); showStatus(encryptStatus, 'Cleared', 'success'); });
clearInputEncrypted.addEventListener('click', () => { inputEncrypted.value = ''; disableDownload(downloadDecryptedFile); showStatus(decryptStatus, 'Cleared', 'success'); });

// ------------------ History Management ------------------ //
function updateEncryptHistory() {
    encryptHistoryList.innerHTML = '';
    encryptedHistory.forEach((item, idx) => {
        const tr = document.createElement('tr');
        // Serial cell
        const tdSerial = document.createElement('td');
        tdSerial.style.padding = '4px 6px';
        tdSerial.textContent = (idx + 1).toString();
        // Message cell
        const tdMsg = document.createElement('td');
        tdMsg.style.padding = '4px 6px';
        tdMsg.style.wordBreak = 'break-all';
        if (item.type === 'Text') {
            tdMsg.textContent = truncate(item.content, 20);
            tdMsg.title = item.content;
        } else {
            tdMsg.textContent = item.name;
            tdMsg.title = item.name;
        }
        // Type cell
        const tdType = document.createElement('td');
        tdType.style.padding = '4px 6px';
        tdType.textContent = item.fileKind;
        // Date cell
        const tdDate = document.createElement('td');
        tdDate.style.padding = '4px 6px';
        tdDate.textContent = item.date;
    tr.appendChild(tdSerial);
    tr.appendChild(tdMsg);
    tr.appendChild(tdDate);
    tr.appendChild(tdType);
        tr.style.cursor = 'pointer';
        tr.addEventListener('click', () => {
            if(item.type === 'Text') inputMessage.value = item.content;
            else alert('File history cannot be pasted');
            showStatus(encryptStatus, 'History item selected!', 'success');
        });
        encryptHistoryList.appendChild(tr);
    });
}

function updateDecryptHistory() {
    decryptHistoryList.innerHTML = '';
    decryptedHistory.forEach((item, idx) => {
        const tr = document.createElement('tr');
        // Serial cell
        const tdSerial = document.createElement('td');
        tdSerial.style.padding = '4px 6px';
        tdSerial.textContent = (idx + 1).toString();
        // Message cell
        const tdMsg = document.createElement('td');
        tdMsg.style.padding = '4px 6px';
        tdMsg.style.wordBreak = 'break-all';
        if (item.type === 'Text') {
            tdMsg.textContent = truncate(item.content, 20);
            tdMsg.title = item.content;
        } else {
            tdMsg.textContent = item.name;
            tdMsg.title = item.name;
        }
        // Type cell
        const tdType = document.createElement('td');
        tdType.style.padding = '4px 6px';
        tdType.textContent = item.fileKind;
        // Date cell
        const tdDate = document.createElement('td');
        tdDate.style.padding = '4px 6px';
        tdDate.textContent = item.date;
    tr.appendChild(tdSerial);
    tr.appendChild(tdMsg);
    tr.appendChild(tdDate);
    tr.appendChild(tdType);
        tr.style.cursor = 'pointer';
        tr.addEventListener('click', () => {
            if(item.type === 'Text') inputEncrypted.value = item.content;
            else alert('File history cannot be pasted');
            showStatus(decryptStatus, 'History item selected!', 'success');
        });
        decryptHistoryList.appendChild(tr);
    });
}
// Helper to get file kind from file or meta
function getFileKind(fileOrMeta) {
    let type = fileOrMeta.type || '';
    if (!type && fileOrMeta.name) {
        const ext = fileOrMeta.name.split('.').pop().toLowerCase();
        if (["jpg","jpeg","png","gif","bmp","webp","svg"].includes(ext)) return "Image";
        if (["mp3","wav","ogg","m4a","aac"].includes(ext)) return "Audio";
        if (["mp4","avi","mov","wmv","webm","mkv"].includes(ext)) return "Video";
        if (["pdf","doc","docx","xls","xlsx","ppt","pptx","txt","csv","rtf"].includes(ext)) return "Document";
        return "Other";
    }
    if (type.startsWith('image/')) return 'Image';
    if (type.startsWith('audio/')) return 'Audio';
    if (type.startsWith('video/')) return 'Video';
    if (type === 'application/pdf' || type.includes('word') || type.includes('excel') || type.includes('powerpoint') || type.includes('text')) return 'Document';
    return 'Other';
}

// Helper to get icon for file kind
function getFileKindIcon(kind) {
    switch(kind) {
        case 'Image': return '🖼️';
        case 'Audio': return '🎵';
        case 'Video': return '🎬';
        case 'Document': return '📄';
        case 'Text': return '📝';
        default: return '📦';
    }
}

// Helper to truncate long text
function truncate(str, n) {
    return (str && str.length > n) ? str.substr(0, n-1) + '…' : str;
}

encryptHistoryBtn.addEventListener('click', () => encryptHistory.classList.toggle('hidden'));
decryptHistoryBtn.addEventListener('click', () => decryptHistory.classList.toggle('hidden'));

document.querySelectorAll('.close-history').forEach(btn => {
    btn.addEventListener('click', () => btn.closest('.history-list').classList.add('hidden'));
});

// ------------------ Drag & Drop ------------------ //
function setupDragDrop(zone, input) {
    ['dragenter','dragover'].forEach(event => zone.addEventListener(event, e => { e.preventDefault(); e.stopPropagation(); zone.classList.add('dragover'); }));
    ['dragleave','drop'].forEach(event => zone.addEventListener(event, e => { e.preventDefault(); e.stopPropagation(); zone.classList.remove('dragover'); }));
    zone.addEventListener('drop', e => { if(e.dataTransfer.files.length>0){ input.files=e.dataTransfer.files; input.dispatchEvent(new Event('change')); } });
}
setupDragDrop(encryptDropZone, fileInput);
setupDragDrop(decryptDropZone, encInput);
