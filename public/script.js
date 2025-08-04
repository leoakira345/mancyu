// public/script.js
const API_BASE_URL = 'http://localhost:3000/api'; // Adjust if your server runs on a different port/host
const socket = io('http://localhost:3000'); // Connect to your Socket.IO server

// --- DOM Elements ---
const authSection = document.getElementById('auth-section');
const chatSection = document.getElementById('chat-section');

const showLoginBtn = document.getElementById('show-login');
const showSignupBtn = document.getElementById('show-signup');
const loginForm = document.getElementById('login-form');
const signupForm = document.getElementById('signup-form');
const loginMessage = document.getElementById('login-message');
const signupMessage = document.getElementById('signup-message');

const currentUsernameSpan = document.getElementById('current-username');
const currentUserIdSpan = document.getElementById('current-userid');
const logoutBtn = document.getElementById('logout-btn');

const friendSearchInput = document.getElementById('friend-search-input');
const searchFriendBtn = document.getElementById('search-friend-btn');
const searchResultsDiv = document.getElementById('search-results');
const friendsList = document.getElementById('friends-list');

const chatPartnerName = document.getElementById('chat-partner-name');
const messagesContainer = document.getElementById('messages-container');
const messageInput = document.getElementById('message-input');
const sendMessageBtn = document.getElementById('send-message-btn');
const uploadImageBtn = document.getElementById('upload-image-btn');
const imageUploadInput = document.getElementById('image-upload');
const recordVoiceBtn = document.getElementById('record-voice-btn');
const sendGifBtn = document.getElementById('send-gif-btn');
const typingIndicator = document.getElementById('typing-indicator');

// --- Global State ---
let currentUser = null;
let currentChatPartner = null; // Stores the _id of the friend currently chatting with
let mediaRecorder;
let audioChunks = [];
let typingTimeout;

// --- Utility Functions ---
function showSection(sectionId) {
    authSection.classList.add('hidden');
    chatSection.classList.add('hidden');
    document.getElementById(sectionId).classList.remove('hidden');
}

function showAuthForm(formId) {
    loginForm.classList.remove('active');
    signupForm.classList.remove('active');
    showLoginBtn.classList.remove('active');
    showSignupBtn.classList.remove('active');

    document.getElementById(formId).classList.add('active');
    if (formId === 'login-form') {
        showLoginBtn.classList.add('active');
    } else {
        showSignupBtn.classList.add('active');
    }
    loginMessage.textContent = '';
    signupMessage.textContent = '';
}

function displayMessage(element, text, type) {
    element.textContent = text;
    element.className = `message ${type}`;
}

function getToken() {
    return localStorage.getItem('token');
}

function setToken(token) {
    localStorage.setItem('token', token);
}

function removeToken() {
    localStorage.removeItem('token');
}

function getCurrentUserId() {
    return localStorage.getItem('userId');
}

function setCurrentUserId(userId) {
    localStorage.setItem('userId', userId);
}

function removeCurrentUserId() {
    localStorage.removeItem('userId');
}

function getCurrentUsername() {
    return localStorage.getItem('username');
}

function setCurrentUsername(username) {
    localStorage.setItem('username', username);
}

function removeCurrentUsername() {
    localStorage.removeItem('username');
}

// --- Authentication Handlers ---
showLoginBtn.addEventListener('click', () => showAuthForm('login-form'));
showSignupBtn.addEventListener('click', () => showAuthForm('signup-form'));

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const usernameOrEmail = document.getElementById('login-username-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const res = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usernameOrEmail, password }),
        });
        const data = await res.json();

        if (res.ok) {
            displayMessage(loginMessage, data.message, 'success');
            setToken(data.token);
            setCurrentUserId(data.userId);
            setCurrentUsername(data.username);
            currentUser = { _id: data.userId, username: data.username }; // Store for client-side use
            initChatApp();
        } else {
            displayMessage(loginMessage, data.message || 'Login failed', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        displayMessage(loginMessage, 'Network error. Please try again.', 'error');
    }
});

signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fullName = document.getElementById('signup-fullname').value;
    const username = document.getElementById('signup-username').value;
    const email = document.getElementById('signup-email').value;
    const phoneNumber = document.getElementById('signup-phone').value;
    const country = document.getElementById('signup-country').value;
    const password = document.getElementById('signup-password').value;

    try {
        const res = await fetch(`${API_BASE_URL}/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fullName, username, email, phoneNumber, country, password }),
        });
        const data = await res.json();

        if (res.ok) {
            displayMessage(signupMessage, `${data.message}. Your User ID is: ${data.userId}`, 'success');
            // Optionally log in directly after signup
            setToken(data.token);
            setCurrentUserId(data.userId);
            setCurrentUsername(data.username);
            currentUser = { _id: data.userId, username: data.username };
            initChatApp();
        } else {
            displayMessage(signupMessage, data.message || 'Signup failed', 'error');
        }
    } catch (error) {
        console.error('Signup error:', error);
        displayMessage(signupMessage, 'Network error. Please try again.', 'error');
    }
});

logoutBtn.addEventListener('click', () => {
    removeToken();
    removeCurrentUserId();
    removeCurrentUsername();
    currentUser = null;
    currentChatPartner = null;
    socket.disconnect(); // Disconnect socket on logout
    showSection('auth-section');
    showAuthForm('login-form');
    friendsList.innerHTML = '';
    messagesContainer.innerHTML = '';
    chatPartnerName.textContent = 'Select a friend to chat';
});

// --- Chat App Initialization ---
async function initChatApp() {
    const token = getToken();
    const userId = getCurrentUserId();
    const username = getCurrentUsername();

    if (token && userId && username) {
        currentUser = { _id: userId, username: username };
        currentUsernameSpan.textContent = username;
        currentUserIdSpan.textContent = userId;
        showSection('chat-section');
        socket.connect(); // Reconnect socket if it was disconnected
        socket.emit('authenticate', token); // Authenticate socket connection
        await loadFriends();
    } else {
        showSection('auth-section');
        showAuthForm('login-form');
    }
}

// --- Friends List Management ---
async function loadFriends() {
    const token = getToken();
    if (!token) return;

    try {
        const res = await fetch(`${API_BASE_URL}/users/friends`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        const friends = await res.json();

        if (res.ok) {
            friendsList.innerHTML = '';
            friends.forEach((friend) => {
                addFriendToList(friend);
            });
        } else {
            console.error('Failed to load friends:', friends.message);
        }
    } catch (error) {
        console.error('Error loading friends:', error);
    }
}

function addFriendToList(friend) {
    const li = document.createElement('li');
    li.dataset.friendId = friend._id;
    li.innerHTML = `
        <span>${friend.username} (${friend.userId})</span>
        <span class="friend-status-indicator" data-status="offline"></span>
    `;
    li.addEventListener('click', () => selectChatPartner(friend));
    friendsList.appendChild(li);
}

// --- Add Friend Functionality ---
searchFriendBtn.addEventListener('click', async () => {
    const searchId = friendSearchInput.value.trim();
    if (!searchId) {
        searchResultsDiv.innerHTML = '<p class="message error">Please enter a User ID.</p>';
        return;
    }

    const token = getToken();
    if (!token) return;

    try {
        const res = await fetch(`${API_BASE_URL}/users/search/${searchId}`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();

        if (res.ok) {
            searchResultsDiv.innerHTML = `
                <div class="user-card">
                    <span>${data.username} (${data.userId})</span>
                    <button data-friend-id="${data._id}" class="add-friend-btn">Add Friend</button>
                </div>
            `;
            document.querySelector('.add-friend-btn').addEventListener('click', addFriendHandler);
        } else {
            searchResultsDiv.innerHTML = `<p class="message error">${data.message || 'User not found.'}</p>`;
        }
    } catch (error) {
        console.error('Search friend error:', error);
        searchResultsDiv.innerHTML = '<p class="message error">Error searching for user.</p>';
    }
});

async function addFriendHandler(e) {
    const friendId = e.target.dataset.friendId;
    const token = getToken();
    if (!token || !friendId) return;

    try {
        const res = await fetch(`${API_BASE_URL}/users/add-friend`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ friendId }),
        });
        const data = await res.json();

        if (res.ok) {
            searchResultsDiv.innerHTML = `<p class="message success">${data.message}</p>`;
            await loadFriends(); // Reload friends list
        } else {
            searchResultsDiv.innerHTML = `<p class="message error">${data.message || 'Failed to add friend.'}</p>`;
        }
    } catch (error) {
        console.error('Add friend error:', error);
        searchResultsDiv.innerHTML = '<p class="message error">Error adding friend.</p>';
    }
}

// --- Chat Functionality ---
async function selectChatPartner(friend) {
    // Remove active class from previous friend
    const currentActive = document.querySelector('#friends-list li.active');
    if (currentActive) {
        currentActive.classList.remove('active');
    }

    // Add active class to selected friend
    const selectedLi = document.querySelector(`#friends-list li[data-friend-id="${friend._id}"]`);
    if (selectedLi) {
        selectedLi.classList.add('active');
    }

    currentChatPartner = friend;
    chatPartnerName.textContent = `${friend.username} (${friend.userId})`;
    messagesContainer.innerHTML = ''; // Clear previous messages
    await loadChatHistory(friend._id);
    messagesContainer.scrollTop = messagesContainer.scrollHeight; // Scroll to bottom
    messageInput.focus();
}

async function loadChatHistory(receiverId) {
    const token = getToken();
    if (!token) return;

    try {
        const res = await fetch(`${API_BASE_URL}/messages/${receiverId}`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        const messages = await res.json();

        if (res.ok) {
            messages.forEach((msg) => displayChatMessage(msg));
        } else {
            console.error('Failed to load chat history:', messages.message);
        }
    } catch (error) {
        console.error('Error loading chat history:', error);
    }
}

function displayChatMessage(message) {
    const isSent = message.sender.userId === getCurrentUserId();
    const bubble = document.createElement('div');
    bubble.classList.add('message-bubble', isSent ? 'sent' : 'received');

    let contentHtml = '';
    if (message.type === 'text') {
        contentHtml = `<p>${message.content}</p>`;
    } else if (message.type === 'image') {
        // For simplicity, assuming content is a base64 string or URL
        contentHtml = `<img src="${message.content}" alt="Image message">`;
    } else if (message.type === 'audio') {
        // For simplicity, assuming content is a base64 string or URL
        contentHtml = `<audio controls src="${message.content}"></audio>`;
    } else if (message.type === 'gif') {
        contentHtml = `<img src="${message.content}" alt="GIF message" class="gif-message">`;
    }

    const senderName = isSent ? 'You' : message.sender.username;
    const timestamp = new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    bubble.innerHTML = `
        ${contentHtml}
        <div class="message-info">${senderName} - ${timestamp}</div>
    `;
    messagesContainer.appendChild(bubble);
    messagesContainer.scrollTop = messagesContainer.scrollHeight; // Keep scrolled to bottom
}

sendMessageBtn.addEventListener('click', () => {
    const content = messageInput.value.trim();
    if (content && currentChatPartner) {
        socket.emit('private_message', { receiverId: currentChatPartner._id, content, type: 'text' });
        messageInput.value = '';
        socket.emit('stop_typing', { receiverId: currentChatPartner._id }); // Stop typing after sending
    }
});

messageInput.addEventListener('input', () => {
    if (!currentChatPartner) return;

    socket.emit('typing', { receiverId: currentChatPartner._id });
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
        socket.emit('stop_typing', { receiverId: currentChatPartner._id });
    }, 3000); // Stop typing after 3 seconds of no input
});

// --- Media & GIF Functionality ---
uploadImageBtn.addEventListener('click', () => imageUploadInput.click());

imageUploadInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file && currentChatPartner) {
        const reader = new FileReader();
        reader.onload = (event) => {
            // In a real app, you'd upload this to cloud storage (e.g., AWS S3, Cloudinary)
            // and send the URL. For this example, we'll send base64 for small images.
            // WARNING: Base64 for large files is inefficient and can crash the app.
            socket.emit('private_message', { receiverId: currentChatPartner._id, content: event.target.result, type: 'image' });
        };
        reader.readAsDataURL(file);
    }
});

recordVoiceBtn.addEventListener('click', async () => {
    if (!mediaRecorder || mediaRecorder.state === 'inactive') {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);
            audioChunks = [];

            mediaRecorder.ondataavailable = (event) => {
                audioChunks.push(event.data);
            };

            mediaRecorder.onstop = () => {
                const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                const reader = new FileReader();
                reader.onload = (event) => {
                    // Similar to images, send base64 for demo. Upload to cloud for production.
                    socket.emit('private_message', { receiverId: currentChatPartner._id, content: event.target.result, type: 'audio' });
                };
                reader.readAsDataURL(audioBlob);
            };

            mediaRecorder.start();
            recordVoiceBtn.textContent = 'Stop Recording';
            recordVoiceBtn.style.backgroundColor = 'red';
        } catch (err) {
            console.error('Error accessing microphone:', err);
            alert('Could not access microphone. Please ensure permissions are granted.');
        }
    } else if (mediaRecorder.state === 'recording') {
        mediaRecorder.stop();
        recordVoiceBtn.textContent = 'Record Voice';
        recordVoiceBtn.style.backgroundColor = ''; // Reset to default
    }
});
