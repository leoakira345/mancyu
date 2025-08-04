// server/server.js
require('dotenv').config(); // Load environment variables from .env
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const { connectDB, User, Message } = require('./db');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Connect to Database
connectDB();

// Middleware
app.use(express.json()); // For parsing application/json
app.use(express.static('public')); // Serve static files from 'public' directory

// JWT Authentication Middleware (for protected routes/sockets)
const protect = (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded.id; // Store user ID from token
            next();
        } catch (error) {
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }
    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

// Generate JWT Token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '1h',
    });
};

// --- API Routes ---

// @route   POST /api/signup
// @desc    Register new user
// @access  Public
app.post('/api/signup', async (req, res) => {
    const { email, fullName, username, phoneNumber, country, password } = req.body;

    try {
        // Check if user already exists
        let user = await User.findOne({ $or: [{ email }, { username }] });
        if (user) {
            return res.status(400).json({ message: 'User with that email or username already exists' });
        }

        // Generate a simple unique userId (for demonstration)
        // In a real app, use a more robust ID generation strategy (e.g., UUID)
        const lastUser = await User.findOne().sort({ createdAt: -1 });
        const newUserIdNum = lastUser ? parseInt(lastUser.userId.replace('CHIT', '')) + 1 : 1001;
        const userId = `CHIT${newUserIdNum}`;

        user = new User({
            userId,
            email,
            fullName,
            username,
            phoneNumber,
            country,
            password,
        });

        await user.save();

        res.status(201).json({
            message: 'User registered successfully',
            userId: user.userId,
            username: user.username,
            token: generateToken(user._id),
        });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

// @route   POST /api/login
// @desc    Authenticate user & get token
// @access  Public
app.post('/api/login', async (req, res) => {
    const { usernameOrEmail, password } = req.body;

    try {
        // Find user by username or email
        const user = await User.findOne({
            $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        res.json({
            message: 'Logged in successfully',
            userId: user.userId,
            username: user.username,
            token: generateToken(user._id),
        });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

// @route   GET /api/users/search/:id
// @desc    Search users by userId
// @access  Private
app.get('/api/users/search/:id', protect, async (req, res) => {
    try {
        const searchId = req.params.id.toUpperCase(); // Ensure case-insensitivity if needed
        const user = await User.findOne({ userId: searchId }).select('-password -email -phoneNumber -country -createdAt -__v');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Don't allow searching for self
        if (user._id.toString() === req.user) {
            return res.status(400).json({ message: 'Cannot search for yourself' });
        }

        res.json(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

// @route   POST /api/users/add-friend
// @desc    Add a user as a friend
// @access  Private
app.post('/api/users/add-friend', protect, async (req, res) => {
    const { friendId } = req.body; // This is the MongoDB _id of the friend to add

    try {
        const currentUser = await User.findById(req.user);
        const friendToAdd = await User.findById(friendId);

        if (!currentUser || !friendToAdd) {
            return res.status(404).json({ message: 'User or friend not found' });
        }

        if (currentUser._id.toString() === friendToAdd._id.toString()) {
            return res.status(400).json({ message: 'Cannot add yourself as a friend' });
        }

        // Check if already friends
        if (currentUser.friends.includes(friendToAdd._id)) {
            return res.status(400).json({ message: 'Already friends with this user' });
        }

        currentUser.friends.push(friendToAdd._id);
        friendToAdd.friends.push(currentUser._id); // Mutual friendship
        await currentUser.save();
        await friendToAdd.save();

        res.status(200).json({ message: `${friendToAdd.username} added as friend!`, friend: { _id: friendToAdd._id, username: friendToAdd.username, userId: friendToAdd.userId } });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

// @route   GET /api/users/friends
// @desc    Get current user's friends list
// @access  Private
app.get('/api/users/friends', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user).populate('friends', 'username userId fullName');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user.friends);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

// @route   GET /api/messages/:receiverId
// @desc    Get chat history between current user and a specific receiver
// @access  Private
app.get('/api/messages/:receiverId', protect, async (req, res) => {
    try {
        const senderId = req.user;
        const receiverId = req.params.receiverId;

        const messages = await Message.find({
            $or: [
                { sender: senderId, receiver: receiverId },
                { sender: receiverId, receiver: senderId },
            ],
        })
            .sort('timestamp')
            .populate('sender', 'username userId')
            .populate('receiver', 'username userId');

        res.json(messages);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

// --- Socket.IO for Real-time Chat ---

// Store active users and their socket IDs
const activeUsers = new Map(); // Map: userId (MongoDB _id) -> socket.id

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    // Authenticate user on socket connection
    socket.on('authenticate', async (token) => {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.id);
            if (user) {
                socket.userId = user._id.toString(); // Attach user ID to socket
                activeUsers.set(socket.userId, socket.id); // Store active user
                socket.join(socket.userId); // Join a room named after their user ID
                console.log(`User ${user.username} (${user.userId}) authenticated and joined room ${socket.userId}`);
                io.emit('user_status_update', { userId: socket.userId, status: 'online' }); // Notify others
            } else {
                socket.disconnect(true); // Disconnect if user not found
            }
        } catch (error) {
            console.error('Socket authentication failed:', error.message);
            socket.disconnect(true); // Disconnect on invalid token
        }
    });

    // Handle private messages
    socket.on('private_message', async ({ receiverId, content, type = 'text' }) => {
        if (!socket.userId) {
            return socket.emit('error', 'Not authenticated');
        }

        try {
            const senderUser = await User.findById(socket.userId);
            const receiverUser = await User.findById(receiverId);

            if (!senderUser || !receiverUser) {
                return socket.emit('error', 'Sender or receiver not found');
            }

            // Save message to DB
            const newMessage = new Message({
                sender: senderUser._id,
                receiver: receiverUser._id,
                content,
                type,
            });
            await newMessage.save();

            // Populate sender/receiver info for sending back to clients
            const populatedMessage = await newMessage
                .populate('sender', 'username userId')
                .populate('receiver', 'username userId');

            // Emit to sender
            socket.emit('new_message', populatedMessage);

            // Emit to receiver if online
            const receiverSocketId = activeUsers.get(receiverId);
            if (receiverSocketId) {
                io.to(receiverSocketId).emit('new_message', populatedMessage);
            } else {
                console.log(`User ${receiverUser.username} is offline. Message stored.`);
                // In a real app, you might implement push notifications here
            }
        } catch (error) {
            console.error('Error sending private message:', error.message);
            socket.emit('error', 'Failed to send message');
        }
    });

    // Handle typing indicator
    socket.on('typing', ({ receiverId }) => {
        if (!socket.userId) return;
        const receiverSocketId = activeUsers.get(receiverId);
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('typing', { senderId: socket.userId });
        }
    });

    socket.on('stop_typing', ({ receiverId }) => {
        if (!socket.userId) return;
        const receiverSocketId = activeUsers.get(receiverId);
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('stop_typing', { senderId: socket.userId });
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        if (socket.userId) {
            activeUsers.delete(socket.userId);
            io.emit('user_status_update', { userId: socket.userId, status: 'offline' }); // Notify others
        }
    });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));