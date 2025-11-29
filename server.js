const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');

console.log('🚀 Starting Secure Messenger...');

const app = express();
const server = http.createServer(app);

// 🔥 ИСПРАВЛЕННЫЕ НАСТРОЙКИ CORS
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 🔥 ИСПРАВЛЕННОЕ ПОДКЛЮЧЕНИЕ К MONGODB
const MONGODB_URI = process.env.MONGO_URL || process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-messenger';

console.log('🔗 Connecting to MongoDB...');
console.log('MongoDB URI:', MONGODB_URI ? 'Present' : 'Missing');

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  console.log('⚠️  Continuing without MongoDB...');
});

// Схемы и модели
const userSchema = new mongoose.Schema({
  userid: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  theme: { type: String, default: 'light' },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now }
}, { timestamps: true });

const friendRequestSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Message = mongoose.model('Message', messageSchema);

// Генерация 8-значного ID
function generateUserID() {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
}

// Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Токен отсутствует' });
  
  jwt.verify(token, 'secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Неверный токен' });
    req.user = user;
    next();
  });
};

// API Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Логин и пароль обязательны' });
    }
    
    if (username.length < 3) {
      return res.status(400).json({ error: 'Логин должен содержать минимум 3 символа' });
    }
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Этот логин уже занят' });
    }
    
    const userid = generateUserID();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      userid,
      username,
      password: hashedPassword
    });
    
    await user.save();
    
    const token = jwt.sign({ userId: user._id, username: user.username }, 'secret-key', { expiresIn: '30d' });
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        userid: user.userid,
        username: user.username,
        theme: user.theme
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Введите логин и пароль' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }
    
    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, username: user.username }, 
      'secret-key', 
      { expiresIn: rememberMe ? '30d' : '1d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        userid: user.userid,
        username: user.username,
        theme: user.theme,
        isOnline: true
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    res.json({
      success: true,
      user: {
        id: user._id,
        userid: user.userid,
        username: user.username,
        theme: user.theme
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
  try {
    const { userid } = req.body;
    const fromUserId = req.user.userId;
    
    const toUser = await User.findOne({ userid });
    if (!toUser) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    if (toUser._id.toString() === fromUserId) {
      return res.status(400).json({ error: 'Нельзя отправить запрос самому себе' });
    }
    
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { from: fromUserId, to: toUser._id },
        { from: toUser._id, to: fromUserId }
      ]
    });
    
    if (existingRequest) {
      return res.status(400).json({ error: 'Запрос уже отправлен' });
    }
    
    const friendRequest = new FriendRequest({
      from: fromUserId,
      to: toUser._id
    });
    
    await friendRequest.save();
    
    res.json({ success: true, message: 'Запрос отправлен' });
  } catch (error) {
    console.error('Friend request error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/friends/requests', authenticateToken, async (req, res) => {
  try {
    const requests = await FriendRequest.find({ 
      to: req.user.userId, 
      status: 'pending' 
    }).populate('from', 'username userid');
    
    res.json({ success: true, requests });
  } catch (error) {
    console.error('Get requests error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/friends/respond', authenticateToken, async (req, res) => {
  try {
    const { requestId, accept } = req.body;
    
    const request = await FriendRequest.findById(requestId).populate('from').populate('to');
    if (!request) {
      return res.status(404).json({ error: 'Запрос не найден' });
    }
    
    if (accept) {
      request.status = 'accepted';
      await request.save();
      res.json({ success: true, message: 'Запрос принят' });
    } else {
      await FriendRequest.findByIdAndDelete(requestId);
      res.json({ success: true, message: 'Запрос отклонен' });
    }
  } catch (error) {
    console.error('Respond error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const friends = await FriendRequest.find({
      $or: [{ from: req.user.userId }, { to: req.user.userId }],
      status: 'accepted'
    }).populate('from', 'username userid isOnline lastSeen').populate('to', 'username userid isOnline lastSeen');
    
    const friendsList = friends.map(request => {
      const friend = request.from._id.toString() === req.user.userId ? request.to : request.from;
      return {
        id: friend._id,
        userid: friend.userid,
        username: friend.username,
        isOnline: friend.isOnline,
        lastSeen: friend.lastSeen
      };
    });
    
    res.json({ success: true, friends: friendsList });
  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/messages/:friendId', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { from: req.user.userId, to: req.params.friendId },
        { from: req.params.friendId, to: req.user.userId }
      ]
    })
    .populate('from', 'username')
    .populate('to', 'username')
    .sort({ timestamp: 1 })
    .limit(100);
    
    res.json({ success: true, messages });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/user/theme', authenticateToken, async (req, res) => {
  try {
    const { theme } = req.body;
    await User.findByIdAndUpdate(req.user.userId, { theme });
    res.json({ success: true, message: 'Тема изменена' });
  } catch (error) {
    console.error('Theme error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// 🔥 ВАЖНО: Обработчик для всех остальных маршрутов
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.io
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Токен отсутствует'));
    
    const decoded = jwt.verify(token, 'secret-key');
    const user = await User.findById(decoded.userId);
    if (!user) return next(new Error('Пользователь не найден'));
    
    socket.userId = user._id.toString();
    socket.username = user.username;
    next();
  } catch (error) {
    next(new Error('Ошибка авторизации'));
  }
});

io.on('connection', async (socket) => {
  console.log('✅ User connected:', socket.username);
  
  await User.findByIdAndUpdate(socket.userId, { 
    isOnline: true, 
    lastSeen: new Date() 
  });
  
  socket.on('send_message', async (data) => {
    try {
      const { to, message } = data;
      
      const newMessage = new Message({
        from: socket.userId,
        to: to,
        message: message.trim()
      });
      
      await newMessage.save();
      await newMessage.populate('from', 'username');
      
      const messageData = {
        id: newMessage._id,
        from: newMessage.from.username,
        to: to,
        message: newMessage.message,
        timestamp: newMessage.timestamp
      };
      
      socket.emit('new_message', messageData);
      socket.to(to).emit('new_message', messageData);
    } catch (error) {
      socket.emit('error', { message: 'Ошибка отправки сообщения' });
    }
  });
  
  socket.on('disconnect', async () => {
    console.log('❌ User disconnected:', socket.username);
    await User.findByIdAndUpdate(socket.userId, { 
      isOnline: false, 
      lastSeen: new Date() 
    });
  });
});

// 🔥 ИСПРАВЛЕННЫЙ ЗАПУСК СЕРВЕРА
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});