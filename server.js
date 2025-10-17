const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB ulanish
mongoose.connect('mongodb+srv://apl:apl00@gamepaymentbot.ffcsj5v.mongodb.net/schb?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Modellar
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  profilePic: { type: String, default: '' },
  bio: { type: String, default: '' },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  balance: { type: Number, default: 0 }, // Virtual pul balans (monetizatsiya uchun)
  isPremium: { type: Boolean, default: false }, // Premium obuna holati
  premiumExpiresAt: { type: Date, default: null }, // Premium tugash sanasi
  coins: { type: Number, default: 0 }, // Ichki valyuta (sotib olish uchun)
  lastDailyReward: { type: Date, default: null }, // Kunlik mukofot
  createdAt: { type: Date, default: Date.now }
});

const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, default: '' },
  description: { type: String, default: '' },
  content: { type: String, required: true },
  media: { type: String, default: '' },
  backgroundColor: { type: String, default: '' }, // Premium uchun orqa fon rangi
  textColor: { type: String, default: '' }, // Premium uchun matn rangi
  poll: {
    question: { type: String, default: '' },
    options: [{ type: String }],
    votes: [{
      optionIndex: { type: Number, required: true },
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
    }]
  },
  scheduledAt: { type: Date, default: null }, // Rejalashtirilgan vaqt
  isSponsored: { type: Boolean, default: false }, // Sponsor post (monetizatsiya)
  sponsorPrice: { type: Number, default: 0 }, // Sponsor narxi
  boostLevel: { type: Number, default: 0 }, // Postni ko'tarish darajasi (pullik)
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  shares: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    replies: [{
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      content: { type: String, required: true },
      likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
  }],
  payouts: {
    likes: { type: Number, default: 0 },
    comments: { type: Number, default: 0 },
    shares: { type: Number, default: 0 }
  },
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  isTip: { type: Boolean, default: false }, // Tip xabari (monetizatsiya)
  tipAmount: { type: Number, default: 0 }, // Tip miqdori
  createdAt: { type: Date, default: Date.now }
});

// Monetizatsiya uchun yangi model: Obuna
const SubscriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['premium', 'basic'], default: 'basic' }, // Obuna turi
  price: { type: Number, required: true }, // Narx
  duration: { type: String, enum: ['monthly', 'yearly'], required: true }, // Davomiylik
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'expired', 'cancelled'], default: 'active' }
});

// To'lov so'rovi modeli
const PaymentRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['balance', 'coins', 'premium'], required: true },
  amount: { type: Number, required: true },
  screenshot: { type: String, required: true }, // Fayl yo'li
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  notes: { type: String, default: '' }, // Admin izohi
  createdAt: { type: Date, default: Date.now }
});

// Yechish so'rovi modeli
const WithdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  tax: { type: Number, required: true }, // 5% QQS
  netAmount: { type: Number, required: true },
  cardNumber: { type: String, required: true }, // Karta raqami (real loyihada xavfsiz saqlash)
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  notes: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

// Story Schema
const StorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  media: { type: String, required: true },
  caption: { type: String, default: '' },
  expiresAt: { type: Date, required: true },
  viewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Message = mongoose.model('Message', MessageSchema);
const Subscription = mongoose.model('Subscription', SubscriptionSchema);
const PaymentRequest = mongoose.model('PaymentRequest', PaymentRequestSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);
const Story = mongoose.model('Story', StorySchema);

// Uploads papkasini yaratish
const uploadsDir = 'public/uploads';
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer sozlamalari (umumiy media uchun: rasm va video)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir)
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const uploadMedia = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Faqat rasm va video fayllari ruxsat etilgan!'), false);
    }
  }
});

// Profil rasmi uchun
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Faqat rasm fayllari ruxsat etilgan!'), false);
    }
  }
});

// Middleware
app.use(express.static('public'));
app.use('/uploads', express.static('public/uploads'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'social-network-secret-key-' + Math.random().toString(36).substring(2),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 1 kun
    store: MongoStore.create({
    mongoUrl: 'mongodb+srv://apl:apl00@gamepaymentbot.ffcsj5v.mongodb.net/schb?retryWrites=true&w=majority',
    ttl: 24 * 60 * 60 // 1 kun
  })
  }
}));

// Auth middleware
const requireLogin = (req, res, next) => {
  if (!req.session.userId) {
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      return res.status(401).json({ success: false, message: "Avtorizatsiya talab qilinadi" });
    } else {
      return res.redirect('/register-login.html');
    }
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.userId || !req.session.isAdmin) {
    return res.status(403).json({ success: false, message: "Admin huquqi kerak" });
  }
  next();
};

// Monetizatsiya middleware: Premium tekshirish
const requirePremium = (req, res, next) => {
  User.findById(req.session.userId, (err, user) => {
    if (err || !user || !user.isPremium || (user.premiumExpiresAt && user.premiumExpiresAt < new Date())) {
      return res.status(403).json({ success: false, message: "Premium obuna kerak" });
    }
    next();
  });
};

// Monetizatsiya hisoblash funksiyasi
async function calcPayouts(post) {
  const user = await User.findById(post.userId);

  // Likes
  const likeGroups = Math.floor(post.likes.length / 100);
  const earnedLikes = likeGroups - post.payouts.likes;
  if (earnedLikes > 0) {
    user.balance += earnedLikes * 1; // $1 per 100 likes
    post.payouts.likes = likeGroups;
  }

  // Comments (top-level)
  const commentGroups = Math.floor(post.comments.length / 100);
  const earnedComments = commentGroups - post.payouts.comments;
  if (earnedComments > 0) {
    user.balance += earnedComments * 1; // $1 per 100 comments
    post.payouts.comments = commentGroups;
  }

  // Shares
  const shareGroups = Math.floor(post.shares.length / 100);
  const earnedShares = shareGroups - post.payouts.shares;
  if (earnedShares > 0) {
    user.balance += earnedShares * 2; // $2 per 100 shares
    post.payouts.shares = shareGroups;
  }

  await user.save();
  await post.save();
}

// Routes

// Asosiy sahifa
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Profil sahifasi
app.get('/profile', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// Admin sahifasi
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Shorts olish
app.get('/api/shorts', requireLogin, async (req, res) => {
  try {
    const shorts = await Post.find({ media: { $ne: '' } })
      .populate('userId', 'username fullName profilePic')
      .populate({
        path: 'comments.userId',
        select: 'username fullName profilePic'
      })
      .populate({
        path: 'comments.replies.userId',
        select: 'username fullName profilePic'
      })
      .sort({ 
        boostLevel: -1,
        createdAt: -1 
      });
    
    res.json({ success: true, shorts });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Shorts yaratish (video yuklash)
app.post('/api/shorts', requireLogin, uploadMedia.single('video'), async (req, res) => {
  try {
    const { title, description, boostLevel } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ success: false, message: "Video fayl kerak" });
    }
    
    if (!title || !description) {
      return res.status(400).json({ success: false, message: "Nomi va izoh kerak" });
    }
    
    // Boost uchun balans tekshirish (balansdan yechish)
    let finalBoostLevel = 0;
    if (parseInt(boostLevel) > 0) {
      const user = await User.findById(req.session.userId);
      const cost = parseInt(boostLevel) * 5; // Har daraja 5$
      if (user.balance < cost) {
        return res.status(400).json({ success: false, message: "Yetarli balans yo'q" });
      }
      user.balance -= cost;
      await user.save();
      finalBoostLevel = parseInt(boostLevel);
    }
    
    const newPost = new Post({
      userId: req.session.userId,
      title,
      description,
      content: description,
      media: '/uploads/' + req.file.filename,
      boostLevel: finalBoostLevel
    });
    
    await newPost.save();
    await newPost.populate('userId', 'username fullName profilePic');
    
    res.json({ success: true, short: newPost });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Ro'yxatdan o'tish
app.post('/register', async (req, res) => {
  try {
    const { username, password, email, fullName } = req.body;
    
    // Validatsiya
    if (!username || !password || !email || !fullName) {
      return res.status(400).json({ success: false, message: "Barcha maydonlarni to'ldiring" });
    }
    
    // Parolni hash qilish
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Yangi foydalanuvchi yaratish
    const newUser = new User({
      username,
      password: hashedPassword,
      email,
      fullName
    });
    
    await newUser.save();
    
    // Sessionga saqlash
    req.session.userId = newUser._id;
    req.session.username = newUser.username;
    req.session.isAdmin = newUser.username === 'admin';
    
    res.json({ success: true, message: "Ro'yxatdan muvaffaqiyatli o'tdingiz", userId: newUser._id });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ success: false, message: "Foydalanuvchi nomi yoki email allaqachon mavjud" });
    }
    res.status(500).json({ success: false, message: error.message });
  }
});

// Kirish
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validatsiya
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Foydalanuvchi nomi va parolni kiriting" });
    }
    
    // Foydalanuvchini topish
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ success: false, message: "Foydalanuvchi topilmadi" });
    }
    
    // Parolni tekshirish
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: "Noto'g'ri parol" });
    }
    
    // Sessionga saqlash
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.isAdmin = user.username === 'admin';
    
    res.json({ success: true, message: "Muvaffaqiyatli kirdingiz", userId: user._id });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Chiqish
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, message: "Chiqishda xatolik" });
    }
    res.json({ success: true, message: "Muvaffaqiyatli chiqdingiz" });
  });
});

// Foydalanuvchini o'zini olish (monetizatsiya ma'lumotlari bilan)
app.get('/user/me', requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId)
      .select('-password')
      .populate('followers', 'username fullName profilePic')
      .populate('following', 'username fullName profilePic');
    
    if (!user) {
      return res.status(404).json({ success: false, message: "Foydalanuvchi topilmadi" });
    }
    
    const posts = await Post.find({ userId: user._id });
    const totalLikes = posts.reduce((sum, post) => sum + post.likes.length, 0);
    
    // Monetizatsiya statistikasi
    const earnings = posts.reduce((sum, post) => sum + (post.isSponsored ? post.sponsorPrice : 0), 0);
    
    res.json({
      success: true,
      user: {
        ...user.toObject(),
        postCount: posts.length,
        totalLikes,
        earnings // Monetizatsiya daromadi
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Foydalanuvchi ma'lumotlarini olish (boshqa foydalanuvchi hisobiga kirganda ham ko'rish)
app.get('/user/:id', requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password')
      .populate('followers', 'username fullName profilePic')
      .populate('following', 'username fullName profilePic');
    
    if (!user) {
      return res.status(404).json({ success: false, message: "Foydalanuvchi topilmadi" });
    }
    
    const posts = await Post.find({ userId: user._id });
    const totalLikes = posts.reduce((sum, post) => sum + post.likes.length, 0);
    
    res.json({
      success: true,
      user: {
        ...user.toObject(),
        postCount: posts.length,
        totalLikes
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Foydalanuvchini yangilash
app.put('/user', requireLogin, async (req, res) => {
  try {
    const { fullName, bio } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.session.userId,
      { fullName, bio },
      { new: true, runValidators: true }
    ).select('-password');
    
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Rasm yuklash
app.post('/upload', requireLogin, upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Fayl yuklanmadi' });
    }
    
    const user = await User.findByIdAndUpdate(
      req.session.userId,
      { profilePic: '/uploads/' + req.file.filename },
      { new: true }
    ).select('-password');
    
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Story yaratish (premium foydalanuvchilar uchun cheksiz)
app.post('/stories', requireLogin, uploadMedia.single('media'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Media fayl kerak' });
    }
    
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 soat
    
    const newStory = new Story({
      userId: req.session.userId,
      media: '/uploads/' + req.file.filename,
      caption: req.body.caption || '',
      expiresAt
    });
    
    await newStory.save();
    await newStory.populate('userId', 'username fullName profilePic');
    
    res.json({ success: true, story: newStory });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Follow qilingan userlarning storylarini olish
app.get('/stories', requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    const followingIds = user.following;
    
    const stories = await Story.find({
      userId: { $in: followingIds },
      expiresAt: { $gt: new Date() }
    })
    .populate('userId', 'username fullName profilePic')
    .sort({ createdAt: -1 });
    
    res.json({ success: true, stories });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Suhbatlarni olish (faqat o'z profilida)
app.get('/messages/conversations', requireLogin, async (req, res) => {
  try {
    const conversations = await Message.aggregate([
      { $match: { receiverId: mongoose.Types.ObjectId(req.session.userId) } },
      { $sort: { createdAt: -1 } },
      { $group: {
        _id: "$senderId",
        lastMessage: { $first: "$content" },
        lastTime: { $first: "$createdAt" },
        messages: { $push: "$$ROOT" }
      }},
      { $addFields: {
        unreadCount: {
          $size: {
            $filter: {
              input: "$messages",
              cond: { $eq: [ "$$this.isRead", false ] }
            }
          }
        }
      }},
      { $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "sender",
        pipeline: [{ $project: { username: 1, fullName: 1, profilePic: 1 } }]
      }},
      { $unwind: "$sender" },
      { $project: {
        sender: 1,
        lastMessage: 1,
        lastTime: 1,
        unreadCount: 1
      }},
      { $sort: { lastTime: -1 } }
    ]);
    
    res.json({ success: true, conversations });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Post yaratish (premium funksiyalar bilan)
app.post('/posts', requireLogin, uploadMedia.single('media'), async (req, res) => {
  try {
    const { content, backgroundColor, textColor, pollQuestion, scheduledAt } = req.body;
    
    if (!content) {
      return res.status(400).json({ success: false, message: "Post matni bo'sh bo'lmasligi kerak" });
    }
    
    const user = await User.findById(req.session.userId);
    const isPremium = user.isPremium && (!user.premiumExpiresAt || new Date(user.premiumExpiresAt) > new Date());

    // Premium funksiyalarni tekshirish
    if (backgroundColor && !isPremium) {
      return res.status(403).json({ success: false, message: "Orqa fon rangi faqat premium uchun" });
    }
    if (textColor && !isPremium) {
      return res.status(403).json({ success: false, message: "Matn rangi faqat premium uchun" });
    }
    if (pollQuestion && !isPremium) {
      return res.status(403).json({ success: false, message: "Poll faqat premium uchun" });
    }
    if (scheduledAt && !isPremium) {
      return res.status(403).json({ success: false, message: "Rejalashtirish faqat premium uchun" });
    }

    // Poll variantlarini yig'ish
    let poll = null;
    if (pollQuestion && isPremium) {
      const options = [];
      for (let i = 0; ; i++) {
        const opt = req.body[`pollOption${i}`];
        if (!opt) break;
        options.push(opt);
      }
      if (options.length >= 2) {
        poll = { question: pollQuestion, options, votes: [] };
      }
    }

    const newPost = new Post({
      userId: req.session.userId,
      content,
      media: req.file ? '/uploads/' + req.file.filename : '',
      backgroundColor: isPremium ? backgroundColor || '' : '',
      textColor: isPremium ? textColor || '' : '',
      poll: poll || undefined,
      scheduledAt: isPremium && scheduledAt ? new Date(scheduledAt) : null,
      isSponsored: false,
      sponsorPrice: 0,
      boostLevel: 0
    });
    
    await newPost.save();
    await newPost.populate('userId', 'username fullName profilePic');
    
    res.json({ success: true, post: newPost });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Postlarni olish (boostlanganlarni yuqorida ko'rsatish, rejalashtirilganlarni ham)
// /posts GET endpointini o'zgartiring (server.js da)
app.get('/posts', requireLogin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;
    
    // Rejalashtirilgan postlarni ham qo'shish (faqat o'tgan vaqtdagilar)
    const now = new Date();
    const posts = await Post.find({ 
      $or: [
        { scheduledAt: null },
        { scheduledAt: { $lte: now } }
      ]
    })
      .populate('userId', 'username fullName profilePic isPremium premiumExpiresAt')
      .populate({
        path: 'comments.userId',
        select: 'username fullName profilePic'
      })
      .populate({
        path: 'comments.replies.userId',
        select: 'username fullName profilePic'
      })
      .sort({ 
        boostLevel: -1, // Boost yuqori
        createdAt: -1 
      })
      .skip(skip)
      .limit(limit);
    
    res.json({ success: true, posts });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// User ID bo'yicha postlarni olish
app.get('/posts/user/:userId', requireLogin, async (req, res) => {
  try {
    const posts = await Post.find({ userId: req.params.userId })
      .populate('userId', 'username fullName profilePic')
      .sort({ createdAt: -1 });
    
    res.json({ success: true, posts });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Poll ovoz berish
app.post('/posts/:id/poll/vote', requireLogin, async (req, res) => {
  try {
    const { optionIndex } = req.body;
    const post = await Post.findById(req.params.id);
    
    if (!post.poll || !post.poll.question) {
      return res.status(400).json({ success: false, message: "Poll topilmadi" });
    }
    
    const existingVote = post.poll.votes.find(v => v.userId.toString() === req.session.userId);
    if (existingVote) {
      return res.status(400).json({ success: false, message: "Alla qachon ovoz berdingiz" });
    }
    
    post.poll.votes.push({ optionIndex: parseInt(optionIndex), userId: req.session.userId });
    await post.save();
    
    res.json({ success: true, votes: post.poll.votes });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Post like qilish
app.post('/posts/:id/like', requireLogin, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ success: false, message: "Post topilmadi" });
    }
    
    const likeIndex = post.likes.indexOf(req.session.userId);
    if (likeIndex > -1) {
      post.likes.splice(likeIndex, 1);
    } else {
      post.likes.push(req.session.userId);
    }
    
    await post.save();
    await calcPayouts(post);
    res.json({ success: true, likes: post.likes.length });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Post share qilish
app.post('/posts/:id/share', requireLogin, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ success: false, message: "Post topilmadi" });
    }
    
    const shareIndex = post.shares.indexOf(req.session.userId);
    if (shareIndex === -1) {
      post.shares.push(req.session.userId);
    }
    
    await post.save();
    await calcPayouts(post);
    res.json({ success: true, shares: post.shares.length });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Komment qo'shish
app.post('/posts/:id/comment', requireLogin, async (req, res) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ success: false, message: "Komment matni bo'sh bo'lmasligi kerak" });
    }
    
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ success: false, message: "Post topilmadi" });
    }
    
    post.comments.push({
      userId: req.session.userId,
      content
    });
    
    await post.save();
    await post.populate({
      path: 'comments.userId',
      select: 'username fullName profilePic'
    });
    await calcPayouts(post);
    
    const newComment = post.comments[post.comments.length - 1];
    res.json({ success: true, comment: newComment });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Komment like qilish
app.post('/posts/:postId/comments/:commentId/like', requireLogin, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    
    if (!post) {
      return res.status(404).json({ success: false, message: "Post topilmadi" });
    }
    
    const comment = post.comments.id(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ success: false, message: "Komment topilmadi" });
    }
    
    const likeIndex = comment.likes.indexOf(req.session.userId);
    if (likeIndex > -1) {
      comment.likes.splice(likeIndex, 1);
    } else {
      comment.likes.push(req.session.userId);
    }
    
    await post.save();
    res.json({ success: true, likes: comment.likes.length });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Kommentga javob berish
app.post('/posts/:postId/comments/:commentId/reply', requireLogin, async (req, res) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ success: false, message: "Javob matni bo'sh bo'lmasligi kerak" });
    }
    
    const post = await Post.findById(req.params.postId);
    
    if (!post) {
      return res.status(404).json({ success: false, message: "Post topilmadi" });
    }
    
    const comment = post.comments.id(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ success: false, message: "Komment topilmadi" });
    }
    
    comment.replies.push({
      userId: req.session.userId,
      content
    });
    
    await post.save();
    await post.populate({
      path: 'comments.replies.userId',
      select: 'username fullName profilePic'
    });
    
    const newReply = comment.replies[comment.replies.length - 1];
    res.json({ success: true, reply: newReply });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Obuna bo'lish
app.post('/user/:id/follow', requireLogin, async (req, res) => {
  try {
    const userToFollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.session.userId);
    
    if (!userToFollow || !currentUser) {
      return res.status(404).json({ success: false, message: "Foydalanuvchi topilmadi" });
    }
    
    // Obuna bo'lish/obunani bekor qilish
    const isFollowing = currentUser.following.includes(userToFollow._id);
    
    if (isFollowing) {
      // Obunani bekor qilish
      currentUser.following.pull(userToFollow._id);
      userToFollow.followers.pull(currentUser._id);
    } else {
      // Obuna bo'lish
      currentUser.following.push(userToFollow._id);
      userToFollow.followers.push(currentUser._id);
    }
    
    await currentUser.save();
    await userToFollow.save();
    
    res.json({ 
      success: true, 
      isFollowing: !isFollowing,
      followers: userToFollow.followers.length 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Xabarlarni olish
app.get('/messages/:userId', requireLogin, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { senderId: req.session.userId, receiverId: req.params.userId },
        { senderId: req.params.userId, receiverId: req.session.userId }
      ]
    })
    .populate('senderId', 'username fullName profilePic')
    .populate('receiverId', 'username fullName profilePic')
    .sort({ createdAt: 1 });
    
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Xabar yuborish (tip qo'shish)
app.post('/messages', requireLogin, async (req, res) => {
  try {
    const { receiverId, content, tipAmount } = req.body;
    
    if (!content || !receiverId) {
      return res.status(400).json({ success: false, message: "Xabar matni va qabul qiluvchi kerak" });
    }
    
    // Tip uchun balans tekshirish
    if (tipAmount > 0) {
      const sender = await User.findById(req.session.userId);
      if (sender.balance < tipAmount) {
        return res.status(400).json({ success: false, message: "Yetarli balans yo'q" });
      }
      sender.balance -= tipAmount;
      const receiver = await User.findById(receiverId);
      receiver.balance += tipAmount;
      await sender.save();
      await receiver.save();
    }
    
    const newMessage = new Message({
      senderId: req.session.userId,
      receiverId,
      content,
      isTip: tipAmount > 0,
      tipAmount: tipAmount || 0
    });
    
    await newMessage.save();
    await newMessage.populate('senderId', 'username fullName profilePic');
    await newMessage.populate('receiverId', 'username fullName profilePic');
    
    res.json({ success: true, message: newMessage });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// O'qilmagan xabarlarni sanash
app.get('/messages/unread/count', requireLogin, async (req, res) => {
  try {
    const count = await Message.countDocuments({
      receiverId: req.session.userId,
      isRead: false
    });
    
    res.json({ success: true, count });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Xabarlarni o'qilgan deb belgilash
app.post('/messages/:userId/read', requireLogin, async (req, res) => {
  try {
    await Message.updateMany(
      {
        senderId: req.params.userId,
        receiverId: req.session.userId,
        isRead: false
      },
      { isRead: true }
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// To'lov so'rovi yuborish (screenshot bilan)
app.post('/payment/request', requireLogin, upload.single('screenshot'), async (req, res) => {
  try {
    const { type, amount } = req.body;
    
    if (!type || !amount || !req.file) {
      return res.status(400).json({ success: false, message: "Barcha ma'lumotlar va screenshot kerak" });
    }
    
    const newRequest = new PaymentRequest({
      userId: req.session.userId,
      type,
      amount: parseFloat(amount),
      screenshot: '/uploads/' + req.file.filename
    });
    
    await newRequest.save();
    
    res.json({ success: true, message: "To'lov so'rovi yuborildi, admin tasdiqlashini kutib turing" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Foydalanuvchining to'lov so'rovlari
app.get('/user/payments', requireLogin, async (req, res) => {
  try {
    const payments = await PaymentRequest.find({ userId: req.session.userId })
      .populate('userId', 'username fullName')
      .sort({ createdAt: -1 });
    
    res.json({ success: true, payments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin to'lov so'rovlari
app.get('/admin/payments', requireAdmin, async (req, res) => {
  try {
    const payments = await PaymentRequest.find()
      .populate('userId', 'username fullName email')
      .sort({ createdAt: -1 });
    
    res.json({ success: true, payments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin to'lovni tasdiqlash
app.put('/admin/payments/:id/approve', requireAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const payment = await PaymentRequest.findById(req.params.id).populate('userId');
    
    if (!payment || payment.status !== 'pending') {
      return res.status(400).json({ success: false, message: "Noto'g'ri so'rov" });
    }
    
    payment.status = 'approved';
    payment.notes = notes || '';
    await payment.save();
    
    const user = payment.userId;
    
    switch (payment.type) {
      case 'balance':
        user.balance += payment.amount;
        break;
      case 'coins':
        user.coins += payment.amount;
        break;
      case 'premium':
        user.isPremium = true;
        const duration = payment.amount >= 99.99 ? 'yearly' : 'monthly'; // Yillik 99.99$ deb faraz
        const endDate = duration === 'monthly' ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
        user.premiumExpiresAt = endDate;
        break;
      default:
        return res.status(400).json({ success: false, message: "Noto'g'ri to'lov turi" });
    }
    
    await user.save();
    
    res.json({ success: true, message: 'To\'lov tasdiqlandi' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin to'lovni rad etish
app.put('/admin/payments/:id/reject', requireAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const payment = await PaymentRequest.findById(req.params.id);
    
    if (!payment || payment.status !== 'pending') {
      return res.status(400).json({ success: false, message: "Noto'g'ri so'rov" });
    }
    
    payment.status = 'rejected';
    payment.notes = notes || '';
    await payment.save();
    
    res.json({ success: true, message: 'To\'lov rad etildi' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Reklama olish (oddiy reklama, premium uchun maxsus)
app.get('/ads', requireLogin, async (req, res) => {
  try {
    // Simulyatsiya: oddiy reklamalar
    const ads = [
      { id: 1, title: 'Reklama 1', image: '/ads/ad1.jpg', url: 'https://example.com' },
      { id: 2, title: 'Reklama 2', image: '/ads/ad2.jpg', url: 'https://example.com' }
    ];
    
    // Premium foydalanuvchilar uchun kam reklama
    const user = await User.findById(req.session.userId);
    const filteredAds = user.isPremium ? ads.slice(0, 1) : ads;
    
    res.json({ success: true, ads: filteredAds });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Sponsor post uchun taklif qabul qilish (admin tomonidan)
app.post('/posts/:id/sponsor', requireAdmin, async (req, res) => {
  try {
    const { price } = req.body;
    const post = await Post.findByIdAndUpdate(
      req.params.id,
      { isSponsored: true, sponsorPrice: price },
      { new: true }
    );
    
    // Muallifga pul o'tkazish
    const user = await User.findById(post.userId);
    user.balance += price * 0.7; // 70% muallifga
    await user.save();
    
    res.json({ success: true, post });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin statistikasi (monetizatsiya bilan)
app.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const postCount = await Post.countDocuments();
    const totalEarnings = await Post.aggregate([{ $group: { _id: null, total: { $sum: '$sponsorPrice' } } }]);
    const premiumUsers = await User.countDocuments({ isPremium: true });
    
    // Eng ko'p obunachiga ega bo'lgan 10 ta foydalanuvchi
    const topUsers = await User.aggregate([
      {
        $project: {
          username: 1,
          fullName: 1,
          profilePic: 1,
          followersCount: { $size: "$followers" }
        }
      },
      { $sort: { followersCount: -1 } },
      { $limit: 10 }
    ]);
    
    res.json({
      success: true,
      stats: {
        userCount,
        postCount,
        totalEarnings: totalEarnings[0]?.total || 0,
        premiumUsers,
        topUsers
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Barcha foydalanuvchilarni olish
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Barcha postlarni olish
app.get('/admin/posts', requireAdmin, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('userId', 'username fullName')
      .sort({ createdAt: -1 });
    
    res.json({ success: true, posts });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Postni o'chirish
app.delete('/admin/posts/:id', requireAdmin, async (req, res) => {
  try {
    await Post.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Post muvaffaqiyatli o'chirildi" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Foydalanuvchini o'chirish
app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    // Foydalanuvchining postlarini ham o'chirish
    await Post.deleteMany({ userId: req.params.id });
    res.json({ success: true, message: "Foydalanuvchi muvaffaqiyatli o'chirildi" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// O'yin: Kunlik mukofot (10 coin)
app.post('/game/daily-reward', requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const lastReward = user.lastDailyReward ? new Date(user.lastDailyReward) : new Date(0);
    lastReward.setHours(0, 0, 0, 0);

    if (lastReward >= today) {
      return res.status(400).json({ success: false, message: "Bugun allaqachon mukofot oldingiz" });
    }

    user.coins += 10;
    user.lastDailyReward = new Date();
    await user.save();

    res.json({ success: true, coins: user.coins, message: "10 coin oldingiz!" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// O'yin: Tangalar otish (coin flip, 50% yutish imkoniyati)
app.post('/game/coin-flip', requireLogin, async (req, res) => {
  try {
    const { bet } = req.body;
    const betAmount = parseInt(bet) || 1;
    const user = await User.findById(req.session.userId);

    if (user.coins < betAmount) {
      return res.status(400).json({ success: false, message: "Yetarli coin yo'q" });
    }

    const isWin = Math.random() > 0.5;
    if (isWin) {
      user.coins += betAmount;
      await user.save();
      res.json({ success: true, win: true, coins: user.coins, message: `Yutdingiz! +${betAmount} coin` });
    } else {
      user.coins -= betAmount;
      await user.save();
      res.json({ success: true, win: false, coins: user.coins, message: `Yutqazdingiz! -${betAmount} coin` });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Balans yechish so'rovi (karta ma'lumotlari bilan, 5% QQS ushlab)
app.post('/withdraw', requireLogin, async (req, res) => {
  try {
    const { amount, cardNumber } = req.body; // Real loyihada expiry, cvv ham qo'shing va payment gateway ishlatish

    if (!amount || !cardNumber) {
      return res.status(400).json({ success: false, message: "Miqdor va karta raqami kerak" });
    }

    const parsedAmount = parseFloat(amount);
    if (parsedAmount <= 0) {
      return res.status(400).json({ success: false, message: "Miqdor musbat bo'lishi kerak" });
    }

    const taxRate = 0.05;
    const tax = parsedAmount * taxRate;
    const netAmount = parsedAmount - tax;

    const newWithdrawal = new Withdrawal({
      userId: req.session.userId,
      amount: parsedAmount,
      tax,
      netAmount,
      cardNumber
    });

    await newWithdrawal.save();
    res.json({ success: true, message: "Yechish so'rovi yuborildi, admin tasdiqlashini kutib turing. Net miqdor: " + netAmount });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Foydalanuvchining yechish so'rovlari
app.get('/user/withdrawals', requireLogin, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ userId: req.session.userId })
      .populate('userId', 'username fullName')
      .sort({ createdAt: -1 });
    res.json({ success: true, withdrawals });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin yechish so'rovlari
app.get('/admin/withdrawals', requireAdmin, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find()
      .populate('userId', 'username fullName email')
      .sort({ createdAt: -1 });
    res.json({ success: true, withdrawals });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin yechishni tasdiqlash (balansni ushlab, real payment qilish)
app.put('/admin/withdrawals/:id/approve', requireAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const withdrawal = await Withdrawal.findById(req.params.id).populate('userId');

    if (!withdrawal || withdrawal.status !== 'pending') {
      return res.status(400).json({ success: false, message: "Noto'g'ri so'rov" });
    }

    const user = withdrawal.userId;
    if (user.balance < withdrawal.amount) {
      return res.status(400).json({ success: false, message: "Foydalanuvchida yetarli balans yo'q" });
    }

    // Balansni ushlash
    user.balance -= withdrawal.amount;
    await user.save();

    // Status yangilash
    withdrawal.status = 'approved';
    withdrawal.notes = notes || '';
    await withdrawal.save();

    // Real loyihada: cardNumber bilan payment gateway orqali pul yuborish (masalan, Stripe)

    res.json({ success: true, message: 'Yechish tasdiqlandi va balans ushlab qoldi' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin yechishni rad etish (balans qaytarish)
app.put('/admin/withdrawals/:id/reject', requireAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const withdrawal = await Withdrawal.findById(req.params.id).populate('userId');

    if (!withdrawal || withdrawal.status !== 'pending') {
      return res.status(400).json({ success: false, message: "Noto'g'ri so'rov" });
    }

    withdrawal.status = 'rejected';
    withdrawal.notes = notes || '';
    await withdrawal.save();

    // Balansni qaytarish (agar oldin ushlanmagan bo'lsa, bu yerda hech narsa qilmaslik mumkin, lekin misol uchun)
    res.json({ success: true, message: 'Yechish rad etildi' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Xato ishlovchisi
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ success: false, message: error.message });
});

// 404 xatosi
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Sahifa topilmadi" });
});

// Postni o'chirish
app.delete('/posts/:id', async (req, res) => {
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId);
    
    if (!post) {
      return res.status(404).json({ success: false, message: 'Post topilmadi' });
    }
    
    // Post egasini tekshirish (agar kerak bo'lsa)
    // if (post.userId.toString() !== req.user.id) {
    //   return res.status(403).json({ success: false, message: 'Ruxsat yo\'q' });
    // }
    
    // Post bilan bog'liq media fayllarni o'chirish
    if (post.media && post.media.length > 0) {
      fs.unlinkSync(path.join(__dirname, 'public', post.media));
    }
    
    // Postni ma'lumotlar bazasidan o'chirish
    await Post.findByIdAndDelete(postId);
    
    res.json({ success: true, message: 'Post muvaffaqiyatli o\'chirildi' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

// Postni tahrirlash
app.put('/posts/:id', async (req, res) => {
  try {
    const postId = req.params.id;
    const { content } = req.body;
    
    const post = await Post.findById(postId);
    
    if (!post) {
      return res.status(404).json({ success: false, message: 'Post topilmadi' });
    }
    
    // Post egasini tekshirish (agar kerak bo'lsa)
    // if (post.userId.toString() !== req.user.id) {
    //   return res.status(403).json({ success: false, message: 'Ruxsat yo\'q' });
    // }
    
    // Post kontentini yangilash
    post.content = content;
    await post.save();
    
    res.json({ success: true, message: 'Post muvaffaqiyatli yangilandi', post });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

// Serverni ishga tushurish
app.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishlamoqda`);
});