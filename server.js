const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const AWS = require('aws-sdk');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ezpzshare')
  .then(() => console.log('📊 MongoDB connected successfully'))
  .catch(err => console.log('❌ MongoDB connection failed:', err.message));

// AWS S3 Configuration
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1'
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  totalFolders: { type: Number, default: 0 },
  totalViews: { type: Number, default: 0 }
});

// Folder Schema
const folderSchema = new mongoose.Schema({
  name: { type: String, required: true },
  password: { type: String, required: true },
  shareId: { type: String, unique: true, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  files: [{
    fileName: String,
    originalName: String,
    fileSize: Number,
    fileType: String,
    s3Key: String,
    uploadedAt: { type: Date, default: Date.now }
  }],
  views: { type: Number, default: 0 },
  downloads: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  lastAccessed: { type: Date, default: Date.now }
});

// Analytics Schema
const analyticsSchema = new mongoose.Schema({
  folderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Folder', required: true },
  action: { type: String, enum: ['view', 'download', 'access_attempt'], required: true },
  ipAddress: String,
  userAgent: String,
  timestamp: { type: Date, default: Date.now },
  success: { type: Boolean, default: true },
  fileId: String
});

const User = mongoose.model('User', userSchema);
const Folder = mongoose.model('Folder', folderSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);

// Middleware for JWT authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Generate unique share ID
const generateShareId = () => {
  return crypto.randomBytes(16).toString('hex');
};

// ROUTES

// Debug endpoint to check environment variables
app.get('/api/debug-env', (req, res) => {
  res.json({ 
    FRONTEND_URL: process.env.FRONTEND_URL,
    FRONTEND_URL_TYPE: typeof process.env.FRONTEND_URL,
    FRONTEND_URL_LENGTH: process.env.FRONTEND_URL ? process.env.FRONTEND_URL.length : 0,
    NODE_ENV: process.env.NODE_ENV,
    PORT: process.env.PORT,
    has_JWT_SECRET: !!process.env.JWT_SECRET,
    has_MONGODB_URI: !!process.env.MONGODB_URI,
    has_AWS_KEYS: !!(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY)
  });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      email,
      password: hashedPassword,
      name
    });
    
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        totalFolders: user.totalFolders,
        totalViews: user.totalViews
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Folder Routes
app.post('/api/folders', authenticateToken, async (req, res) => {
  try {
    const { name, password } = req.body;
    
    if (!name || !password) {
      return res.status(400).json({ error: 'Name and password are required' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const folder = new Folder({
      name,
      password: hashedPassword,
      shareId: generateShareId(),
      owner: req.user.userId
    });
    
    await folder.save();
    
    await User.findByIdAndUpdate(req.user.userId, { $inc: { totalFolders: 1 } });
    
    res.status(201).json({
      id: folder._id,
      name: folder.name,
      shareId: folder.shareId,
      files: folder.files,
      views: folder.views,
      downloads: folder.downloads,
      createdAt: folder.createdAt,
      shareLink: `${process.env.FRONTEND_URL}/share/${folder.shareId}`
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/folders', authenticateToken, async (req, res) => {
  try {
    const folders = await Folder.find({ owner: req.user.userId })
      .select('-password')
      .sort({ createdAt: -1 });
    
    const foldersWithLinks = folders.map(folder => ({
      id: folder._id,
      name: folder.name,
      shareId: folder.shareId,
      files: folder.files,
      views: folder.views,
      downloads: folder.downloads,
      createdAt: folder.createdAt,
      shareLink: `${process.env.FRONTEND_URL}/share/${folder.shareId}`
    }));
    
    res.json(foldersWithLinks);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// File Upload Route
app.post('/api/folders/:folderId/upload', authenticateToken, upload.array('files'), async (req, res) => {
  try {
    const { folderId } = req.params;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'No files provided' });
    }
    
    const folder = await Folder.findOne({ _id: folderId, owner: req.user.userId });
    if (!folder) {
      return res.status(404).json({ error: 'Folder not found' });
    }
    
    const uploadedFiles = [];
    
    for (const file of files) {
      const fileExtension = path.extname(file.originalname);
      const fileName = `${crypto.randomUUID()}${fileExtension}`;
      const s3Key = `folders/${folder.shareId}/${fileName}`;
      
      const uploadParams = {
        Bucket: process.env.AWS_S3_BUCKET,
        Key: s3Key,
        Body: file.buffer,
        ContentType: file.mimetype,
        ACL: 'private'
      };
      
      await s3.upload(uploadParams).promise();
      
      const fileData = {
        fileName: fileName,
        originalName: file.originalname,
        fileSize: file.size,
        fileType: file.mimetype,
        s3Key: s3Key,
        uploadedAt: new Date()
      };
      
      folder.files.push(fileData);
      uploadedFiles.push(fileData);
    }
    
    await folder.save();
    
    res.json({
      message: `${files.length} file(s) uploaded successfully`,
      files: uploadedFiles
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// File preview route
app.get('/api/share/:shareId/preview/:fileId', async (req, res) => {
  try {
    const { shareId, fileId } = req.params;
    
    const folder = await Folder.findOne({ shareId });
    if (!folder) {
      return res.status(404).json({ error: 'Folder not found' });
    }
    
    const file = folder.files.id(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    const signedUrl = s3.getSignedUrl('getObject', {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: file.s3Key,
      Expires: 300,
      ResponseContentDisposition: `inline; filename="${file.originalName}"`
    });
    
    res.redirect(signedUrl);
    
  } catch (error) {
    console.error('Preview error:', error);
    res.status(500).json({ error: 'Preview failed' });
  }
});

// Public folder access
app.post('/api/share/:shareId/access', async (req, res) => {
  try {
    const { shareId } = req.params;
    const { password } = req.body;
    
    const folder = await Folder.findOne({ shareId });
    if (!folder) {
      return res.status(404).json({ error: 'Folder not found' });
    }
    
    const isMatch = await bcrypt.compare(password, folder.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    
    folder.views += 1;
    folder.lastAccessed = new Date();
    await folder.save();
    
    await User.findByIdAndUpdate(folder.owner, { $inc: { totalViews: 1 } });
    
    await Analytics.create({
      folderId: folder._id,
      action: 'view',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });
    
    res.json({
      id: folder._id,
      name: folder.name,
      files: folder.files.map(file => ({
        id: file._id,
        originalName: file.originalName,
        fileSize: file.fileSize,
        fileType: file.fileType,
        uploadedAt: file.uploadedAt
      })),
      views: folder.views
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// File download route
app.get('/api/share/:shareId/download/:fileId', async (req, res) => {
  try {
    const { shareId, fileId } = req.params;
    
    const folder = await Folder.findOne({ shareId });
    if (!folder) {
      return res.status(404).json({ error: 'Folder not found' });
    }
    
    const file = folder.files.id(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    const signedUrl = s3.getSignedUrl('getObject', {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: file.s3Key,
      Expires: 300,
      ResponseContentDisposition: `attachment; filename="${file.originalName}"`
    });
    
    folder.downloads += 1;
    await folder.save();
    
    await Analytics.create({
      folderId: folder._id,
      action: 'download',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      fileId: fileId
    });
    
    res.json({ downloadUrl: signedUrl });
  } catch (error) {
    res.status(500).json({ error: 'Download failed' });
  }
});

// Delete folder route
app.delete('/api/folders/:folderId', authenticateToken, async (req, res) => {
  try {
    const { folderId } = req.params;
    
    const folder = await Folder.findOne({ _id: folderId, owner: req.user.userId });
    if (!folder) {
      return res.status(404).json({ error: 'Folder not found' });
    }
    
    if (folder.files && folder.files.length > 0) {
      const deleteParams = {
        Bucket: process.env.AWS_S3_BUCKET,
        Delete: {
          Objects: folder.files.map(file => ({ Key: file.s3Key }))
        }
      };
      
      try {
        await s3.deleteObjects(deleteParams).promise();
      } catch (s3Error) {
        console.error('S3 deletion error:', s3Error);
      }
    }
    
    await Analytics.deleteMany({ folderId: folder._id });
    await Folder.findByIdAndDelete(folderId);
    await User.findByIdAndUpdate(req.user.userId, { $inc: { totalFolders: -1 } });
    
    res.json({ 
      message: 'Folder deleted successfully',
      deletedFolder: {
        id: folder._id,
        name: folder.name,
        filesDeleted: folder.files.length
      }
    });
    
  } catch (error) {
    console.error('Delete folder error:', error);
    res.status(500).json({ error: 'Failed to delete folder' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 EzPzShare API running on port ${PORT}`);
  console.log(`📊 MongoDB connected`);
  console.log(`☁️ AWS S3 configured for file storage`);
});

