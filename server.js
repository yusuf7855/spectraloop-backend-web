// server.js - Complete SpectraLoop Backend with Image Upload
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 5000;

// Configuration
const JWT_SECRET = 'spectraloop_admin_secret_key_2025';
const ADMIN_CREDENTIALS = {
    username: 'admin',
    password: 'admin'
};

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'blog-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    // Accept only image files
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (uploaded images)
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect('mongodb+srv://221118047:221118047@cluster0.wb6g5u1.mongodb.net/spectraloop?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('MongoDB connected successfully');
});

// Application Schema
const applicationSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true
    },
    lastName: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    phone: {
        type: String,
        required: true,
        trim: true
    },
    department: {
        type: String,
        required: true
    },
    grade: {
        type: String,
        required: true
    },
    workArea: {
        type: String,
        required: true
    },
    whyJoin: {
        type: String,
        required: true
    },
    previousExperience: {
        type: String,
        required: true
    },
    timeCommitment: {
        type: String,
        required: true
    },
    attendMeetings: {
        type: String,
        required: true
    },
    careerGoals: {
        type: String,
        required: true
    },
    additionalInfo: {
        type: String,
        default: ''
    },
    softwareKnowledge: [{
        type: String
    }],
    status: {
        type: String,
        enum: ['pending', 'reviewed', 'accepted', 'rejected'],
        default: 'pending'
    },
    appliedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const Application = mongoose.model('Application', applicationSchema);

// Blog Schema - Updated with image field
const blogSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    excerpt: {
        type: String,
        required: true,
        trim: true
    },
    content: {
        type: String,
        required: true
    },
    category: {
        type: String,
        required: true,
        enum: ['Teknoloji', 'Yarışma', 'Takım', 'Gelecek']
    },
    slug: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    image: {
        type: String,
        default: null
    },
    imageUrl: {
        type: String,
        default: null
    },
    readTime: {
        type: String,
        default: '5 dk'
    },
    published: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const Blog = mongoose.model('Blog', blogSchema);

// Auth middleware
const authenticateAdmin = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No token provided.'
        });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        res.status(400).json({
            success: false,
            message: 'Invalid token.'
        });
    }
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'SpectraLoop API is running',
        timestamp: new Date().toISOString()
    });
});

// Admin Authentication Routes

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log('Login attempt:', { username, password });
        
        if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        const token = jwt.sign(
            { username: username, role: 'admin' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log('Login successful for:', username);
        
        res.json({
            success: true,
            message: 'Login successful',
            token: token,
            admin: { username }
        });
        
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

// Verify Admin Token
app.get('/api/admin/verify', authenticateAdmin, (req, res) => {
    res.json({
        success: true,
        admin: req.admin
    });
});

// Admin Dashboard Stats
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const totalApplications = await Application.countDocuments();
        const pendingApplications = await Application.countDocuments({ status: 'pending' });
        const acceptedApplications = await Application.countDocuments({ status: 'accepted' });
        const totalBlogs = await Blog.countDocuments();
        
        // Recent applications
        const recentApplications = await Application.find()
            .sort({ appliedAt: -1 })
            .limit(5)
            .select('firstName lastName email department workArea status appliedAt');
        
        res.json({
            success: true,
            data: {
                stats: {
                    totalApplications,
                    pendingApplications,
                    acceptedApplications,
                    totalBlogs
                },
                recentApplications
            }
        });
    } catch (error) {
        console.error('Get admin stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch stats'
        });
    }
});

// Image Upload Route
app.post('/api/upload', authenticateAdmin, upload.single('image'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No file uploaded'
            });
        }

        const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
        
        res.json({
            success: true,
            message: 'Image uploaded successfully',
            data: {
                filename: req.file.filename,
                originalname: req.file.originalname,
                mimetype: req.file.mimetype,
                size: req.file.size,
                url: imageUrl
            }
        });
    } catch (error) {
        console.error('Image upload error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to upload image'
        });
    }
});

// Application Routes

// Submit application
app.post('/api/applications', async (req, res) => {
    try {
        console.log('Received application:', req.body);
        
        const applicationData = req.body;
        
        // Check if email already exists
        const existingApplication = await Application.findOne({ email: applicationData.email });
        if (existingApplication) {
            return res.status(400).json({
                success: false,
                message: 'Bu email adresi ile daha önce başvuru yapılmış.'
            });
        }
        
        // Create new application
        const newApplication = new Application(applicationData);
        await newApplication.save();
        
        console.log('Application saved with ID:', newApplication._id);
        
        res.status(201).json({
            success: true,
            message: 'Başvurunuz başarıyla alınmıştır.',
            applicationId: newApplication._id
        });
        
    } catch (error) {
        console.error('Application submission error:', error);
        res.status(500).json({
            success: false,
            message: 'Başvuru gönderilirken bir hata oluştu. Lütfen tekrar deneyin.',
            error: error.message
        });
    }
});

// Get all applications (admin endpoint)
app.get('/api/applications', async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;
        const filter = status ? { status } : {};
        
        const applications = await Application.find(filter)
            .sort({ appliedAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
            
        const total = await Application.countDocuments(filter);
        
        res.json({
            success: true,
            data: applications,
            pagination: {
                current: parseInt(page),
                pages: Math.ceil(total / limit),
                total
            }
        });
    } catch (error) {
        console.error('Get applications error:', error);
        res.status(500).json({
            success: false,
            message: 'Başvurular getirilirken hata oluştu.',
            error: error.message
        });
    }
});

// Get single application
app.get('/api/applications/:id', async (req, res) => {
    try {
        const application = await Application.findById(req.params.id);
        if (!application) {
            return res.status(404).json({
                success: false,
                message: 'Başvuru bulunamadı.'
            });
        }
        
        res.json({
            success: true,
            data: application
        });
    } catch (error) {
        console.error('Get application error:', error);
        res.status(500).json({
            success: false,
            message: 'Başvuru getirilirken hata oluştu.',
            error: error.message
        });
    }
});

// Update application status
app.patch('/api/applications/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const application = await Application.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );
        
        if (!application) {
            return res.status(404).json({
                success: false,
                message: 'Başvuru bulunamadı.'
            });
        }
        
        console.log(`Application ${req.params.id} status updated to: ${status}`);
        
        res.json({
            success: true,
            data: application,
            message: `Başvuru durumu ${status} olarak güncellendi.`
        });
    } catch (error) {
        console.error('Update status error:', error);
        res.status(500).json({
            success: false,
            message: 'Durum güncellenirken hata oluştu.',
            error: error.message
        });
    }
});

// Blog Routes

// Get all blogs
app.get('/api/blogs', async (req, res) => {
    try {
        const blogs = await Blog.find({ published: true }).sort({ createdAt: -1 });
        res.json({
            success: true,
            data: blogs
        });
    } catch (error) {
        console.error('Get blogs error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch blogs'
        });
    }
});

// Get single blog by slug
app.get('/api/blogs/:slug', async (req, res) => {
    try {
        const blog = await Blog.findOne({ slug: req.params.slug, published: true });
        if (!blog) {
            return res.status(404).json({
                success: false,
                message: 'Blog not found'
            });
        }
        
        res.json({
            success: true,
            data: blog
        });
    } catch (error) {
        console.error('Get blog error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch blog'
        });
    }
});

// Create blog (Admin only) - Updated for image support
app.post('/api/blogs', authenticateAdmin, async (req, res) => {
    try {
        const blogData = req.body;
        
        console.log('Creating blog:', blogData);
        
        // Generate slug from title if not provided
        if (!blogData.slug) {
            blogData.slug = blogData.title
                .toLowerCase()
                .replace(/ğ/g, 'g')
                .replace(/ü/g, 'u')
                .replace(/ş/g, 's')
                .replace(/ı/g, 'i')
                .replace(/ö/g, 'o')
                .replace(/ç/g, 'c')
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/(^-|-$)/g, '');
        }
        
        const newBlog = new Blog(blogData);
        await newBlog.save();
        
        console.log('Blog created with ID:', newBlog._id);
        
        res.status(201).json({
            success: true,
            message: 'Blog created successfully',
            data: newBlog
        });
    } catch (error) {
        console.error('Create blog error:', error);
        if (error.code === 11000) {
            res.status(400).json({
                success: false,
                message: 'Blog with this slug already exists'
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'Failed to create blog',
                error: error.message
            });
        }
    }
});

// Update blog (Admin only) - Updated for image support
app.put('/api/blogs/:id', authenticateAdmin, async (req, res) => {
    try {
        const blogData = req.body;
        
        // Update slug if title changed
        if (blogData.title && !blogData.slug) {
            blogData.slug = blogData.title
                .toLowerCase()
                .replace(/ğ/g, 'g')
                .replace(/ü/g, 'u')
                .replace(/ş/g, 's')
                .replace(/ı/g, 'i')
                .replace(/ö/g, 'o')
                .replace(/ç/g, 'c')
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/(^-|-$)/g, '');
        }
        
        const blog = await Blog.findByIdAndUpdate(
            req.params.id,
            blogData,
            { new: true }
        );
        
        if (!blog) {
            return res.status(404).json({
                success: false,
                message: 'Blog not found'
            });
        }
        
        console.log('Blog updated:', blog._id);
        
        res.json({
            success: true,
            message: 'Blog updated successfully',
            data: blog
        });
    } catch (error) {
        console.error('Update blog error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update blog',
            error: error.message
        });
    }
});

// Delete blog (Admin only)
app.delete('/api/blogs/:id', authenticateAdmin, async (req, res) => {
    try {
        const blog = await Blog.findByIdAndDelete(req.params.id);
        
        if (!blog) {
            return res.status(404).json({
                success: false,
                message: 'Blog not found'
            });
        }
        
        // Delete associated image file if exists
        if (blog.image) {
            const imagePath = path.join(__dirname, 'uploads', blog.image);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
                console.log('Deleted image file:', blog.image);
            }
        }
        
        console.log('Blog deleted:', blog._id);
        
        res.json({
            success: true,
            message: 'Blog deleted successfully'
        });
    } catch (error) {
        console.error('Delete blog error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete blog',
            error: error.message
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({
        success: false,
        message: 'Sunucu hatası oluştu.',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint bulunamadı.',
        path: req.path
    });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    mongoose.connection.close(() => {
        console.log('MongoDB connection closed');
        process.exit(0);
    });
});

app.listen(PORT, () => {
    console.log(`SpectraLoop API server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Admin credentials: username='admin', password='admin'`);
});

module.exports = app;