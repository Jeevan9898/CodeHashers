// Required packages
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const { create } = require('ipfs-http-client');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// 🔒 Rate limiter middleware (100 requests per 15 minutes per IP)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again after 15 minutes.'
    }
});
app.use(limiter); // Apply to all requests, or...

// Optional: Apply only to /register route like this:
// app.use('/register', limiter);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Mongoose Schema
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    ipfsCID: { type: String, required: true },
    encryptionKey: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Encryption helpers
function encryptData(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return {
        iv: iv.toString('hex'),
        data: encrypted
    };
}

// IPFS setup (local node)
const ipfs = create({ url: 'http://localhost:5001' }); // Ensure your IPFS daemon is running

// Register route
app.post('/register', [
    body('fullName').notEmpty().withMessage('Full Name is required.'),
    body('age').isInt({ min: 1 }).withMessage('Age must be a valid positive number.'),
    body('gender').notEmpty().withMessage('Gender is required.'),
    body('email').isEmail().withMessage('Invalid email format.'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long.')
        .matches(/(?=.*[0-9])(?=.*[!@#$%^&*])/) 
        .withMessage('Password must contain at least one number and one special character.'),
    body('phoneNumber')
        .matches(/^[0-9]{10}$/)
        .withMessage('Phone number must be exactly 10 digits.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { fullName, age, gender, email, password, phoneNumber } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const userData = JSON.stringify({ fullName, age, gender, phoneNumber, passwordHash });

        const encryptionKey = crypto.randomBytes(32).toString('hex');
        const encrypted = encryptData(userData, encryptionKey);

        const encryptedBuffer = Buffer.from(JSON.stringify(encrypted));
        const result = await ipfs.add(encryptedBuffer);

        // Pin to local IPFS node
        await ipfs.pin.add(result.cid);

        // Verify pin
        let isPinned = false;
        for await (const pin of ipfs.pin.ls()) {
            if (pin.cid.toString() === result.cid.toString()) {
                isPinned = true;
                break;
            }
        }

        if (!isPinned) {
            return res.status(500).json({
                success: false,
                message: 'Data uploaded but not pinned on local IPFS node.'
            });
        }

        // Store in MongoDB
        const newUser = new User({ email, ipfsCID: result.cid.toString(), encryptionKey });
        await newUser.save();

        res.status(201).json({
            success: true,
            message: 'User data securely stored, pinned to local IPFS node, and saved in MongoDB.',
            cid: result.cid.toString()
        });

    } catch (err) {
        console.error('❌ Registration failed:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});

// Decryption helper
function decryptData(encrypted, key) {
    const iv = Buffer.from(encrypted.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Sign-in route with validation, decryption error handling, and rate limit
app.post('/signin', signinLimiter, [
    body('email').isEmail().withMessage('Invalid email format.'),
    body('password').notEmpty().withMessage('Password is required.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        // Fetch encrypted data from IPFS
        let encryptedBuffer = Buffer.alloc(0);
        for await (const chunk of ipfs.cat(user.ipfsCID)) {
            encryptedBuffer = Buffer.concat([encryptedBuffer, chunk]);
        }

        const encrypted = JSON.parse(encryptedBuffer.toString());

        // Decrypt user data
        let decrypted;
        try {
            decrypted = decryptData(encrypted, user.encryptionKey);
        } catch (err) {
            console.error('❌ Decryption failed:', err);
            return res.status(500).json({ success: false, message: 'Data decryption failed.' });
        }

        const userData = JSON.parse(decrypted);

        // Compare passwords
        const isMatch = await bcrypt.compare(password, userData.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        res.json({
            success: true,
            message: 'Sign-in successful',
            user: {
                fullName: userData.fullName,
                age: userData.age,
                gender: userData.gender,
                phoneNumber: userData.phoneNumber
            }
        });

    } catch (err) {
        console.error('❌ Sign-in error:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

