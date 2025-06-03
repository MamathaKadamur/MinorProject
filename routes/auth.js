// routes/auth.js
const express = require('express');
const upload = require('../middleware/upload');
const { registerUser, loginUser } = require('../controllers/authController');
const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);

// Image Upload Route
router.post('/upload-image', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

  const imageUrl = `http://localhost:${process.env.PORT}/uploads/${req.file.filename}`;
  res.status(200).json({ imageUrl });
});

module.exports = router;
