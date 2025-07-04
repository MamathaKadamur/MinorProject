// routes/upload.js
const express = require('express');
const router = express.Router();
const upload = require('../middleware/upload');

// Image upload route
router.post('/upload-image', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.status(200).json({ imageUrl });
});

module.exports = router;
