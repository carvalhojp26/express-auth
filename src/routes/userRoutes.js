const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authenticateToken = require('../middlewares/authenticateToken');

router.get('/protected', authenticateToken, userController.getProtected);

module.exports = router;
