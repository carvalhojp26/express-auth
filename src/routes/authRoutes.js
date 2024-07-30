const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authenticateUser = require('../middlewares/authenticateUser');

router.post('/signup', authController.signup);
router.post('/login', authenticateUser, authController.login);
router.post('/refreshToken', authController.refreshToken);
router.delete('/logout', authController.logout);

module.exports = router;
