const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Token = require('../models/Token');
const User = require('../models/Users');
const { generateAccessToken } = require('../services/authService');

exports.signup = async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = await User.countDocuments() + 1;
        const newUser = new User({
            userId,
            username,
            password: hashedPassword
        });
        await newUser.save();
        res.status(201).send('User created successfully');
    } catch (error) {
        res.status(500).send({ message: 'Server Error', error: error.message });
    }
};

exports.login = async (req, res) => {
    const user = { userId: req.user.userId, name: req.body.username };

    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);

    try {
        const newToken = new Token({ token: refreshToken });
        await newToken.save();
        res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } catch (error) {
        res.status(500).send({ message: 'Failed to save token', error: error.message });
    }
};

exports.refreshToken = async (req, res) => {
    const refreshToken = req.body.token;

    if (refreshToken == null) {
        return res.sendStatus(401);
    }

    try {
        const dbToken = await Token.findOne({ token: refreshToken });

        if (!dbToken) {
            return res.status(403).send('Inexistent token');
        }

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
            if (error) {
                return res.status(403).send('Invalid sign');
            }

            const accessToken = generateAccessToken({ userId: user.userId, name: user.name });
            res.json({ accessToken: accessToken });
        });
    } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
    }
};

exports.logout = async (req, res) => {
    const token = req.body.token;

    try {
        await Token.findOneAndDelete({ token: token });
        res.status(204).send('Token deleted successfully');
    } catch (error) {
        res.status(500).send({ message: 'Failed to delete token', error: error.message });
    }
};
