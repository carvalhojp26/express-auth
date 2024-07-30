require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require("jsonwebtoken");
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/Users');
const connectDB = require('./database');
const Token = require('./models/Token')

app.use(express.json())

connectDB()

app.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = await User.countDocuments() + 1;
        const newUser = new User({
            userId,
            username,
            password: hashedPassword
        })
        await newUser.save()
        res.status(201).send('User created successfully')
    } catch(error) {
        res.status(500).send({ message: 'Server Error', error: error.message})
    }
})

app.post('/login', authenticateUser, async (req, res) => {
    const user = {userId: req.user.userId, name: req.body.username}

    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)

    try{
        const newToken = new Token({ token: refreshToken })
        await newToken.save()
        res.json({ accessToken: accessToken, refreshToken: refreshToken})
    } catch (error) {
        res.status(500).send({ message: 'Failed to save token', error: error.message})
    }
})

app.post('/refreshToken', async (req, res) => {
    const refreshToken = req.body.token
    
    if (refreshToken == null) {
        return res.sendStatus(401)
    }
    
    try {
        const dbToken = await Token.findOne({ token: refreshToken })

        if (!dbToken) {
            return res.status(403).send('Inexistent token')
        }

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
            if (error) {
                return res.status(403).send('Invalid sign')
            }

        const accessToken = generateAccessToken({userId: user.userId ,name: user.name})
        res.json({ accessToken: accessToken })
        })
    } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message})
    }
})

app.delete('/logout', async (req, res) => {
    const token = req.body.token;

    try {
        await Token.findOneAndDelete({ token: token})
        res.status(204).send('Token deleted successfully')
    } catch (error) {
        res.status(500).send({ message: 'Failed to delete token', error: error.message })
    }
})

async function authenticateUser(req, res, next) {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.status(400).send('No user found');
        }

        if (await bcrypt.compare(password, user.password)) {
            req.user = { userId: user.userId, username: user.username }
            next();
        } else {
            res.status(403).send('Invalid password');
        }
    } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
    }
}

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1m'})
}

app.get('/protected', authenticateToken, (req, res) => {
    res.json({ userId: req.user.userId, username: req.user.name})
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    
    if (token == null) {
        return res.sendStatus(401).send('No token provided')
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
        if (error) {
            return res.sendStatus(403).send('Invalid token')
        }

        req.user = user
        next()
    })
}

app.listen(4000);
console.log('Server listening on port 4000');