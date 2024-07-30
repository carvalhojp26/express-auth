require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require("jsonwebtoken");
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/Users');
const connectDB = require('./database');

app.use(express.json())

connectDB()

let refreshTokens = [] //store in database

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
        res.status(500).send({ message: 'fudeu aqui', error: error.message})
    }
})

app.post('/login', authenticateUser, (req, res) => {
    const username = req.body.username
    const user = {name: username}

    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    res.json({ accessToken: accessToken, refreshToken: refreshToken})
})

app.delete('/logout', (req, res) => {
    //delete from database

    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})


app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    
    if (refreshToken == null) {
        return res.sendStatus(401)
    }
    
    if (!refreshTokens.includes(refreshToken)) {
        console.log("token not included in array")
        return res.sendStatus(403)
    }
    
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
        if (error) {
            console.log("invalid sign")
            return res.sendStatus(403)
        }
        
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken})
    })
    
})

async function authenticateUser(req, res, next) {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.status(400).send('No user found');
        }

        if (await bcrypt.compare(password, user.password)) {
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

app.listen(4000);
console.log('Server listening on port 4000');