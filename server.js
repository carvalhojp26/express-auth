require('dotenv').config()

const express = require('express');
const app = express();

const jwt = require("jsonwebtoken")

app.use(express.json())

const posts = [
    {
        username: "joao",
        title: "post1"
    },
    {
        username: "beatriz",
        title: "post2"
    }
]

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name))
})

app.post('/login', (req, res) => {
    //authenticate

    const username = req.body.username
    const user = {name: username}

    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
    res.json({ accessToken: accessToken})
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

app.listen(3000);
console.log('Server listening on port 3000');