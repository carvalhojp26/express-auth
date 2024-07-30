require('dotenv').config()

const express = require('express');
const app = express();

const jwt = require("jsonwebtoken")

app.use(express.json())

let refreshTokens = [] //store in database

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

app.delete('/logout', (req, res) => {
    //delete from database

    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

app.post('/login', (req, res) => {
    //authenticate

    const username = req.body.username
    const user = {name: username}

    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    res.json({ accessToken: accessToken, refreshToken: refreshToken})
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s'})
}

app.listen(4000);
console.log('Server listening on port 4000');