const bcrypt = require('bcryptjs');
const User = require('../models/Users');

async function authenticateUser(req, res, next) {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.status(400).send('No user found');
        }

        if (await bcrypt.compare(password, user.password)) {
            req.user = { userId: user.userId, username: user.username };
            next();
        } else {
            res.status(403).send('Invalid password');
        }
    } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
    }
}

module.exports = authenticateUser;
