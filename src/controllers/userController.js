exports.getProtected = (req, res) => {
    res.json({ userId: req.user.userId, username: req.user.name });
};
