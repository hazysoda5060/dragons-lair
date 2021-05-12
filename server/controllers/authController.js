const bcrypt = require('bcryptjs')

module.exports = {
    register: async (req, res) => {
        const db = req.app.get('db')
        const {username, password, isAdmin} = req.body
        const result = await db.get_user(username)
        if(result[0]) {
            return res.status(409).send('username taken')
        }
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const registeredUser = await db.register_user(isAdmin, username, hash)
        delete registeredUser[0].user_password
        req.session.user = registeredUser[0]
        res.status(200).send(req.session.user)
    },
    login: async (req, res) => {
        const db = req.app.get('db')
        const {username, password} = req.body
        const foundUser = await db.get_user(username)
        if(!foundUser[0]) {
            return res.status(401).send('incorrect username or password')
        }
        const isAuthenticated = bcrypt.compareSync(password, foundUser[0].hash)
        if(!isAuthenticated) {
            return res.status(403).send('incorrect username or password')
        }
        req.session.user = foundUser[0]
        res.send(req.session.user)
    },
}