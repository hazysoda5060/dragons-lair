const bcrypt = require('bcryptjs')

module.exports = {
    register: async (req, res) => {
        const db = req.app.get('db')
        const {username, password, isAdmin} = req.body
        const result = await db.get_user(username)
        if(result[0]) {
            return res.status(409).send('Username taken')
        }
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const registeredUser = await db.register_user(isAdmin, username, hash)
        delete registeredUser[0].user_password
        req.session.user = registeredUser[0]
        res.status(200).send(req.session.user)
    },
}