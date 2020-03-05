const express = require('express')
const jsonBodyParser = express.json()

const authRouter = express.Router()
const AuthService = require('./auth-service')

authRouter
  .post('/login', jsonBodyParser, (req, res, next) => {
    const { user_name, password } = req.body
    const loginUser = { user_name, password }

    // endpoint first validates the the request body contains
    // credentialed fields
    // Need help understanding object.entries syntax
    for (const [key, value] of Object.entries(loginUser))
        if (value == null)
        return res.status(400).json({
            error: `Missing '${key}' in request body`
        })
   
    // Uses user_name credential value to find a user from the database
    // using Authservice method
    AuthService.getUserWithUserName(
        req.app.get('db'),
        loginUser.user_name
    )
        .then(dbUser => {
            if(!dbUser)
                return res.status(400).json({
                    error: 'Incorrect user_name or password',
                })
           
            // If a user is found, password credential is validated using bcrypt compare
            return AuthService.comparePasswords(loginUser.password, dbUser.password)
                .then(compareMatch => {
                    if (!compareMatch)
                        return res.status(400).json({
                            error: 'Incorrect user_name or password'
                        })
                        
                        // If everything validates, respond with auth token
                        // creates response with json web token (subject, payload, secret)
                        const sub = dbUser.user_name
                        const payload = { user_id: dbUser.id}
                        res.send({
                            authToken: AuthService.createJwt(sub, payload),
                        })
                })
        })
    
    .catch(next)
  })

module.exports = authRouter