const bcrypt = require('bcryptjs')
const AuthService = require('../auth/auth-service')

function requireAuth(req, res, next) {
    const authToken = req.get('Authorization') || ''
    
    let basicToken

    // Conditional if authtoken is missing
    if (!authToken.toLowerCase().startsWith('basic ')) {
        return res.status(401).json({ error: 'Missing basic token' })
    } else {
        basicToken = authToken.slice('basic '.length, authToken.length)
    }

    // What does Buffer do?
    // Parse token value out of header
    const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(basicToken)

    // Check if username or password is missing and throw error
    if (!tokenUserName || !tokenPassword) {
        return res.status(401).json({ error: 'Unauthorized request'})
    }

    // Query database for a user that matches this username
    
    //QUESTION: I've never seen syntax with back to back brackets before
    AuthService.getUserWithUserName(
        req.app.get('db'),
        tokenUserName
    )
    
        .then(user => {
            if (!user) {
                return res.status(401).json({ error: 'Unauthorized request' })
            }
            return bcrypt.compare(tokenPassword, user.password)
                .then(passwordsMatch => {
                    if (!passwordsMatch) {
                        return res.status(401).json({ error: 'Unauthorized request' })
                    }

                    req.user = user
                    next()
                })
        })

    .catch(next)
  }
  
  module.exports = {
    requireAuth,
  }