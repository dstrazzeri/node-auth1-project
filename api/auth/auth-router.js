// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const bcrypt = require('bcryptjs')
const router = express.Router()
const Users = require('../users/users-model')
const{
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require('./auth-middleware')



/**
 1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

 response:
 status 200
 {
    "user_id": 2,
    "username": "sue"
  }

 response on username taken:
 status 422
 {
    "message": "Username taken"
  }

 response on password three chars or less:
 status 422
 {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/register',checkUsernameFree,checkPasswordLength,  async (req, res, next) => {
  try {
    const { username, password } = req.body
    const newUser = {
      username,
      password: bcrypt.hashSync(password, 10),
    }
    const created = await Users.add(newUser)
    res.status(201).json({username: created.username, user_id: created.user_id})
  } catch (err) {
    next(err)
  }
})
/**
 2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

 response:
 status 200
 {
    "message": "Welcome sue!"
  }

 response on invalid credentials:
 status 401
 {
    "message": "Invalid credentials"
  }
 */

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {

    const { username, password } = req.body
    const [userFromDb] = await Users.findBy({ username })

    const verifies = bcrypt.compareSync(password, userFromDb.password)
    if (verifies === false) {
      return res.status(401).json({message: 'Invalid credentials'})
    }else
      req.session.user = userFromDb
    res.status(200).json({message: `Welcome ${username}`})
  } catch (err) {
    next(err)
  }
})
/**
 3 [GET] /api/auth/logout

 response for logged-in users:
 status 200
 {
    "message": "logged out"
  }

 response for not-logged-in users:
 status 200
 {
    "message": "no session"
  }
 */

router.get('/logout', async (req, res, next) => {
  try {
    if (req.session.user) {
      req.session.destroy((err) => {
        if (err) {
          res.status(500).json('unknown error')
        } else {
          res.status(200).json({message:"logged out"})
        }
      })
    } else {
      res.status(200).json({message:"no session"})
    }
  } catch (err) {
    next(err)
  }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router