const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const jwt = require('jsonwebtoken')
const LocalStrategy = require('passport-local').Strategy
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits 
var cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const passportJWT = require("passport-jwt");
const JWTStrategy   = passportJWT.Strategy;
const bcrypt = require("bcrypt");

const port = 8080
const db = require('./db.json')

const app = express()
app.use(logger('dev'))
app.use(cookieParser())

/*
Configure the local strategy for use by Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('local', new LocalStrategy(
  {
    usernameField: 'username', // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password', // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's stateless
  },
  function (username, password, done) {
    console.log("password: " + password)
    console.log("db.pass" + db.password)
    console.log("hola: " + bcrypt.hashSync(password, 10))
    if (username === db.user && password === db.password) {
      const user = {
        username: 'eric',
        surname: 'casanovas'
      }
      return done(null, user) // the first argument for done is the error, if any. In our case no error so that null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler
    }
    return done(null, false) // in passport returning false as the user object means that the authentication process failed.
  }
))

const cookieExtractor = req => {
  let jwt = null 

  if (req && req.cookies) {
      jwt = req.cookies['jwt']
  }

  return jwt
}

passport.use('jwt', new JWTStrategy({
  jwtFromRequest: cookieExtractor,
  secretOrKey: jwtSecret
}, (jwtPayload, done) => {
  const { expiration } = jwtPayload

  if (Date.now() > expiration) {
      done('Unauthorized', false)
  }

  done(null, jwtPayload)
}))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields
app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.

app.get('/', 
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        res.send(fortune.fortune());
    }
)

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', session: false }),
  (req, res) => { //
    // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
    // This is what ends up in our JWT
    const jwtClaims = {
      username: 'eric',
      surname: 'casanovas'
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // Just for testing, send the JWT directly to the browser. Later on we should send the token inside a cookie.
    res.cookie('jwt', token).redirect('/');

    // And let us log a link to the jwt.iot debugger, for easy checking/verifying:
    //console.log(cookies)
    //console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    //console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/logout', (req, res) => {
  if (req.cookies['jwt']) {
      res
      .clearCookie('jwt')
      .status(200)
      .json({
          message: 'You have logged out'
      })
  } else {
      res.status(401).json({
          error: 'Invalid jwt'
      })
  }
})

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})


