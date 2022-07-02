const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByUsername, getUserById) {

  const authenticateUser = async (username, password, done) => {
    //const user = JSON.stringify(getUserByUsername(username))
    const user = getUserByUsername(username)
    
    if (user == null) {
      return done(null, false, { message: 'No user with that username' })
    }
    
    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user)
      } else {
        return done(null, false, { message: 'Password incorrect' })
      }
    } catch (e) {
      return done(e)
    }
  }
  
  passport.use(new LocalStrategy({ usernameField: 'username' }, authenticateUser))
  passport.serializeUser((user, done) => done(null, user.id))
  passport.deserializeUser((id, done) => {
    //return done(null, JSON.stringify(getUserById(id)))
    return done(null, getUserById(id))
  })
}

module.exports = initialize

/*const user = db.get('SELECT * FROM users WHERE email = ?', [ email ], function(err, row) {
  if (err) { return done(err); }
  if (!row) { return done(null, false, { message: 'Incorrect username or password.' }); }
});*/