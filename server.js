const express = require('express')
const app = express()
const passport = require('passport')
const bcrypt = require('bcrypt')
const session = require('express-session')
const flash = require('express-flash')
const methodOverride = require('method-override')



const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./userInfo.db", sqlite3.OPEN_READWRITE, (err) => {
  if (err) return console.error(err.message);  
});



const initializePassport = require('./passport-config')
initializePassport(
  passport,
  username => users.find(user => user.username === username),
  //username => db.get('SELECT * FROM users WHERE username = ?', [ username ]),
  id => users.find(user => user.id === id)
  //id => db.get('SELECT * FROM users WHERE useruno = ?', [ id ])
)

const users = []

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
  //secret: process.env.SESSION_SECRET,
  //secret: (Math.random() + 1).toString(36).substring(2),
  secret: 'rqewn24basdf',
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))





app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs')
})

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs')
  //console.log(Date.now())
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
  
  
  if(req.body.password != req.body.confirmpassword){
    res.render('error.ejs',{error_message: "Passwords don't match"})
  }
  else if(users.find(user => user.username === req.body.username)){
    res.render('error.ejs',{error_message: "Username already exists"})
  }
  else{
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10)
      db.run(`INSERT INTO users(useruno, name, username, password, email, number) VALUES (?,?,?,?,?,?);`,
       [Date.now(), req.body.name, req.body.username, hashedPassword, req.body.email, req.body.number], (err) => {
        if (err) return console.error(err.message); 
       })
      users.push({
        id: Date.now().toString(),
        name: req.body.name,
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
        number: req.body.number
      })
      res.redirect('/login')
    } catch {
      res.redirect('/register')
      }
  }
})

app.delete('/logout', (req, res) => {
  req.logOut()
  res.redirect('/login')
})

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next()
  }

  res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
  next()
}

app.listen(3000)

function close(){
  db.close((err) => {
    if (err) console.error(err.message);
  });
}